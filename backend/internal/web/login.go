// Package web serves Guardian's own sign-in pages: sign in, sign up, choosing a new password, and the
// templates, styles and error pages they share. The OIDC package renders its consent, no-access and
// sign-out pages with the same templates.
package web

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// Mount registers the sign-in pages and their static files at the root of the router.
func Mount(r chi.Router) {
	r.Get("/", homePage)
	r.Get("/login", loginPage)
	r.Post("/login", loginSubmit)
	r.Get("/signup", signupPage)
	r.Post("/signup", signupSubmit)
	r.Get("/password", passwordPage)
	r.Post("/password", passwordSubmit)
	r.Get("/static/*", serveStatic)
	r.Head("/static/*", serveStatic)
}

var loginsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "guardian", Name: "logins_total", Help: "Interactive login attempts by result.",
}, []string{"result"}) // success | failure

// Login throttling uses Postgres counters (shared by all replicas): failed attempts per username and per IP.
const (
	loginWindow     = 15 * time.Minute
	maxLoginPerUser = 10
	maxLoginPerIP   = 50
)

const wrongLogin = "Wrong username or password."

// continueTo is where a finished sign-in page sends the browser: back into the app's sign-in, or Home.
func continueTo(returnTo string) string {
	if returnTo != "" {
		return returnTo
	}
	return "/"
}

// MustChangePasswordURL is the page an account with a temporary password must pass before anything else.
func MustChangePasswordURL(returnTo string) string {
	if returnTo == "" {
		return "/password"
	}
	return "/password?return_to=" + url.QueryEscape(returnTo)
}

// signedInPage is S8: the browser already has a session and nowhere to go.
func signedInPage(w http.ResponseWriter, r *http.Request, sess db.Session) {
	acct, err := db.GetAccount(sess.AccountID)
	if err != nil {
		Error(w, ServerError)
		return
	}
	if acct.MustChangePassword {
		http.Redirect(w, r, MustChangePasswordURL(""), http.StatusFound)
		return
	}
	Render(w, http.StatusOK, "signedin", Page{Title: "Signed in", Username: acct.Username, CSRF: httpx.CSRFToken(w, r)})
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := httpx.SafeReturnTo(r.URL.Query().Get("return_to"))
	if sess, ok := httpx.SessionFromRequest(r); ok {
		if returnTo != "" {
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
		signedInPage(w, r, sess)
		return
	}
	Render(w, http.StatusOK, "login", Page{Title: "Sign in", CSRF: httpx.CSRFToken(w, r), ReturnTo: returnTo})
}

func loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	login := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	returnTo := httpx.SafeReturnTo(r.PostFormValue("return_to"))
	showError := func(status int, msg string) {
		if len(login) > 256 {
			login = ""
		}
		Render(w, status, "login", Page{Title: "Sign in", Error: msg, CSRF: httpx.CSRFToken(w, r), ReturnTo: returnTo, Login: login})
	}
	if !httpx.CSRFValid(r) {
		showError(http.StatusForbidden, "The form had expired. Sign in again.")
		return
	}
	ip := httpx.ClientIP(r)
	userKey := "login:user:" + strings.ToLower(login)
	ipKey := "login:ip:" + ip

	if len(login) == 0 || len(login) > 256 || len(password) == 0 || len(password) > 1024 {
		showError(http.StatusUnauthorized, wrongLogin)
		return
	}
	userFails, _ := db.RateLimitCount(userKey, loginWindow)
	ipFails, _ := db.RateLimitCount(ipKey, loginWindow)
	if userFails >= maxLoginPerUser || ipFails >= maxLoginPerIP {
		httpx.RateLimited.WithLabelValues("login").Inc()
		showError(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}

	acct, hash, err := db.GetAccountForLogin(login)
	valid := false
	if err == nil && hash != "" && acct.Status == "active" {
		valid = auth.VerifyPassword(password, hash)
	} else {
		auth.DummyVerify(password) // same cost whether or not the account exists
	}
	if !valid {
		db.RateLimitHit(userKey, loginWindow)
		db.RateLimitHit(ipKey, loginWindow)
		loginsTotal.WithLabelValues("failure").Inc()
		db.Audit("login.failure", acct.ID, "", ip, map[string]any{"username": login})
		showError(http.StatusUnauthorized, wrongLogin)
		return
	}

	db.RateLimitReset(userKey, loginWindow)
	loginsTotal.WithLabelValues("success").Inc()
	if _, err := httpx.StartSession(w, r, acct.ID); err != nil {
		slog.Error("failed to start a session", "error", err)
		Error(w, ServerError)
		return
	}
	db.TouchLogin(acct.ID)
	db.Audit("login.success", acct.ID, "", ip, nil)

	if acct.MustChangePassword {
		http.Redirect(w, r, MustChangePasswordURL(returnTo), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, continueTo(returnTo), http.StatusSeeOther)
}
