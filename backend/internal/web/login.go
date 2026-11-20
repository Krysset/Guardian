// Package web serves Guardian's own sign-in pages: sign in, sign up, choosing a new password, and the
// templates, styles and error pages they share. The OIDC package renders its consent, no-access and
// sign-out pages with the same templates.
package web

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"guardian/internal/auth"
	"guardian/internal/config"
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
	r.Get("/signup/inbox", inboxPage)
	r.Post("/signup/inbox", inboxSubmit)
	r.Get("/confirm", confirmPage)
	r.Get("/forgot", forgotPage)
	r.Post("/forgot", forgotSubmit)
	r.Get("/reset", resetPage)
	r.Post("/reset", resetSubmit)
	r.Get("/mfa", mfaPage)
	r.Post("/mfa", mfaSubmit)
	r.Post("/mfa/cancel", mfaCancel)
	r.Get("/mfa/setup", mfaSetupPage)
	r.Get("/mfa/stepup", stepUpPage)
	r.Post("/mfa/setup", mfaSetupSubmit)
	r.Get("/static/*", serveStatic)
	r.Head("/static/*", serveStatic)
}

var loginsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "guardian", Name: "logins_total", Help: "Interactive login attempts by result.",
}, []string{"result"}) // success | failure

// Login throttling uses Postgres counters (shared by all replicas). Failures are counted per account and
// IP address together: by default 5 in 15 minutes block that address for that account, and nobody else. A
// separate limit counts every failure from one address, whatever the account. Accounts are never locked,
// so nobody can lock someone else out by guessing their password. The limits are settings
// (config.LoginLimits), set by Configure.
var loginLimits = config.DefaultLoginLimits

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
	page := Page{Title: "Sign in", CSRF: httpx.CSRFToken(w, r), ReturnTo: returnTo}
	if r.URL.Query().Get("reset") == "done" {
		page.Notice = "Your password was changed, and every session was signed out. Sign in with the new one."
	}
	Render(w, http.StatusOK, "login", page)
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
	ipKey := "login:ip:" + ip

	if len(login) == 0 || len(login) > 256 || len(password) == 0 || len(password) > 1024 {
		showError(http.StatusUnauthorized, wrongLogin)
		return
	}
	acct, hash, err := db.GetAccountForLogin(login)
	// The account's id when it exists, so its username and its email share one counter; otherwise what was
	// typed, so an unknown name is limited the same way and the limit does not reveal which names exist.
	subject := strings.ToLower(login)
	if err == nil {
		subject = acct.ID
	}
	userKey := "login:account:" + subject + ":ip:" + ip
	userFails, _ := db.RateLimitCount(userKey, loginLimits.Window)
	ipFails, _ := db.RateLimitCount(ipKey, loginLimits.Window)
	if userFails >= loginLimits.PerAccountAndIP || ipFails >= loginLimits.PerIP {
		httpx.CountRefused("login")
		auth.DummyVerify(password) // a refusal takes as long as a check
		showError(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}

	valid := false
	if err == nil && hash != "" && (acct.Status == "active" || acct.Status == "pending") {
		valid = auth.VerifyPassword(password, hash)
	} else {
		auth.DummyVerify(password) // same cost whether or not the account exists
	}
	if !valid {
		db.RateLimitHit(userKey, loginLimits.Window)
		db.RateLimitHit(ipKey, loginLimits.Window)
		loginsTotal.WithLabelValues("failure").Inc()
		db.Audit("login.failure", acct.ID, "", ip, map[string]any{"username": login})
		showError(http.StatusUnauthorized, wrongLogin)
		return
	}

	db.RateLimitReset(userKey, loginLimits.Window)
	if acct.Status == "pending" {
		// The right password, but the sign-up waits for its email confirmation.
		msg := "Confirm your email address first: open the link we sent you."
		if httpx.FlowCookie(r, signupCookie) != "" {
			msg += " To get a new one, go back to the check-your-inbox page."
		}
		showError(http.StatusForbidden, msg)
		return
	}
	next, reason, err := mfaAfterPassword(acct.ID)
	if err != nil {
		Error(w, ServerError)
		return
	}
	if next != "" {
		// The password was right; the session starts once the second factor is passed (or set up).
		db.Audit("login.password_ok", acct.ID, "", ip, map[string]any{"next": next})
		startMFAFlow(w, r, mfaFlow{Account: acct.ID, Purpose: "signin", Setup: next == "setup", Reason: reason, ReturnTo: returnTo})
		return
	}
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
