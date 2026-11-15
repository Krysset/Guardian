// Package web serves Guardian's own sign-in pages: the HTML templates and the login page. The OIDC
// package renders its consent, logout and error pages with the same templates.
package web

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// Mount registers the sign-in pages at the root of the router.
func Mount(r chi.Router) {
	r.Get("/login", loginPage)
	r.Post("/login", loginSubmit)
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

func loginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := httpx.SafeReturnTo(r.URL.Query().Get("return_to"))
	if sess, ok := httpx.SessionFromRequest(r); ok {
		if returnTo != "" {
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
		acct, _ := db.GetAccount(sess.AccountID)
		Render(w, http.StatusOK, "logout", Page{
			Title: "Signed in", Message: "You are signed in as " + acct.Username + ".", CSRF: httpx.CSRFToken(w, r),
		})
		return
	}
	Render(w, http.StatusOK, "login", Page{Title: "Sign in", CSRF: httpx.CSRFToken(w, r), ReturnTo: returnTo})
}

func loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	if !httpx.CSRFValid(r) {
		Message(w, http.StatusForbidden, "Request rejected", "Your form expired. Reload the page and try again.")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	returnTo := httpx.SafeReturnTo(r.PostFormValue("return_to"))
	ip := httpx.ClientIP(r)
	userKey := "login:user:" + strings.ToLower(username)
	ipKey := "login:ip:" + ip

	showError := func(status int, msg string) {
		Render(w, status, "login", Page{Title: "Sign in", Error: msg, CSRF: httpx.CSRFToken(w, r), ReturnTo: returnTo})
	}
	if len(username) == 0 || len(username) > 256 || len(password) == 0 || len(password) > 1024 {
		showError(http.StatusUnauthorized, "Invalid username or password.")
		return
	}
	userFails, _ := db.RateLimitCount(userKey, loginWindow)
	ipFails, _ := db.RateLimitCount(ipKey, loginWindow)
	if userFails >= maxLoginPerUser || ipFails >= maxLoginPerIP {
		httpx.RateLimited.WithLabelValues("login").Inc()
		showError(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}

	acct, hash, err := db.GetAccountByUsername(username)
	valid := false
	if err == nil && hash != "" && acct.Status == "active" {
		valid = auth.VerifyPassword(password, hash)
	} else {
		auth.DummyVerify(password) // same cost whether or not the user exists
	}
	if !valid {
		db.RateLimitHit(userKey, loginWindow)
		db.RateLimitHit(ipKey, loginWindow)
		loginsTotal.WithLabelValues("failure").Inc()
		db.Audit("login.failure", acct.ID, "", ip, map[string]any{"username": username})
		showError(http.StatusUnauthorized, "Invalid username or password.")
		return
	}

	db.RateLimitReset(userKey, loginWindow)
	loginsTotal.WithLabelValues("success").Inc()
	if _, err := httpx.StartSession(w, r, acct.ID); err != nil {
		slog.Error("failed to start a session", "error", err)
		Message(w, http.StatusInternalServerError, "Something went wrong", "Please try again.")
		return
	}
	db.TouchLogin(acct.ID)
	db.Audit("login.success", acct.ID, "", ip, nil)

	dest := returnTo
	if dest == "" {
		dest = "/login"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
