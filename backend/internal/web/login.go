// Package web serves Guardian's own sign-in pages: sign in, sign up, choosing a new password, and the
// templates, styles and error pages they share. The OIDC package renders its consent, no-access and
// sign-out pages with the same templates.
package web

import (
	"database/sql"
	"errors"
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
	"guardian/internal/passkey"
	db "guardian/internal/store"
)

// Mount registers the sign-in pages and their static files at the root of the router.
func Mount(r chi.Router) {
	r.Get("/", homePage)
	r.Get("/login", loginPage)
	r.Post("/login/passkey", passkeySubmit)
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

// Sign-ins on the sign-in pages. Neither metric has anything about who: only how, and why not.
var (
	loginsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "logins_total",
		Help: "Completed sign-ins by method: password, passkey, password_and_code, password_and_key, " +
			"password_and_recovery_code. A sign-in that fails at any step is counted in guardian_login_failures_total instead.",
	}, []string{"method"})
	loginFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "login_failures_total",
		Help: "Failed steps on the sign-in pages (signing in, and the two-factor step before an app that requires it), " +
			"by the factor that failed and why. Attempts refused by the rate limiter are in guardian_rate_limited_total.",
	}, []string{"factor", "reason"})
)

// loginFailureLabels are every factor and reason pair that can happen, so each series exists from the
// start: a graph or an alert of a rate never misses the first failure.
var loginFailureLabels = [][2]string{
	{"password", "wrong_password"}, {"password", "unknown_account"}, {"password", "account_disabled"},
	{"password", "email_unconfirmed"},
	{"passkey", "not_recognised"}, {"passkey", "account_disabled"}, {"passkey", "expired"},
	{"code", "wrong_code"}, {"recovery_code", "wrong_code"}, {"key", "not_recognised"}, {"key", "expired"},
}

func init() {
	for _, m := range []string{"password", "passkey", "password_and_code", "password_and_key", "password_and_recovery_code"} {
		loginsTotal.WithLabelValues(m)
	}
	for _, l := range loginFailureLabels {
		loginFailures.WithLabelValues(l[0], l[1])
	}
}

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
	page := Page{ReturnTo: returnTo}
	if r.URL.Query().Get("reset") == "done" {
		page.Notice = "Your password was changed, and every session was signed out. Sign in with the new one."
	}
	renderLogin(w, r, page, http.StatusOK)
}

// passkeyCookie holds the sign-in page's passkey challenge, so the answer must come from this browser.
const passkeyCookie = "guardian_passkey"

// renderLogin shows S1. Every view carries a fresh passkey challenge for "Sign in with a passkey" and the
// browser's passkey suggestions in the username field; without JavaScript they are simply not offered.
func renderLogin(w http.ResponseWriter, r *http.Request, page Page, status int) {
	page.Title, page.CSRF = "Sign in", httpx.CSRFToken(w, r)
	if opts, token, err := passkey.BeginPasskeyLogin(); err != nil {
		if !errors.Is(err, passkey.ErrOff) {
			slog.Error("failed to start a passkey sign-in", "error", err)
		}
	} else {
		page.KeyOptions = string(opts)
		httpx.SetFlowCookie(w, passkeyCookie, token, passkey.Timeout)
	}
	Render(w, status, "login", page)
}

// passkeySubmit is "Sign in with a passkey" (V8): the passkey is both factors, so the session counts as
// having passed two-factor. Failures count against the address like wrong passwords.
func passkeySubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	returnTo := httpx.SafeReturnTo(r.PostFormValue("return_to"))
	showError := func(status int, msg string) {
		renderLogin(w, r, Page{Error: msg, ReturnTo: returnTo}, status)
	}
	if !httpx.CSRFValid(r) {
		showError(http.StatusForbidden, "The form had expired. Sign in again.")
		return
	}
	token := httpx.FlowCookie(r, passkeyCookie)
	httpx.ClearFlowCookie(w, passkeyCookie)
	ip := httpx.ClientIP(r)
	ipKey := "login:ip:" + ip
	if fails, _ := db.RateLimitCount(ipKey, loginLimits.Window); fails >= loginLimits.PerIP {
		httpx.CountRefused("login")
		showError(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}
	accountID, name, err := passkey.FinishPasskeyLogin(token, []byte(r.PostFormValue("credential")))
	var acct db.Account
	reason := "not_recognised"
	if err == nil {
		if acct, err = db.GetAccount(accountID); err == nil && acct.Status != "active" {
			err, reason = passkey.ErrNotRecognised, "account_disabled"
		}
	}
	switch {
	case errors.Is(err, passkey.ErrExpired):
		loginFailures.WithLabelValues("passkey", "expired").Inc()
		showError(http.StatusBadRequest, "That took too long. Try again.")
		return
	case err != nil:
		if !errors.Is(err, passkey.ErrNotRecognised) && !errors.Is(err, sql.ErrNoRows) {
			slog.Error("failed to check a passkey", "error", err)
		}
		db.RateLimitHit(ipKey, loginLimits.Window)
		loginFailures.WithLabelValues("passkey", reason).Inc()
		db.Audit("login.failure", accountID, "", ip, map[string]any{"method": "passkey"})
		showError(http.StatusUnauthorized, "That passkey isn't registered here. Sign in with your password instead.")
		return
	}
	finishSignIn(w, r, acct, "passkey", map[string]any{"method": "passkey", "key": name}, returnTo, "hwk", "user")
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
		renderLogin(w, r, Page{Error: msg, ReturnTo: returnTo, Login: login}, status)
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

	valid, reason := false, "wrong_password"
	switch {
	case err == nil && hash != "" && (acct.Status == "active" || acct.Status == "pending"):
		valid = auth.VerifyPassword(password, hash)
	case err != nil:
		reason = "unknown_account"
		auth.DummyVerify(password) // same cost whether or not the account exists
	default: // no password (only a passkey, or never set), or disabled
		if acct.Status != "active" && acct.Status != "pending" {
			reason = "account_disabled"
		}
		auth.DummyVerify(password)
	}
	if !valid {
		db.RateLimitHit(userKey, loginLimits.Window)
		db.RateLimitHit(ipKey, loginLimits.Window)
		loginFailures.WithLabelValues("password", reason).Inc()
		db.Audit("login.failure", acct.ID, "", ip, map[string]any{"username": login})
		showError(http.StatusUnauthorized, wrongLogin)
		return
	}

	db.RateLimitReset(userKey, loginLimits.Window)
	if acct.Status == "pending" {
		// The right password, but the sign-up waits for its email confirmation.
		loginFailures.WithLabelValues("password", "email_unconfirmed").Inc()
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
	finishSignIn(w, r, acct, "password", nil, returnTo, "pwd")
}
