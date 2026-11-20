package web

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	"guardian/internal/mail"
	db "guardian/internal/store"
)

// The pages behind Guardian's emails: confirming an address (S2b, S12), and resetting a forgotten password
// (S10, S11). Every link is a one-time account_token; only its hash is stored.

const (
	confirmLinkLifetime = 24 * time.Hour
	resetLinkLifetime   = time.Hour

	// signupCookie ties a sign-up that waits for its email confirmation to the browser that made it. The
	// confirmation link signs in only in that browser, so a mail scanner that opens the link, or anyone else
	// who gets it, confirms the address but gets no session.
	signupCookie = "guardian_signup"

	mailsPerAccount = 5 // links per account per hour; more are silently not sent
	mailWindow      = time.Hour
	forgotPerIP     = 20 // reset requests per address per hour
)

// ErrTooManyMails means the account was sent too many links this hour; the link was not sent.
var ErrTooManyMails = errors.New("too many emails for this account; try again in an hour")

// SendConfirmation emails a link that confirms address for the account (E1). At sign-up, browser is the
// hash of the browser's sign-up cookie and returnTo is where sign-in continues afterwards.
func SendConfirmation(acct db.Account, address string, signup bool, browser, returnTo string) error {
	if allowed, err := mailAllowed(acct.ID); err != nil {
		return err
	} else if !allowed {
		return ErrTooManyMails
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		return err
	}
	t, err := db.CreateAccountToken(acct.ID, db.TokenEmailVerify, auth.HashToken(token), confirmLinkLifetime,
		db.TokenMetadata{Email: address, Signup: signup, Browser: browser, ReturnTo: returnTo})
	if err != nil {
		return err
	}
	mail.Enqueue(mail.ConfirmAddress(address, httpx.Issuer+"/confirm?token="+token, t.ExpiresAt, acct.Zoneinfo, signup))
	return nil
}

// mailAllowed counts a link for the account and reports whether it may still be sent this hour, so nobody
// can flood an inbox through Guardian.
func mailAllowed(accountID string) (bool, error) {
	n, err := db.RateLimitHit("mail:account:"+accountID, mailWindow)
	if err != nil {
		return false, err
	}
	if n > mailsPerAccount {
		httpx.RateLimited.WithLabelValues("mail").Inc()
		return false, nil
	}
	return true, nil
}

// NotifyPasswordChanged sends E3 when the account has an email address.
func NotifyPasswordChanged(acct db.Account) {
	if acct.Email != "" {
		mail.Enqueue(mail.PasswordChanged(acct.Email, time.Now(), acct.Zoneinfo))
	}
}

// ---- S2b: check your inbox ----------------------------------------------------

// pendingSignup returns the confirmation the browser's sign-up waits for.
func pendingSignup(r *http.Request) (db.AccountToken, db.Account, bool) {
	cookie := httpx.FlowCookie(r, signupCookie)
	if cookie == "" {
		return db.AccountToken{}, db.Account{}, false
	}
	t, err := db.FindSignupToken(auth.HashToken(cookie))
	if err != nil && !errors.Is(err, db.ErrTokenExpired) && !errors.Is(err, db.ErrTokenUsed) {
		return db.AccountToken{}, db.Account{}, false
	}
	acct, err := db.GetAccount(t.AccountID)
	if err != nil || acct.Status != "pending" {
		return db.AccountToken{}, db.Account{}, false
	}
	return t, acct, true
}

func inboxPage(w http.ResponseWriter, r *http.Request) {
	t, _, ok := pendingSignup(r)
	if !ok {
		http.Redirect(w, r, "/signup", http.StatusFound)
		return
	}
	Render(w, http.StatusOK, "inbox", Page{Title: "Check your inbox", CSRF: httpx.CSRFToken(w, r),
		Email: mail.Mask(t.Metadata.Email), Change: r.URL.Query().Has("change")})
}

// inboxSubmit resends the link, or sends it to a corrected address.
func inboxSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	t, acct, ok := pendingSignup(r)
	if !ok {
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}
	page := Page{Title: "Check your inbox", Email: mail.Mask(t.Metadata.Email), FieldErrors: map[string]string{}}
	show := func(status int) {
		page.CSRF = httpx.CSRFToken(w, r)
		Render(w, status, "inbox", page)
	}
	if !httpx.CSRFValid(r) {
		page.Error = "The form had expired. Try again."
		show(http.StatusForbidden)
		return
	}
	address := t.Metadata.Email
	if r.PostFormValue("action") == "change" {
		address = strings.TrimSpace(r.PostFormValue("email"))
		page.Change = true
		if msg := emailProblem(address); msg != "" {
			page.FieldErrors["email"] = msg
			show(http.StatusBadRequest)
			return
		}
	}
	err := SendConfirmation(acct, address, true, t.Metadata.Browser, t.Metadata.ReturnTo)
	if errors.Is(err, ErrTooManyMails) {
		page.Error = "We have sent several links already. Wait an hour, then try again."
		show(http.StatusTooManyRequests)
		return
	}
	if err != nil {
		slog.Error("failed to send a confirmation link", "error", err)
		Error(w, ServerError)
		return
	}
	page.Email, page.Change = mail.Mask(address), false
	page.Notice = "We sent a new link. Only the newest link works."
	show(http.StatusOK)
}

// emailProblem returns what is wrong with an address typed at sign-up, or "".
func emailProblem(address string) string {
	if !ValidEmail(address) {
		return "Enter an email address such as name@example.com."
	}
	if used, err := db.EmailInUse(address); err != nil || used {
		return "That email address is already in use."
	}
	return ""
}

// ---- S12: email confirmation ----------------------------------------------------

func confirmPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	t, err := db.ConfirmEmail(auth.HashToken(token))
	ip := httpx.ClientIP(r)
	switch {
	case err == nil:
		db.Audit("email.confirmed", t.AccountID, "", ip, map[string]any{"signup": t.Metadata.Signup})
		if !t.Metadata.Signup {
			result(w, "ok", "Email address confirmed", "Thanks. You can now reset your password by email.", &Link{"Continue", "/"})
			return
		}
		// The sign-up is complete. Sign in only in the browser that signed up.
		if cookie := httpx.FlowCookie(r, signupCookie); cookie != "" && auth.HashToken(cookie) == t.Metadata.Browser {
			httpx.ClearFlowCookie(w, signupCookie)
			if _, err := httpx.StartSession(w, r, t.AccountID); err != nil {
				Error(w, ServerError)
				return
			}
			db.TouchLogin(t.AccountID)
			http.Redirect(w, r, continueTo(httpx.SafeReturnTo(t.Metadata.ReturnTo)), http.StatusSeeOther)
			return
		}
		result(w, "ok", "Email address confirmed", "Your account is ready. Sign in to continue.", &Link{"Sign in", "/login"})
	case errors.Is(err, db.ErrEmailTaken):
		if t.Metadata.Signup {
			result(w, "warn", "This address can't be used", "Another account started using it first. Choose a different address.",
				&Link{"Change the address", "/signup/inbox?change"})
			return
		}
		result(w, "warn", "This address can't be used", "Another account started using it first. Choose a different address.", &Link{"Continue", "/"})
	case t.Metadata.Signup && errors.Is(err, db.ErrTokenExpired):
		result(w, "warn", "This link has expired", "Ask for a new one.", &Link{"Send a new link", "/signup/inbox"})
	case errors.Is(err, db.ErrTokenUsed):
		result(w, "warn", "This link was already used", "Each link works once. If your address is not confirmed yet, ask for a new link.", &Link{"Continue", "/"})
	case errors.Is(err, db.ErrTokenExpired), errors.Is(err, db.ErrTokenInvalid):
		result(w, "warn", "This link has expired", "Ask for a new one.", &Link{"Continue", "/"})
	default:
		slog.Error("failed to confirm an email address", "error", err)
		Error(w, ServerError)
	}
}

// result shows the outcome of a link (S12 and the reset link's states).
func result(w http.ResponseWriter, icon, heading, message string, link *Link) {
	Render(w, http.StatusOK, "result", Page{Title: heading, Heading: heading, Message: message, Link: link, Icon: icon})
}

// ---- S10, S11: forgot and reset password ---------------------------------------------

func forgotPage(w http.ResponseWriter, r *http.Request) {
	if !mail.Enabled() {
		NotFoundHandler(w, r)
		return
	}
	Render(w, http.StatusOK, "forgot", Page{Title: "Forgot password", CSRF: httpx.CSRFToken(w, r)})
}

// forgotSubmit always answers the same, whether or not the account exists or has an address. The email
// goes out in the background, so the answer takes the same time too.
func forgotSubmit(w http.ResponseWriter, r *http.Request) {
	if !mail.Enabled() {
		NotFoundHandler(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	login := strings.TrimSpace(r.PostFormValue("username"))
	page := Page{Title: "Forgot password"}
	if len(login) <= 256 {
		page.Login = login
	}
	if !httpx.CSRFValid(r) {
		page.Error = "The form had expired. Try again."
		page.CSRF = httpx.CSRFToken(w, r)
		Render(w, http.StatusForbidden, "forgot", page)
		return
	}
	ip := httpx.ClientIP(r)
	if r.PostFormValue("website") != "" {
		// The honeypot: answer as if the link was sent, and send nothing.
		honeypotHit(r, "forgot")
		Render(w, http.StatusOK, "forgot", Page{Title: "Forgot password", Sent: true})
		return
	}
	n, err := db.RateLimitHit("forgot:ip:"+ip, mailWindow)
	if err != nil {
		Error(w, ServerError)
		return
	}
	if n > forgotPerIP {
		httpx.RateLimited.WithLabelValues("forgot").Inc()
		page.Error = "Too many requests from your network. Try again in an hour."
		page.CSRF = httpx.CSRFToken(w, r)
		Render(w, http.StatusTooManyRequests, "forgot", page)
		return
	}
	if login != "" && len(login) <= 256 {
		if err := sendResetLink(login, ip); err != nil {
			slog.Error("failed to send a password reset link", "error", err)
		}
	}
	Render(w, http.StatusOK, "forgot", Page{Title: "Forgot password", Sent: true})
}

func sendResetLink(login, ip string) error {
	acct, _, err := db.GetAccountForLogin(login)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (acct.Email == "" || acct.Status != "active")) {
		return nil
	}
	if err != nil {
		return err
	}
	if allowed, err := mailAllowed(acct.ID); err != nil || !allowed {
		return err
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		return err
	}
	t, err := db.CreateAccountToken(acct.ID, db.TokenPasswordReset, auth.HashToken(token), resetLinkLifetime, db.TokenMetadata{})
	if err != nil {
		return err
	}
	db.Audit("password.reset_requested", acct.ID, "", ip, nil)
	mail.Enqueue(mail.ResetPassword(acct.Email, httpx.Issuer+"/reset?token="+url.QueryEscape(token), t.ExpiresAt, acct.Zoneinfo))
	return nil
}

func resetExpired(w http.ResponseWriter) {
	result(w, "warn", "This link has expired", "Reset links work once, for an hour. Ask for a new one.",
		&Link{"Send a new link", "/forgot"})
}

func resetPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if _, err := db.PeekAccountToken(auth.HashToken(token), db.TokenPasswordReset); err != nil {
		resetExpired(w)
		return
	}
	Render(w, http.StatusOK, "reset", Page{Title: "Reset password", CSRF: httpx.CSRFToken(w, r), Token: token})
}

func resetSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	token := r.PostFormValue("token")
	page := Page{Title: "Reset password", Token: token, FieldErrors: map[string]string{}}
	show := func(status int) {
		page.CSRF = httpx.CSRFToken(w, r)
		Render(w, status, "reset", page)
	}
	if !httpx.CSRFValid(r) {
		page.Error = "The form had expired. Fill in the passwords again."
		show(http.StatusForbidden)
		return
	}
	password, password2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if !ValidPassword(password) {
		page.FieldErrors["password"] = "Use at least 10 characters."
	} else if password != password2 {
		page.FieldErrors["password2"] = "The passwords don't match."
	}
	if len(page.FieldErrors) > 0 {
		show(http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		Error(w, ServerError)
		return
	}
	t, notices, err := db.ResetPassword(auth.HashToken(token), hash)
	switch {
	case errors.Is(err, db.ErrTokenInvalid), errors.Is(err, db.ErrTokenExpired), errors.Is(err, db.ErrTokenUsed):
		resetExpired(w)
		return
	case err != nil:
		slog.Error("failed to reset a password", "error", err)
		Error(w, ServerError)
		return
	}
	SendLogoutNotices(notices)
	httpx.ClearSessionCookie(w)
	db.Audit("password.reset", t.AccountID, "", httpx.ClientIP(r), map[string]any{"sessions_ended": true})
	if acct, err := db.GetAccount(t.AccountID); err == nil {
		NotifyPasswordChanged(acct)
	}
	http.Redirect(w, r, "/login?reset=done", http.StatusSeeOther)
}
