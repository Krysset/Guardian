package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	"guardian/internal/mail"
	db "guardian/internal/store"
)

// signupPage is S2. With email on, the form asks for an address (optional unless REQUIRE_EMAIL), and a
// sign-up with an address completes only once the address is confirmed (S2b, S12).
func signupPage(w http.ResponseWriter, r *http.Request) {
	returnTo := httpx.SafeReturnTo(r.URL.Query().Get("return_to"))
	if sess, ok := httpx.SessionFromRequest(r); ok {
		if returnTo != "" {
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
		signedInPage(w, r, sess)
		return
	}
	Render(w, http.StatusOK, "signup", Page{Title: "Create an account", CSRF: httpx.CSRFToken(w, r), ReturnTo: returnTo})
}

func signupSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	username := strings.TrimSpace(r.PostFormValue("username"))
	email := ""
	if mail.Enabled() {
		email = strings.TrimSpace(r.PostFormValue("email"))
	}
	password, password2 := r.PostFormValue("password"), r.PostFormValue("password2")
	returnTo := httpx.SafeReturnTo(r.PostFormValue("return_to"))
	page := Page{Title: "Create an account", ReturnTo: returnTo, FieldErrors: map[string]string{}}
	if len(username) <= 64 {
		page.Login = username
	}
	if len(email) <= 254 {
		page.Email = email
	}
	show := func(status int) {
		page.CSRF = httpx.CSRFToken(w, r)
		Render(w, status, "signup", page)
	}
	if !httpx.CSRFValid(r) {
		page.Error = "The form had expired. Fill in the passwords again."
		show(http.StatusForbidden)
		return
	}
	// The honeypot: people never see this field; bots that fill in every field do.
	if r.PostFormValue("website") != "" {
		page.Error = "We couldn't create the account. Try again."
		show(http.StatusBadRequest)
		return
	}
	if !ValidUsername(username) {
		page.FieldErrors["username"] = "Use 3–64 letters, digits, dots, dashes or underscores."
	}
	if email == "" && RequireEmail() {
		page.FieldErrors["email"] = "Enter your email address."
	} else if email != "" {
		if msg := emailProblem(email); msg != "" {
			page.FieldErrors["email"] = msg
		}
	}
	if !ValidPassword(password) {
		page.FieldErrors["password"] = "Use at least 10 characters."
	} else if password != password2 {
		page.FieldErrors["password2"] = "The passwords don't match."
	}
	if len(page.FieldErrors) > 0 {
		show(http.StatusBadRequest)
		return
	}

	acct, err := CreateAccount(r, username, password, email != "")
	switch {
	case errors.Is(err, ErrUsernameTaken):
		page.FieldErrors["username"] = "That username is taken."
		show(http.StatusConflict)
		return
	case errors.Is(err, ErrTooManySignups):
		page.Error = "Too many accounts were created from your network. Try again in an hour."
		show(http.StatusTooManyRequests)
		return
	case err != nil:
		slog.Error("failed to create an account", "error", err)
		Error(w, ServerError)
		return
	}

	if email != "" {
		// The account waits for its address. The cookie lets this browser resend the link, change the
		// address, and be signed in by the link.
		cookie, err := auth.RandomToken(32)
		if err == nil {
			err = SendConfirmation(acct, email, true, auth.HashToken(cookie), returnTo)
		}
		if err != nil {
			slog.Error("failed to send the sign-up confirmation", "error", err)
			Error(w, ServerError)
			return
		}
		httpx.SetFlowCookie(w, signupCookie, cookie, db.PendingSignupLifetime)
		http.Redirect(w, r, "/signup/inbox", http.StatusSeeOther)
		return
	}

	// Sign-up signs the new account in and continues where it started.
	if _, err := httpx.StartSession(w, r, acct.ID); err != nil {
		slog.Error("failed to start a session", "error", err)
		Error(w, ServerError)
		return
	}
	db.TouchLogin(acct.ID)
	http.Redirect(w, r, continueTo(returnTo), http.StatusSeeOther)
}
