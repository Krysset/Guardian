package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// signupPage is S2. Email addresses at sign-up come with confirmation emails in 0.3.
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
	password, password2 := r.PostFormValue("password"), r.PostFormValue("password2")
	returnTo := httpx.SafeReturnTo(r.PostFormValue("return_to"))
	page := Page{Title: "Create an account", ReturnTo: returnTo, FieldErrors: map[string]string{}}
	if len(username) <= 64 {
		page.Login = username
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
	if !ValidPassword(password) {
		page.FieldErrors["password"] = "Use at least 10 characters."
	} else if password != password2 {
		page.FieldErrors["password2"] = "The passwords don't match."
	}
	if len(page.FieldErrors) > 0 {
		show(http.StatusBadRequest)
		return
	}

	acct, err := CreateAccount(r, username, password)
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

	// Sign-up signs the new account in and continues where it started.
	if _, err := httpx.StartSession(w, r, acct.ID); err != nil {
		slog.Error("failed to start a session", "error", err)
		Error(w, ServerError)
		return
	}
	db.TouchLogin(acct.ID)
	http.Redirect(w, r, continueTo(returnTo), http.StatusSeeOther)
}
