package web

import (
	"log/slog"
	"net/http"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// passwordPage is S3: an administrator set a temporary password, and the account must choose its own
// before it can do anything else. There is no way to skip it.
func passwordPage(w http.ResponseWriter, r *http.Request) {
	returnTo := httpx.SafeReturnTo(r.URL.Query().Get("return_to"))
	sess, ok := httpx.SessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	acct, err := db.GetAccount(sess.AccountID)
	if err != nil {
		Error(w, ServerError)
		return
	}
	if !acct.MustChangePassword {
		http.Redirect(w, r, continueTo(returnTo), http.StatusFound)
		return
	}
	Render(w, http.StatusOK, "password", Page{Title: "Choose a new password", CSRF: httpx.CSRFToken(w, r), ReturnTo: returnTo})
}

func passwordSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	returnTo := httpx.SafeReturnTo(r.PostFormValue("return_to"))
	sess, ok := httpx.SessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	page := Page{Title: "Choose a new password", ReturnTo: returnTo, FieldErrors: map[string]string{}}
	show := func(status int) {
		page.CSRF = httpx.CSRFToken(w, r)
		Render(w, status, "password", page)
	}
	if !httpx.CSRFValid(r) {
		page.Error = "The form had expired. Fill in the passwords again."
		show(http.StatusForbidden)
		return
	}
	acct, err := db.GetAccount(sess.AccountID)
	if err != nil {
		Error(w, ServerError)
		return
	}
	if !acct.MustChangePassword {
		http.Redirect(w, r, continueTo(returnTo), http.StatusSeeOther)
		return
	}
	password, password2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if !ValidPassword(password) {
		page.FieldErrors["password"] = "Use at least 10 characters."
	} else if password != password2 {
		page.FieldErrors["password2"] = "The passwords don't match."
	} else if hash, err := db.GetPasswordHash(acct.ID); err == nil && hash != "" && auth.VerifyPassword(password, hash) {
		page.FieldErrors["password"] = "That's the temporary password. Choose a new one."
	}
	if len(page.FieldErrors) > 0 {
		show(http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(password)
	if err == nil {
		err = db.UpdatePasswordHash(acct.ID, hash) // also clears must_change_password
	}
	if err != nil {
		slog.Error("failed to save a new password", "error", err)
		Error(w, ServerError)
		return
	}
	db.Audit("password.changed", acct.ID, "", httpx.ClientIP(r), map[string]any{"replaced_temporary": true})
	NotifyPasswordChanged(acct)
	http.Redirect(w, r, continueTo(returnTo), http.StatusSeeOther)
}
