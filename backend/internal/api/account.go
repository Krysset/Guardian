package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	"guardian/internal/oidc"
	db "guardian/internal/store"
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

const usernameRule = "username must be 3-64 characters: letters, digits, '.', '_' or '-'"

func validPassword(p string) bool {
	// Upper bound protects the hasher from huge inputs.
	return len(p) >= 10 && len(p) <= 1024
}

const passwordRule = "The password must be 10-1024 characters"

// validEmail accepts a bare address such as alice@example.com, nothing else ("Alice <a@b>" is refused).
func validEmail(s string) bool {
	if len(s) > 254 {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

const (
	signupLimit  = 10 // sign-ups per IP per window
	signupWindow = time.Hour
)

// signup is open to everyone, so it is limited per client IP (counters live in Postgres and are shared by
// all replicas). Accounts created by administrators (POST /accounts) are not limited.
func signup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !usernameRe.MatchString(req.Username) {
		httpx.Error(w, http.StatusBadRequest, usernameRule)
		return
	}
	if !validPassword(req.Password) {
		httpx.Error(w, http.StatusBadRequest, passwordRule)
		return
	}
	// Counted only for valid requests, so typos in the form do not use up the limit.
	n, err := db.RateLimitHit("register:ip:"+httpx.ClientIP(r), signupWindow)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if n > signupLimit {
		httpx.RateLimited.WithLabelValues("register").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(int(signupWindow.Seconds())))
		httpx.Error(w, http.StatusTooManyRequests, "Too many sign-ups from this address. Try again later.")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	acct, err := db.CreateAccount(req.Username, hash)
	if db.IsUniqueViolation(err) {
		httpx.Error(w, http.StatusConflict, "That username is already taken")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to create the account")
		return
	}
	db.Audit("account.signed_up", acct.ID, "", httpx.ClientIP(r), nil)
	httpx.JSON(w, http.StatusCreated, acct)
}

// profileFields are the account fields both a user and an administrator may change.
type profileFields struct {
	Username    *string `json:"username"`
	DisplayName *string `json:"display_name"`
	GivenName   *string `json:"given_name"`
	FamilyName  *string `json:"family_name"`
	PictureURL  *string `json:"picture_url"`
	Locale      *string `json:"locale"`
	Zoneinfo    *string `json:"zoneinfo"`
}

// check returns what is wrong with the fields, or "".
func (p profileFields) check() string {
	if p.Username != nil && !usernameRe.MatchString(*p.Username) {
		return usernameRule
	}
	for name, v := range map[string]*string{"display_name": p.DisplayName, "given_name": p.GivenName, "family_name": p.FamilyName} {
		if v != nil && len(*v) > 128 {
			return name + " may be up to 128 characters"
		}
	}
	if p.PictureURL != nil && *p.PictureURL != "" && (len(*p.PictureURL) > 2048 || !httpx.ValidRedirectURI(*p.PictureURL)) {
		return "picture_url must be an https URL"
	}
	if (p.Locale != nil && len(*p.Locale) > 35) || (p.Zoneinfo != nil && len(*p.Zoneinfo) > 64) {
		return "locale may be up to 35 characters and zoneinfo up to 64"
	}
	return ""
}

func (p profileFields) update() db.AccountUpdate {
	return db.AccountUpdate{Username: p.Username, DisplayName: p.DisplayName, GivenName: p.GivenName,
		FamilyName: p.FamilyName, PictureURL: p.PictureURL, Locale: p.Locale, Zoneinfo: p.Zoneinfo}
}

// accountFail answers a failed account change.
func accountFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		httpx.Error(w, http.StatusNotFound, "Account not found")
	case errors.Is(err, db.ErrLastAdmin):
		httpx.ErrorCode(w, http.StatusConflict, "last_admin",
			"Guardian must keep at least one active administrator whose membership does not expire")
	case db.IsUniqueViolation(err):
		httpx.Error(w, http.StatusConflict, "That username or email is already in use")
	default:
		slog.Error("account change failed", "error", err)
		httpx.Error(w, http.StatusInternalServerError, "Request failed")
	}
}

// getMe returns the signed-in account, and whether it is an administrator (for the management UI).
func getMe(w http.ResponseWriter, r *http.Request) {
	acct, err := db.GetAccount(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	admin, err := db.IsAdmin(acct.ID)
	if err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, struct {
		db.Account
		IsAdmin bool `json:"is_admin"`
	}{acct, admin})
}

// updateMe changes the signed-in user's profile. Only fields present in the body change; "" clears one.
// The email address is not here: it is set through verification, which arrives in release 0.3.
func updateMe(w http.ResponseWriter, r *http.Request) {
	var req profileFields
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if msg := req.check(); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	acct, _, err := db.UpdateAccount(httpx.AccountID(r), req.update())
	if err != nil {
		accountFail(w, err)
		return
	}
	if req.Username != nil {
		db.Audit("account.username_changed", acct.ID, "", httpx.ClientIP(r), map[string]any{"username": acct.Username})
	}
	httpx.JSON(w, http.StatusOK, acct)
}

// changeMyPassword needs the current password. It ends the user's other sessions, so a changed password
// also locks out anyone who signed in with the old one.
func changeMyPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !validPassword(req.NewPassword) {
		httpx.Error(w, http.StatusBadRequest, passwordRule)
		return
	}
	id := httpx.AccountID(r)
	hash, err := db.GetPasswordHash(id)
	if err != nil || hash == "" || !auth.VerifyPassword(req.CurrentPassword, hash) {
		httpx.ErrorCode(w, http.StatusForbidden, "wrong_password", "The current password is not correct")
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := db.UpdatePasswordHash(id, newHash); err != nil {
		accountFail(w, err)
		return
	}
	notices, err := db.RevokeOtherSessions(id, httpx.SessionID(r))
	if err != nil {
		slog.Error("failed to end other sessions after a password change", "error", err)
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("password.changed", id, "", httpx.ClientIP(r), map[string]any{"other_sessions_ended": true})
	httpx.NoContent(w)
}

// ---- Administration ---------------------------------------------------------

// listAccounts: ?q= searches username, display name and email; ?status= is active or disabled;
// ?cursor= continues from next_cursor of the previous page; ?limit= is 1-200 (default 50).
func listAccounts(w http.ResponseWriter, r *http.Request) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	status := q.Get("status")
	if status != "" && status != "active" && status != "disabled" {
		httpx.Error(w, http.StatusBadRequest, "status must be active or disabled")
		return
	}
	if len(q.Get("q")) > 256 {
		httpx.Error(w, http.StatusBadRequest, "q may be up to 256 characters")
		return
	}
	accounts, err := db.ListAccounts(db.AccountFilter{Query: q.Get("q"), Status: status, After: q.Get("cursor"), Limit: limit + 1})
	if err != nil {
		accountFail(w, err)
		return
	}
	resp := map[string]any{"next_cursor": nil}
	if len(accounts) > limit {
		accounts = accounts[:limit]
		resp["next_cursor"] = accounts[limit-1].Username
	}
	resp["items"] = accounts
	httpx.JSON(w, http.StatusOK, resp)
}

// createAccount creates an account for someone. An email set here counts as verified.
func createAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !usernameRe.MatchString(req.Username) {
		httpx.Error(w, http.StatusBadRequest, usernameRule)
		return
	}
	if !validPassword(req.Password) {
		httpx.Error(w, http.StatusBadRequest, passwordRule)
		return
	}
	if req.Email != "" && !validEmail(req.Email) {
		httpx.Error(w, http.StatusBadRequest, "email must be an address such as alice@example.com")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	acct, err := db.CreateAccountWithEmail(req.Username, hash, req.Email)
	if err != nil {
		accountFail(w, err)
		return
	}
	db.Audit("account.created", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"target": acct.ID, "username": acct.Username})
	httpx.JSON(w, http.StatusCreated, acct)
}

// getAccount returns an account and the groups it is in.
func getAccount(w http.ResponseWriter, r *http.Request) {
	acct, err := db.GetAccount(chi.URLParam(r, "account"))
	if err != nil {
		accountFail(w, err)
		return
	}
	groups, err := db.AccountGroups(acct.ID)
	if err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, struct {
		db.Account
		Groups []db.Membership `json:"groups"`
	}{acct, groups})
}

// updateAccount changes any profile field, the email (counts as verified; "" removes it) and the status.
// Disabling an account ends all of its sessions and tells apps with back-channel logout at once.
func updateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		profileFields
		Email  *string `json:"email"`
		Status *string `json:"status"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if msg := req.check(); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	if req.Email != nil && *req.Email != "" && !validEmail(*req.Email) {
		httpx.Error(w, http.StatusBadRequest, "email must be an address such as alice@example.com")
		return
	}
	if req.Status != nil && *req.Status != "active" && *req.Status != "disabled" {
		httpx.Error(w, http.StatusBadRequest, "status must be active or disabled")
		return
	}
	u := req.update()
	u.Email, u.Status = req.Email, req.Status
	acct, notices, err := db.UpdateAccount(chi.URLParam(r, "account"), u)
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	detail := map[string]any{"target": acct.ID}
	if req.Status != nil {
		detail["status"] = *req.Status
	}
	if req.Email != nil {
		detail["email_changed"] = true
	}
	if req.Username != nil {
		detail["username"] = acct.Username
	}
	db.Audit("account.updated", httpx.AccountID(r), "", httpx.ClientIP(r), detail)
	httpx.JSON(w, http.StatusOK, acct)
}

// deleteAccount disables the account at once, ends all of its sessions and removes it from its groups.
func deleteAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "account")
	if _, err := db.GetAccount(id); err != nil {
		accountFail(w, err)
		return
	}
	notices, err := db.SoftDeleteAccount(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices) // apps that support back-channel logout drop the user at once
	db.Audit("account.deleted", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"target": id})
	httpx.NoContent(w)
}

// setAccountPassword is how an administrator helps someone who cannot reset their own password (for
// example an account without an email). The user must choose a new password at their next sign-in, and
// all of the account's sessions end.
func setAccountPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !validPassword(req.NewPassword) {
		httpx.Error(w, http.StatusBadRequest, passwordRule)
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	id := chi.URLParam(r, "account")
	notices, err := db.SetPasswordByAdmin(id, hash)
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("password.set_by_admin", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"target": id})
	httpx.NoContent(w)
}
