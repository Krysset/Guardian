package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	"guardian/internal/mail"
	"guardian/internal/oidc"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// The username and password rules are shared with the sign-up page (package web).
var (
	usernameRule  = web.UsernameRule
	passwordRule  = web.PasswordRule
	validPassword = web.ValidPassword
)

var validEmail = web.ValidEmail

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
	if web.RequireEmail() {
		// Confirming the address needs the sign-up page, which waits for the link in the same browser.
		httpx.ErrorCode(w, http.StatusBadRequest, "email_required", "Sign-up needs an email address here: use the sign-up page")
		return
	}
	acct, err := web.CreateAccount(r, req.Username, req.Password, false)
	switch {
	case errors.Is(err, web.ErrUsernameRule), errors.Is(err, web.ErrPasswordRule):
		httpx.Error(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, web.ErrTooManySignups):
		w.Header().Set("Retry-After", strconv.Itoa(int(web.SignupWindow.Seconds())))
		httpx.Error(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, web.ErrUsernameTaken):
		httpx.Error(w, http.StatusConflict, err.Error())
	case err != nil:
		slog.Error("failed to create an account", "error", err)
		httpx.Error(w, http.StatusInternalServerError, "Failed to create the account")
	default:
		httpx.JSON(w, http.StatusCreated, acct)
	}
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
	if p.Username != nil && !web.ValidUsername(*p.Username) {
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
	mfa, err := db.GetMFAStatus(acct.ID)
	if err != nil {
		accountFail(w, err)
		return
	}
	required, err := db.MFARequirement(acct.ID)
	if err != nil {
		accountFail(w, err)
		return
	}
	type mfaInfo struct {
		db.MFAStatus
		Required bool `json:"required"`
	}
	httpx.JSON(w, http.StatusOK, struct {
		db.Account
		IsAdmin bool    `json:"is_admin"`
		MFA     mfaInfo `json:"mfa"`
	}{acct, admin, mfaInfo{mfa, required != ""}})
}

// updateMe changes the signed-in user's profile. Only fields present in the body change; "" clears one.
// The email address is not here: it changes through PUT /me/email and its confirmation link.
func updateMe(w http.ResponseWriter, r *http.Request) {
	var req profileFields
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if msg := req.check(); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	// The username is a protected change; the rest of the profile is not.
	if req.Username != nil && !httpx.RequireReauth(w, r) {
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

// changeMyEmail starts a change of the signed-in user's address: it emails a confirmation link to the new
// address (E1) and a notice to the old one (E5). The address changes only when the link is opened.
func changeMyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !httpx.RequireReauth(w, r) {
		return
	}
	if !mail.Enabled() {
		httpx.ErrorCode(w, http.StatusConflict, "email_off", "This Guardian does not send email, so addresses cannot be confirmed")
		return
	}
	if !validEmail(req.Email) {
		httpx.Error(w, http.StatusBadRequest, "email must be an address such as name@example.com")
		return
	}
	acct, err := db.GetAccount(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	if used, err := db.EmailInUse(req.Email); err != nil {
		accountFail(w, err)
		return
	} else if used {
		httpx.ErrorCode(w, http.StatusConflict, "email_in_use", "That email address is already in use")
		return
	}
	err = web.SendConfirmation(acct, req.Email, false, "", "")
	if errors.Is(err, web.ErrTooManyMails) {
		w.Header().Set("Retry-After", "3600")
		httpx.ErrorCode(w, http.StatusTooManyRequests, "too_many_emails", "Too many emails for this account. Try again in an hour.")
		return
	}
	if err != nil {
		accountFail(w, err)
		return
	}
	if acct.Email != "" {
		mail.Enqueue(mail.EmailChanging(acct.Email, req.Email, time.Now(), acct.Zoneinfo))
	}
	db.Audit("email.change_requested", acct.ID, "", httpx.ClientIP(r), nil)
	httpx.JSON(w, http.StatusAccepted, map[string]string{"pending_email": req.Email})
}

// reauthLimit is how many wrong passwords a session may send to /me/reauth in reauthWindow before it must
// wait. The session is already signed in, so this only slows down someone guessing at an unattended screen.
const (
	reauthLimit  = 5
	reauthWindow = 15 * time.Minute
)

// reauth confirms who the signed-in user is with their password, or a code from their authenticator app,
// which opens the window for protected changes (httpx.ReauthWindow).
func reauth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	id, ip := httpx.AccountID(r), httpx.ClientIP(r)
	key := "reauth:account:" + id
	if n, err := db.RateLimitCount(key, reauthWindow); err != nil {
		accountFail(w, err)
		return
	} else if n >= reauthLimit {
		httpx.RateLimited.WithLabelValues("reauth").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(int(reauthWindow.Seconds())))
		httpx.ErrorCode(w, http.StatusTooManyRequests, "rate_limited", "Too many wrong passwords. Try again in 15 minutes.")
		return
	}
	if (req.Password == "") == (req.Code == "") {
		httpx.Error(w, http.StatusBadRequest, "Send either password or code")
		return
	}
	var ok bool
	if req.Code != "" {
		var err error
		if ok, _, _, err = web.VerifySecondFactor(id, req.Code, false); errors.Is(err, web.ErrTooManyAttempts) {
			w.Header().Set("Retry-After", strconv.Itoa(int(reauthWindow.Seconds())))
			httpx.ErrorCode(w, http.StatusTooManyRequests, "rate_limited", "Too many wrong codes. Try again in 15 minutes.")
			return
		} else if err != nil {
			accountFail(w, err)
			return
		}
	} else {
		hash, err := db.GetPasswordHash(id)
		if err != nil {
			accountFail(w, err)
			return
		}
		ok = hash != "" && len(req.Password) <= 1024 && auth.VerifyPassword(req.Password, hash)
	}
	if !ok {
		db.RateLimitHit(key, reauthWindow)
		db.Audit("reauth.failure", id, "", ip, nil)
		if req.Code != "" {
			httpx.ErrorCode(w, http.StatusForbidden, "wrong_code", "The code is not correct")
		} else {
			httpx.ErrorCode(w, http.StatusForbidden, "wrong_password", "The password is not correct")
		}
		return
	}
	db.RateLimitReset(key, reauthWindow)
	t, err := db.Reauthenticate(httpx.SessionID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	db.Audit("reauth.success", id, "", ip, nil)
	httpx.JSON(w, http.StatusOK, map[string]any{"reauthenticated_until": t.Add(httpx.ReauthWindow).UTC()})
}

// changeMyPassword is a protected change: the session must have proved who its user is within the last
// few minutes (POST /me/reauth). It ends the user's other sessions, so a changed password also locks out
// anyone who signed in with the old one.
func changeMyPassword(w http.ResponseWriter, r *http.Request) {
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
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
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
	if acct, err := db.GetAccount(id); err == nil {
		web.NotifyPasswordChanged(acct)
	}
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
	if !web.ValidUsername(req.Username) {
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
