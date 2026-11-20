package api

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
	"guardian/internal/mail"
	"guardian/internal/oidc"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// Two-factor for the signed-in user (U11), and the admin reset (A9). Setting up, removing and renewing
// are protected changes. Setting up takes three calls, so nothing is saved until the app has produced a
// code and one recovery code has been typed back:
//
//	POST /me/mfa/totp          -> the secret, its QR code, setup_token
//	POST /me/mfa/totp/confirm  -> {setup_token, code}: the recovery codes, a new setup_token
//	POST /me/mfa/totp/finish   -> {setup_token, recovery_code}: saved

func mfaFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, web.ErrSetupExpired):
		httpx.ErrorCode(w, http.StatusBadRequest, "setup_expired", "The setup has expired or does not belong to this account; start again")
	case errors.Is(err, web.ErrWrongCode):
		httpx.ErrorCode(w, http.StatusBadRequest, "wrong_code", "The code is wrong")
	case errors.Is(err, db.ErrNoTOTP):
		httpx.ErrorCode(w, http.StatusConflict, "no_totp", "Set up an authenticator app first")
	default:
		accountFail(w, err)
	}
}

func startTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	acct, err := db.GetAccount(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	view, err := web.NewTOTPSetup(acct)
	if err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, view)
}

func confirmTOTPSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupToken string `json:"setup_token"`
		Code       string `json:"code"`
	}
	if !httpx.DecodeJSON(w, r, &req) || !httpx.RequireReauth(w, r) {
		return
	}
	codes, token, err := web.ConfirmTOTPSetup(httpx.AccountID(r), req.SetupToken, req.Code)
	if err != nil {
		mfaFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "setup_token": token})
}

func finishTOTPSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupToken   string `json:"setup_token"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !httpx.DecodeJSON(w, r, &req) || !httpx.RequireReauth(w, r) {
		return
	}
	acct, err := db.GetAccount(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	if err := web.FinishTOTPSetup(acct, req.SetupToken, req.RecoveryCode, httpx.ClientIP(r)); err != nil {
		mfaFail(w, err)
		return
	}
	// The session has just shown it holds the app.
	if err := db.StepUpSession(httpx.SessionID(r)); err != nil {
		accountFail(w, err)
		return
	}
	httpx.NoContent(w)
}

// removeTOTP removes the authenticator app and the recovery codes. An account that must use two-factor
// (administrators, group owners) cannot remove it.
func removeTOTP(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	reason, err := db.MFARequirement(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	if reason != "" {
		httpx.ErrorCode(w, http.StatusConflict, "mfa_required", reason+" It cannot be removed.")
		return
	}
	n, err := db.RemoveMFA(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	if n == 0 {
		httpx.ErrorCode(w, http.StatusConflict, "no_totp", "The account has no authenticator app")
		return
	}
	db.Audit("mfa.totp_removed", id, "", httpx.ClientIP(r), nil)
	if acct, err := db.GetAccount(id); err == nil && acct.Email != "" {
		mail.Enqueue(mail.TwoFactorChanged(acct.Email, false, "Authenticator app", time.Now(), acct.Zoneinfo))
	}
	httpx.NoContent(w)
}

// renewRecoveryCodes makes new recovery codes; finishRecoveryCodes puts them in place once one is typed back.
func renewRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	if has, err := db.HasTOTP(id); err != nil {
		accountFail(w, err)
		return
	} else if !has {
		mfaFail(w, db.ErrNoTOTP)
		return
	}
	codes, token, err := web.NewRecoveryCodeSet(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "setup_token": token})
}

func finishRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupToken   string `json:"setup_token"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !httpx.DecodeJSON(w, r, &req) || !httpx.RequireReauth(w, r) {
		return
	}
	if err := web.FinishRecoveryCodes(httpx.AccountID(r), req.SetupToken, req.RecoveryCode, httpx.ClientIP(r)); err != nil {
		mfaFail(w, err)
		return
	}
	httpx.NoContent(w)
}

// resetAccountMFA is the last step of the recovery ladder (A9): an administrator removes an account's
// two-factor methods, giving a reason. The account is signed out everywhere and told by email.
func resetAccountMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if n := utf8.RuneCountInString(req.Reason); n < 3 || n > 500 {
		httpx.Error(w, http.StatusBadRequest, "reason must be 3-500 characters: it is recorded and emailed to the user")
		return
	}
	acct, err := db.GetAccount(chi.URLParam(r, "account"))
	if err != nil {
		accountFail(w, err)
		return
	}
	n, err := db.RemoveMFA(acct.ID)
	if err != nil {
		accountFail(w, err)
		return
	}
	if n == 0 {
		httpx.ErrorCode(w, http.StatusConflict, "no_totp", "The account has no two-factor methods")
		return
	}
	notices, err := db.RevokeOtherSessions(acct.ID, "")
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("mfa.reset", httpx.AccountID(r), "", httpx.ClientIP(r),
		map[string]any{"account": acct.ID, "reason": req.Reason, "sessions_ended": true})
	if acct.Email != "" {
		mail.Enqueue(mail.TwoFactorReset(acct.Email, req.Reason, time.Now(), acct.Zoneinfo))
	}
	httpx.NoContent(w)
}
