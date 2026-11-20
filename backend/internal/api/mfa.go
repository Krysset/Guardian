package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
	"guardian/internal/mail"
	"guardian/internal/oidc"
	"guardian/internal/passkey"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// Two-factor for the signed-in user (U11), and the admin reset (A9). Setting up, removing and renewing
// are protected changes. Nothing is saved until it is proven: an authenticator app produces a code, a
// security key answers, and the first method's recovery codes are typed back.
//
//	POST /me/mfa/totp          -> the secret, its QR code, setup_token
//	POST /me/mfa/totp/confirm  -> {setup_token, code}: the recovery codes, a new setup_token
//	POST /me/mfa/keys          -> {options, setup_token}: for navigator.credentials.create
//	POST /me/mfa/keys/finish   -> {setup_token, credential, name}: 201 the key, or for the first method
//	                              200 the recovery codes and a new setup_token
//	POST /me/mfa/finish        -> {setup_token, recovery_code}: saved

func mfaFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, web.ErrSetupExpired), errors.Is(err, passkey.ErrExpired):
		httpx.ErrorCode(w, http.StatusBadRequest, "setup_expired", "The setup has expired or does not belong to this account; start again")
	case errors.Is(err, web.ErrWrongCode):
		httpx.ErrorCode(w, http.StatusBadRequest, "wrong_code", "The code is wrong")
	case errors.Is(err, passkey.ErrNotRecognised):
		httpx.ErrorCode(w, http.StatusBadRequest, "key_not_recognised", "The security key's answer could not be checked; try again")
	case errors.Is(err, db.ErrCredentialInUse):
		httpx.ErrorCode(w, http.StatusConflict, "key_registered", "That security key is already registered")
	case errors.Is(err, db.ErrNoTOTP):
		httpx.ErrorCode(w, http.StatusConflict, "no_totp", "The account has no authenticator app")
	case errors.Is(err, db.ErrNoSecondFactor):
		httpx.ErrorCode(w, http.StatusConflict, "no_second_factor", "Set up an authenticator app or a security key first")
	case errors.Is(err, db.ErrKeyNotFound):
		httpx.ErrorCode(w, http.StatusNotFound, "not_found", "No such security key")
	case errors.Is(err, passkey.ErrNoKeys):
		httpx.ErrorCode(w, http.StatusConflict, "no_keys", "The account has no security keys")
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

// finishSetup saves an authenticator app or a first security key once a recovery code is typed back.
func finishSetup(w http.ResponseWriter, r *http.Request) {
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
	amr, err := web.FinishSetup(acct, req.SetupToken, req.RecoveryCode, httpx.ClientIP(r))
	if err != nil {
		mfaFail(w, err)
		return
	}
	// The session has just shown it holds the app or the key.
	if err := db.StepUpSession(httpx.SessionID(r), amr); err != nil {
		accountFail(w, err)
		return
	}
	httpx.NoContent(w)
}

func startKeySetup(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	opts, token, err := passkey.BeginRegistration(httpx.AccountID(r))
	if err != nil {
		mfaFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"options": opts, "setup_token": token})
}

func finishKeySetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupToken string          `json:"setup_token"`
		Credential json.RawMessage `json:"credential"`
		Name       string          `json:"name"`
	}
	if !httpx.DecodeJSON(w, r, &req) || !httpx.RequireReauth(w, r) {
		return
	}
	name, ok := web.KeyName(req.Name)
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "name must be at most 64 characters")
		return
	}
	acct, err := db.GetAccount(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	k, err := passkey.FinishRegistration(acct.ID, req.SetupToken, req.Credential)
	if err != nil {
		mfaFail(w, err)
		return
	}
	saved, codes, token, err := web.AddKey(acct, name, k, httpx.ClientIP(r))
	if err != nil {
		mfaFail(w, err)
		return
	}
	if saved == nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "setup_token": token})
		return
	}
	if err := db.StepUpSession(httpx.SessionID(r), "hwk"); err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"key": saved})
}

func renameKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	name, ok := web.KeyName(req.Name)
	if !ok || strings.TrimSpace(req.Name) == "" {
		httpx.Error(w, http.StatusBadRequest, "name must be 1-64 characters")
		return
	}
	id := httpx.AccountID(r)
	k, err := db.RenameSecurityKey(id, chi.URLParam(r, "key"), name)
	if err != nil {
		mfaFail(w, err)
		return
	}
	db.Audit("mfa.key_renamed", id, "", httpx.ClientIP(r), map[string]any{"key": name})
	httpx.JSON(w, http.StatusOK, k)
}

func removeTOTP(w http.ResponseWriter, r *http.Request) { removeFactor(w, r, "totp") }
func removeKey(w http.ResponseWriter, r *http.Request)  { removeFactor(w, r, chi.URLParam(r, "key")) }

// removeFactor removes the authenticator app or one security key; the recovery codes go with the last
// method. An account that must use two-factor (administrators, group owners) keeps at least one.
func removeFactor(w http.ResponseWriter, r *http.Request, factor string) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	reason, err := db.MFARequirement(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	name, _, err := db.RemoveFactor(id, factor, reason != "")
	if errors.Is(err, db.ErrLastFactor) {
		httpx.ErrorCode(w, http.StatusConflict, "mfa_required", reason+" Keep at least one two-factor method.")
		return
	} else if err != nil {
		mfaFail(w, err)
		return
	}
	method, event, detail := "Authenticator app", "mfa.totp_removed", map[string]any(nil)
	if factor != "totp" {
		method, event, detail = web.KeyMethod(name), "mfa.key_removed", map[string]any{"key": name}
	}
	db.Audit(event, id, "", httpx.ClientIP(r), detail)
	if acct, err := db.GetAccount(id); err == nil && acct.Email != "" {
		mail.Enqueue(mail.TwoFactorChanged(acct.Email, false, method, time.Now(), acct.Zoneinfo))
	}
	httpx.NoContent(w)
}

// renewRecoveryCodes makes new recovery codes; finishRecoveryCodes puts them in place once one is typed back.
func renewRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	if has, err := db.HasSecondFactor(id); err != nil {
		accountFail(w, err)
		return
	} else if !has {
		mfaFail(w, db.ErrNoSecondFactor)
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
