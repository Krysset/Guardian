package web

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"rsc.io/qr"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	"guardian/internal/mail"
	db "guardian/internal/store"
)

// Two-factor at sign-in (S13), the required setup (S15, S16), and the setup logic the API shares.
//
// Between the password and the second factor the browser holds no session, only a sealed flow cookie
// (encrypted with the key encryption key) that names the account and where sign-in continues. The setup
// carries its state the same way, in a sealed token in the form, so nothing waits in the database until
// the setup is finished.

const (
	mfaCookie       = "guardian_mfa"
	mfaFlowLifetime = 10 * time.Minute
	setupLifetime   = 15 * time.Minute

	mfaAttempts = 5 // wrong codes per account in mfaWindow
	mfaWindow   = 15 * time.Minute
)

// mfaFlow is the sign-in waiting for its second factor.
type mfaFlow struct {
	Account  string `json:"a"`
	Purpose  string `json:"p"` // "signin" (no session yet) or "stepup" (a session that must add two-factor)
	Setup    bool   `json:"s"` // two-factor must be set up first (S15)
	Reason   string `json:"r"` // why it is required, for S15
	ReturnTo string `json:"t"`
	Expires  int64  `json:"e"`
}

func seal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return auth.Seal(b)
}

func unseal(sealed string, v any) bool {
	b, err := auth.Open(sealed)
	return err == nil && json.Unmarshal(b, v) == nil
}

func startMFAFlow(w http.ResponseWriter, r *http.Request, f mfaFlow) {
	f.Expires = time.Now().Add(mfaFlowLifetime).Unix()
	sealed, err := seal(f)
	if err != nil {
		Error(w, ServerError)
		return
	}
	httpx.SetFlowCookie(w, mfaCookie, sealed, mfaFlowLifetime)
	target := "/mfa"
	if f.Setup {
		target = "/mfa/setup"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func readMFAFlow(r *http.Request) (mfaFlow, bool) {
	var f mfaFlow
	if !unseal(httpx.FlowCookie(r, mfaCookie), &f) || time.Now().Unix() > f.Expires {
		return mfaFlow{}, false
	}
	if f.Purpose == "stepup" {
		// A step-up belongs to the session that started it.
		sess, ok := httpx.SessionFromRequest(r)
		if !ok || sess.AccountID != f.Account {
			return mfaFlow{}, false
		}
	}
	return f, true
}

// mfaAfterPassword decides what follows a correct password: the second factor if the account has one,
// the setup if it must have one, or nothing ("") to sign in straight away.
func mfaAfterPassword(accountID string) (next, reason string, err error) {
	has, err := db.HasTOTP(accountID)
	if err != nil || has {
		return "challenge", "", err
	}
	reason, err = db.MFARequirement(accountID)
	if err != nil || reason == "" {
		return "", "", err
	}
	return "setup", reason, nil
}

// StepUp sends a signed-in user through two-factor before continuing to returnTo: the code if they have
// an authenticator app, otherwise its setup. appName says who requires it.
func StepUp(w http.ResponseWriter, r *http.Request, accountID, returnTo, appName string) {
	has, err := db.HasTOTP(accountID)
	if err != nil {
		Error(w, ServerError)
		return
	}
	startMFAFlow(w, r, mfaFlow{Account: accountID, Purpose: "stepup", Setup: !has,
		Reason: appName + " requires two-factor.", ReturnTo: returnTo})
}

// stepUpPage is where the management UI sends a signed-in user whose session has not passed two-factor
// when a page needs it (an administrator's or group owner's rights, 403 mfa_required). It asks for a code,
// or sets two-factor up first, and returns to return_to (a page of the management UI). Without a session it
// is the sign-in page; a session that already passed two-factor goes straight back.
func stepUpPage(w http.ResponseWriter, r *http.Request) {
	returnTo := httpx.SafeReturnTo(r.URL.Query().Get("return_to"))
	sess, ok := httpx.SessionFromRequest(r)
	if !ok {
		target := "/login"
		if returnTo != "" {
			target += "?return_to=" + url.QueryEscape(returnTo)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	if slices.Contains(sess.AMR, "otp") {
		http.Redirect(w, r, continueTo(returnTo), http.StatusFound)
		return
	}
	StepUp(w, r, sess.AccountID, returnTo, "This page")
}

// ErrTooManyAttempts means too many wrong codes; the account must wait.
var ErrTooManyAttempts = errors.New("too many wrong codes")

// VerifySecondFactor checks an authenticator code, or a recovery code, for the account. method is "totp"
// or "recovery_code"; left is how many recovery codes remain after one was used.
func VerifySecondFactor(accountID, code string, recovery bool) (ok bool, method string, left int, err error) {
	key := "mfa:account:" + accountID
	n, err := db.RateLimitCount(key, mfaWindow)
	if err != nil {
		return false, "", 0, err
	}
	if n >= mfaAttempts {
		httpx.CountRefused("mfa")
		return false, "", 0, ErrTooManyAttempts
	}
	if recovery {
		method = "recovery_code"
		ok, left, err = db.UseRecoveryCode(accountID, auth.HashRecoveryCode(accountID, code))
	} else {
		method = "totp"
		ok, err = verifyTOTP(accountID, code)
	}
	if err != nil {
		return false, method, 0, err
	}
	if !ok {
		db.RateLimitHit(key, mfaWindow)
		return false, method, 0, nil
	}
	db.RateLimitReset(key, mfaWindow)
	return true, method, left, nil
}

func verifyTOTP(accountID, code string) (bool, error) {
	f, err := db.GetTOTP(accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	secret, err := auth.Decrypt(f.SealedSecret, TOTPSecretAAD(accountID))
	if err != nil {
		return false, err
	}
	step, ok := auth.VerifyTOTP(string(secret), code, time.Now(), f.LastStep)
	if !ok {
		return false, nil
	}
	return db.UseTOTPStep(f.ID, step)
}

// TOTPSecretAAD is the associated data of an account's stored authenticator-app secret.
func TOTPSecretAAD(accountID string) string { return auth.AAD("account_mfa", "secret", accountID) }

// ---- Setting up an authenticator app (shared with the API) ------------------------

// totpSetup is the state of a setup between its steps, sealed into a token.
type totpSetup struct {
	Account string   `json:"a"`
	Secret  string   `json:"s,omitempty"`
	Codes   []string `json:"c,omitempty"` // the recovery codes shown, once the app is confirmed
	Step    int64    `json:"n,omitempty"` // the time step of the confirming code
	Stage   string   `json:"g"`           // "scan", "codes" (app confirmed, codes shown) or "renew" (new codes only)
	Expires int64    `json:"e"`
}

// TOTPSetupView is what the first step shows: the QR code, the secret for typing in by hand, and the token
// to send back with the first code.
type TOTPSetupView struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
	QRCode     string `json:"qr_code"` // a data: URI of a PNG image
	SetupToken string `json:"setup_token"`
}

var (
	ErrSetupExpired = errors.New("the setup has expired; start again")
	ErrWrongCode    = errors.New("the code is wrong")
)

func sealSetup(s totpSetup) (string, error) {
	s.Expires = time.Now().Add(setupLifetime).Unix()
	return seal(s)
}

func openSetup(token, accountID, stage string) (totpSetup, error) {
	var s totpSetup
	if !unseal(token, &s) || s.Account != accountID || s.Stage != stage || time.Now().Unix() > s.Expires {
		return totpSetup{}, ErrSetupExpired
	}
	return s, nil
}

// NewTOTPSetup starts setting up an authenticator app for the account.
func NewTOTPSetup(acct db.Account) (TOTPSetupView, error) {
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return TOTPSetupView{}, err
	}
	uri := auth.OTPAuthURI(mail.SiteName(), acct.Username, secret)
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		return TOTPSetupView{}, err
	}
	code.Scale = 6
	token, err := sealSetup(totpSetup{Account: acct.ID, Secret: secret, Stage: "scan"})
	if err != nil {
		return TOTPSetupView{}, err
	}
	return TOTPSetupView{Secret: secret, OTPAuthURI: uri, SetupToken: token,
		QRCode: "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())}, nil
}

// ConfirmTOTPSetup checks the first code from the app and returns the recovery codes to show, with the
// token for the last step. Nothing is saved yet.
func ConfirmTOTPSetup(accountID, token, code string) (codes []string, next string, err error) {
	s, err := openSetup(token, accountID, "scan")
	if err != nil {
		return nil, "", err
	}
	step, ok := auth.VerifyTOTP(s.Secret, code, time.Now(), 0)
	if !ok {
		return nil, "", ErrWrongCode
	}
	if codes, err = auth.NewRecoveryCodes(); err != nil {
		return nil, "", err
	}
	next, err = sealSetup(totpSetup{Account: accountID, Secret: s.Secret, Codes: codes, Step: step, Stage: "codes"})
	return codes, next, err
}

// SetupCodes returns the recovery codes a token carries, to show them again after a wrong answer.
func SetupCodes(accountID, token string) []string {
	for _, stage := range []string{"codes", "renew"} {
		if s, err := openSetup(token, accountID, stage); err == nil {
			return s.Codes
		}
	}
	return nil
}

// FinishTOTPSetup checks that one recovery code was saved (typed back), then saves the app and the codes,
// replacing any earlier ones, and tells the account by email (E4).
func FinishTOTPSetup(acct db.Account, token, typed, ip string) error {
	s, err := openSetup(token, acct.ID, "codes")
	if err != nil {
		return err
	}
	if !typedOneOf(typed, s.Codes, acct.ID) {
		return ErrWrongCode
	}
	sealed, err := auth.Encrypt([]byte(s.Secret), TOTPSecretAAD(acct.ID))
	if err != nil {
		return err
	}
	if err := db.SaveTOTP(acct.ID, sealed, hashCodes(acct.ID, s.Codes), s.Step); err != nil {
		return err
	}
	db.Audit("mfa.totp_added", acct.ID, "", ip, nil)
	if acct.Email != "" {
		mail.Enqueue(mail.TwoFactorChanged(acct.Email, true, "Authenticator app", time.Now(), acct.Zoneinfo))
	}
	return nil
}

// NewRecoveryCodeSet makes new recovery codes to show; they replace the old ones only when one is typed
// back (FinishRecoveryCodes).
func NewRecoveryCodeSet(accountID string) (codes []string, token string, err error) {
	if codes, err = auth.NewRecoveryCodes(); err != nil {
		return nil, "", err
	}
	token, err = sealSetup(totpSetup{Account: accountID, Codes: codes, Stage: "renew"})
	return codes, token, err
}

// FinishRecoveryCodes replaces the account's recovery codes with the new set, once one is typed back.
func FinishRecoveryCodes(accountID, token, typed, ip string) error {
	s, err := openSetup(token, accountID, "renew")
	if err != nil {
		return err
	}
	if !typedOneOf(typed, s.Codes, accountID) {
		return ErrWrongCode
	}
	if err := db.ReplaceRecoveryCodes(accountID, hashCodes(accountID, s.Codes)); err != nil {
		return err
	}
	db.Audit("mfa.recovery_codes_renewed", accountID, "", ip, nil)
	return nil
}

func typedOneOf(typed string, codes []string, accountID string) bool {
	h := auth.HashRecoveryCode(accountID, typed)
	return slices.ContainsFunc(codes, func(c string) bool { return auth.HashRecoveryCode(accountID, c) == h })
}

func hashCodes(accountID string, codes []string) []string {
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i] = auth.HashRecoveryCode(accountID, c)
	}
	return out
}

// ---- S13: the second factor -------------------------------------------------------

func mfaPage(w http.ResponseWriter, r *http.Request) {
	f, ok := readMFAFlow(r)
	if !ok || f.Setup {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	Render(w, http.StatusOK, "mfa", Page{Title: "Two-factor", CSRF: httpx.CSRFToken(w, r), Recovery: r.URL.Query().Has("recovery")})
}

func mfaSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	f, ok := readMFAFlow(r)
	if !ok || f.Setup {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	recovery := r.PostFormValue("method") == "recovery"
	page := Page{Title: "Two-factor", Recovery: recovery, FieldErrors: map[string]string{}}
	show := func(status int) {
		page.CSRF = httpx.CSRFToken(w, r)
		Render(w, status, "mfa", page)
	}
	if !httpx.CSRFValid(r) {
		page.Error = "The form had expired. Try again."
		show(http.StatusForbidden)
		return
	}
	ok, method, left, err := VerifySecondFactor(f.Account, r.PostFormValue("code"), recovery)
	ip := httpx.ClientIP(r)
	switch {
	case errors.Is(err, ErrTooManyAttempts):
		page.Error = "Too many wrong codes. Wait 15 minutes, then try again."
		show(http.StatusTooManyRequests)
		return
	case err != nil:
		slog.Error("failed to check a second factor", "error", err)
		Error(w, ServerError)
		return
	case !ok:
		db.Audit("mfa.failure", f.Account, "", ip, map[string]any{"method": method})
		if recovery {
			page.FieldErrors["code"] = "That recovery code is wrong or was used already."
		} else {
			page.FieldErrors["code"] = "That code is wrong. Codes change every 30 seconds."
		}
		show(http.StatusUnauthorized)
		return
	}
	detail := map[string]any{"method": method}
	if method == "recovery_code" {
		detail["recovery_codes_left"] = left
	}
	completeMFAFlow(w, r, f, detail)
}

// completeMFAFlow signs in, or steps the session up, once the second factor is passed.
func completeMFAFlow(w http.ResponseWriter, r *http.Request, f mfaFlow, detail map[string]any) {
	httpx.ClearFlowCookie(w, mfaCookie)
	ip := httpx.ClientIP(r)
	if f.Purpose == "stepup" {
		sess, ok := httpx.SessionFromRequest(r)
		if !ok || sess.AccountID != f.Account {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err := db.StepUpSession(sess.ID); err != nil {
			Error(w, ServerError)
			return
		}
		db.Audit("mfa.step_up", f.Account, "", ip, detail)
		http.Redirect(w, r, continueTo(httpx.SafeReturnTo(f.ReturnTo)), http.StatusSeeOther)
		return
	}
	acct, err := db.GetAccount(f.Account)
	if err != nil || acct.Status != "active" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if _, err := httpx.StartSession(w, r, acct.ID, "pwd", "otp"); err != nil {
		slog.Error("failed to start a session", "error", err)
		Error(w, ServerError)
		return
	}
	loginsTotal.WithLabelValues("success").Inc()
	db.TouchLogin(acct.ID)
	db.Audit("login.success", acct.ID, "", ip, detail)
	returnTo := httpx.SafeReturnTo(f.ReturnTo)
	if acct.MustChangePassword {
		http.Redirect(w, r, MustChangePasswordURL(returnTo), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, continueTo(returnTo), http.StatusSeeOther)
}

// mfaCancel is "Sign out" on the two-factor pages: it drops the waiting sign-in, and ends the session of
// a step-up.
func mfaCancel(w http.ResponseWriter, r *http.Request) {
	if !httpx.CSRFValid(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	httpx.ClearFlowCookie(w, mfaCookie)
	if sess, ok := httpx.SessionFromRequest(r); ok {
		if targets, err := db.RevokeSession(sess.ID); err == nil {
			notices := make([]db.LogoutNotice, len(targets))
			for i, t := range targets {
				notices[i] = db.LogoutNotice{LogoutTarget: t, AccountID: sess.AccountID, SessionID: sess.ID}
			}
			SendLogoutNotices(notices)
		}
		db.Audit("logout", sess.AccountID, "", httpx.ClientIP(r), map[string]any{"from": "two-factor"})
		httpx.ClearSessionCookie(w)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- S15, S16: the required setup ----------------------------------------------------

func setupAccount(r *http.Request) (mfaFlow, db.Account, bool) {
	f, ok := readMFAFlow(r)
	if !ok || !f.Setup {
		return mfaFlow{}, db.Account{}, false
	}
	acct, err := db.GetAccount(f.Account)
	return f, acct, err == nil
}

func setupPage(w http.ResponseWriter, r *http.Request, f mfaFlow, view TOTPSetupView, errs map[string]string) Page {
	return Page{Title: "Set up two-factor", CSRF: httpx.CSRFToken(w, r), Message: f.Reason,
		// The QR code is a PNG that Guardian made itself, so it is safe as a data: URI.
		QRCode:       template.URL(view.QRCode),
		SecretGroups: auth.GroupSecret(view.Secret), Token: view.SetupToken, FieldErrors: errs}
}

func mfaSetupPage(w http.ResponseWriter, r *http.Request) {
	f, acct, ok := setupAccount(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	view, err := NewTOTPSetup(acct)
	if err != nil {
		slog.Error("failed to start a two-factor setup", "error", err)
		Error(w, ServerError)
		return
	}
	Render(w, http.StatusOK, "mfasetup", setupPage(w, r, f, view, nil))
}

func mfaSetupSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	f, acct, ok := setupAccount(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !httpx.CSRFValid(r) {
		http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
		return
	}
	switch r.PostFormValue("step") {
	case "scan":
		codes, next, err := ConfirmTOTPSetup(acct.ID, r.PostFormValue("token"), r.PostFormValue("code"))
		switch {
		case errors.Is(err, ErrWrongCode):
			view, err := NewTOTPSetup(acct)
			if err != nil {
				Error(w, ServerError)
				return
			}
			// A wrong code shows a new secret: the old one may have been scanned wrongly.
			Render(w, http.StatusBadRequest, "mfasetup", setupPage(w, r, f, view,
				map[string]string{"code": "That code is wrong. Scan this new QR code and try again."}))
		case err != nil:
			http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
		default:
			Render(w, http.StatusOK, "recoverycodes", Page{Title: "Recovery codes", CSRF: httpx.CSRFToken(w, r),
				Codes: codes, Token: next})
		}
	case "codes":
		token := r.PostFormValue("token")
		err := FinishTOTPSetup(acct, token, r.PostFormValue("code"), httpx.ClientIP(r))
		switch {
		case errors.Is(err, ErrWrongCode):
			Render(w, http.StatusBadRequest, "recoverycodes", Page{Title: "Recovery codes", CSRF: httpx.CSRFToken(w, r),
				Codes: SetupCodes(acct.ID, token), Token: token,
				FieldErrors: map[string]string{"code": "That is not one of the codes above."}})
		case err != nil:
			http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
		default:
			completeMFAFlow(w, r, f, map[string]any{"method": "totp", "set_up": true})
		}
	default:
		http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
	}
}
