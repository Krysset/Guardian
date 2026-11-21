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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"rsc.io/qr"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	"guardian/internal/mail"
	"guardian/internal/passkey"
	db "guardian/internal/store"
)

// Two-factor at sign-in (S13, and S14 for a security key), the required setup (S15, S16), and the setup
// logic the API shares.
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
	// Password is a fingerprint of the account's password hash when the flow began: a password change or
	// reset in between ends the flow.
	Password string `json:"w"`
}

// passwordFingerprint identifies the account's current password hash without revealing it.
func passwordFingerprint(accountID string) string {
	hash, err := db.GetPasswordHash(accountID)
	if err != nil {
		return ""
	}
	return auth.HashToken("pw:" + hash)[:16]
}

// seal and unseal carry a value through the browser, encrypted and bound to its kind (see auth.Seal).
func seal(kind string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return auth.Seal(kind, b)
}

func unseal(kind, sealed string, v any) bool {
	b, err := auth.Open(kind, sealed)
	return err == nil && json.Unmarshal(b, v) == nil
}

func startMFAFlow(w http.ResponseWriter, r *http.Request, f mfaFlow) {
	f.Expires = time.Now().Add(mfaFlowLifetime).Unix()
	f.Password = passwordFingerprint(f.Account)
	sealed, err := seal("mfa-flow", f)
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
	if !unseal("mfa-flow", httpx.FlowCookie(r, mfaCookie), &f) || time.Now().Unix() > f.Expires ||
		(f.Purpose != "signin" && f.Purpose != "stepup") || f.Password != passwordFingerprint(f.Account) {
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
	has, err := db.HasSecondFactor(accountID)
	if err != nil || has {
		return "challenge", "", err
	}
	reason, err = db.MFARequirement(accountID)
	if err != nil || reason == "" {
		return "", "", err
	}
	return "setup", reason, nil
}

// StepUp sends a signed-in user through two-factor before continuing to returnTo: a code or a security key
// if they have one, otherwise the setup. appName says who requires it.
func StepUp(w http.ResponseWriter, r *http.Request, accountID, returnTo, appName string) {
	has, err := db.HasSecondFactor(accountID)
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
	if httpx.TwoFactor(sess.AMR) {
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
	// Counted before it is checked, so codes sent together cannot all slip under the limit; a right one
	// clears the count.
	key := "mfa:account:" + accountID
	n, err := db.RateLimitHit(key, mfaWindow)
	if err != nil {
		return false, "", 0, err
	}
	if n > mfaAttempts {
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
		return false, method, 0, nil
	}
	db.RateLimitReset(key, mfaWindow)
	return true, method, left, nil
}

// VerifyKey checks a security key's answer (see passkey.BeginLogin) for the account, under the same limit
// as wrong codes, and returns the key's name. A key that is not recognised is passkey.ErrNotRecognised; a
// stale or reused token passkey.ErrExpired.
func VerifyKey(accountID, token string, response []byte) (string, error) {
	key := "mfa:account:" + accountID
	n, err := db.RateLimitHit(key, mfaWindow)
	if err != nil {
		return "", err
	}
	if n > mfaAttempts {
		httpx.CountRefused("mfa")
		return "", ErrTooManyAttempts
	}
	name, err := passkey.FinishLogin(accountID, token, response)
	if errors.Is(err, passkey.ErrNotRecognised) {
		return "", err
	}
	if errors.Is(err, passkey.ErrExpired) {
		db.RateLimitRefund(key, mfaWindow) // a stale ceremony is no guess
	}
	if err == nil {
		db.RateLimitReset(key, mfaWindow)
	}
	return name, err
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

// totpSetup is the state of a setup between its steps, sealed into a token. A security key added as the
// first second factor waits here too, checked but not saved, while its recovery codes are shown.
type totpSetup struct {
	Account string      `json:"a"`
	Secret  string      `json:"s,omitempty"`
	Codes   []string    `json:"c,omitempty"` // the recovery codes shown, once the app or key is confirmed
	Step    int64       `json:"n,omitempty"` // the time step of the confirming code
	Stage   string      `json:"g"`           // "scan", "codes" (app or key confirmed, codes shown) or "renew" (new codes only)
	Key     *pendingKey `json:"k,omitempty"`
	Expires int64       `json:"e"`
}

// pendingKey is a checked security key waiting for its recovery codes to be saved.
type pendingKey struct {
	Name      string `json:"n"`
	ID        []byte `json:"i"`
	Cred      []byte `json:"c"`
	SignCount uint32 `json:"s"`
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
	return seal("totp-setup", s)
}

func openSetup(token, accountID, stage string) (totpSetup, error) {
	var s totpSetup
	if !unseal("totp-setup", token, &s) || s.Account != accountID || s.Stage != stage || time.Now().Unix() > s.Expires {
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

// FinishSetup checks that one recovery code was saved (typed back), then saves the authenticator app or the
// security key with the codes, replacing any earlier codes, and tells the account by email (E4). It returns
// the amr value the new method stands for ("otp" or "hwk").
func FinishSetup(acct db.Account, token, typed, ip string) (string, error) {
	s, err := openSetup(token, acct.ID, "codes")
	if err != nil {
		return "", err
	}
	if !typedOneOf(typed, s.Codes, acct.ID) {
		return "", ErrWrongCode
	}
	if s.Key != nil {
		_, err := saveKey(acct, s.Key, hashCodes(acct.ID, s.Codes), ip)
		return "hwk", err
	}
	sealed, err := auth.Encrypt([]byte(s.Secret), TOTPSecretAAD(acct.ID))
	if err != nil {
		return "", err
	}
	if err := db.SaveTOTP(acct.ID, sealed, hashCodes(acct.ID, s.Codes), s.Step); err != nil {
		return "", err
	}
	db.Audit("mfa.totp_added", acct.ID, "", ip, nil)
	if acct.Email != "" {
		mail.Enqueue(mail.TwoFactorChanged(acct.Email, true, "Authenticator app", time.Now(), acct.Zoneinfo))
	}
	return "otp", nil
}

// KeyMethod names a security key in emails.
func KeyMethod(name string) string { return "Security key or passkey “" + name + "”" }

func saveKey(acct db.Account, k *pendingKey, codeHashes []string, ip string) (db.SecurityKey, error) {
	saved, err := db.AddSecurityKey(acct.ID, k.Name, k.ID, k.Cred, k.SignCount, codeHashes)
	if err != nil {
		return db.SecurityKey{}, err
	}
	db.Audit("mfa.key_added", acct.ID, "", ip, map[string]any{"key": k.Name, "passkey": saved.Passkey})
	if acct.Email != "" {
		mail.Enqueue(mail.TwoFactorChanged(acct.Email, true, KeyMethod(k.Name), time.Now(), acct.Zoneinfo))
	}
	return saved, nil
}

// AddKey stores a security key checked by passkey.FinishRegistration. An account that already has a second
// factor gets it saved at once (saved). For the first one, the recovery codes come first: AddKey returns
// them with a token for FinishSetup, and nothing is saved until one code is typed back.
func AddKey(acct db.Account, name string, k passkey.NewKey, ip string) (saved *db.SecurityKey, codes []string, token string, err error) {
	pk := &pendingKey{Name: name, ID: k.ID, Cred: k.Credential, SignCount: k.SignCount}
	has, err := db.HasSecondFactor(acct.ID)
	if err != nil {
		return nil, nil, "", err
	}
	if has {
		s, err := saveKey(acct, pk, nil, ip)
		return &s, nil, "", err
	}
	if codes, err = auth.NewRecoveryCodes(); err != nil {
		return nil, nil, "", err
	}
	token, err = sealSetup(totpSetup{Account: acct.ID, Codes: codes, Stage: "codes", Key: pk})
	return nil, codes, token, err
}

// KeyName checks the name a user gives a security key: 1-64 characters, "Security key" when left empty.
func KeyName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Security key", true
	}
	return name, utf8.RuneCountInString(name) <= 64 && !strings.ContainsFunc(name, unicode.IsControl)
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

// ---- S13, S14: the second factor ---------------------------------------------------

// mfaMode picks what S13 asks for: ?recovery, ?key or ?code, else the authenticator code if the account has
// the app and the security key if it has only keys.
func mfaMode(r *http.Request, st db.MFAStatus) string {
	q := r.URL.Query()
	switch {
	case q.Has("recovery"):
		return "recovery"
	case q.Has("key") && len(st.SecurityKeys) > 0, !st.TOTP && len(st.SecurityKeys) > 0 && !q.Has("code"):
		return "key"
	}
	return "code"
}

// renderMFA shows S13 (a code), or S14 (a security key: the page carries a fresh challenge).
func renderMFA(w http.ResponseWriter, r *http.Request, f mfaFlow, mode string, page Page, status int) {
	st, err := db.GetMFAStatus(f.Account)
	if err != nil {
		Error(w, ServerError)
		return
	}
	if mode == "" {
		mode = mfaMode(r, st)
	}
	page.Title = "Two-factor"
	page.Recovery, page.Key = mode == "recovery", mode == "key"
	page.HasTOTP, page.HasKeys = st.TOTP, len(st.SecurityKeys) > 0
	if page.Key {
		opts, token, err := passkey.BeginLogin(f.Account)
		if err != nil {
			slog.Error("failed to start a security key check", "error", err)
			Error(w, ServerError)
			return
		}
		page.KeyOptions, page.Token = string(opts), token
	}
	page.CSRF = httpx.CSRFToken(w, r)
	Render(w, status, "mfa", page)
}

func mfaPage(w http.ResponseWriter, r *http.Request) {
	f, ok := readMFAFlow(r)
	if !ok || f.Setup {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	renderMFA(w, r, f, "", Page{}, http.StatusOK)
}

func mfaSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	f, ok := readMFAFlow(r)
	if !ok || f.Setup {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	mode := r.PostFormValue("method")
	if mode != "recovery" && mode != "key" {
		mode = "code"
	}
	fail := func(status int, page Page) { renderMFA(w, r, f, mode, page, status) }
	if !httpx.CSRFValid(r) {
		fail(http.StatusForbidden, Page{Error: "The form had expired. Try again."})
		return
	}
	ip := httpx.ClientIP(r)
	if mode == "key" {
		name, err := VerifyKey(f.Account, r.PostFormValue("token"), []byte(r.PostFormValue("credential")))
		switch {
		case errors.Is(err, ErrTooManyAttempts):
			fail(http.StatusTooManyRequests, Page{Error: "Too many failed attempts. Wait 15 minutes, then try again."})
		case errors.Is(err, passkey.ErrExpired):
			loginFailures.WithLabelValues("key", "expired").Inc()
			fail(http.StatusBadRequest, Page{Error: "That took too long. Try again."})
		case errors.Is(err, passkey.ErrNotRecognised):
			loginFailures.WithLabelValues("key", "not_recognised").Inc()
			db.Audit("mfa.failure", f.Account, "", ip, map[string]any{"method": "security_key"})
			fail(http.StatusUnauthorized, Page{Error: "That security key isn't one of yours. Try another, or use another method."})
		case err != nil:
			slog.Error("failed to check a security key", "error", err)
			Error(w, ServerError)
		default:
			completeMFAFlow(w, r, f, "hwk", map[string]any{"method": "security_key", "key": name})
		}
		return
	}
	recovery := mode == "recovery"
	ok, method, left, err := VerifySecondFactor(f.Account, r.PostFormValue("code"), recovery)
	switch {
	case errors.Is(err, ErrTooManyAttempts):
		fail(http.StatusTooManyRequests, Page{Error: "Too many wrong codes. Wait 15 minutes, then try again."})
		return
	case err != nil:
		slog.Error("failed to check a second factor", "error", err)
		Error(w, ServerError)
		return
	case !ok:
		factor := "code"
		if recovery {
			factor = "recovery_code"
		}
		loginFailures.WithLabelValues(factor, "wrong_code").Inc()
		db.Audit("mfa.failure", f.Account, "", ip, map[string]any{"method": method})
		msg := "That code is wrong. Codes change every 30 seconds."
		if recovery {
			msg = "That recovery code is wrong or was used already."
		}
		fail(http.StatusUnauthorized, Page{FieldErrors: map[string]string{"code": msg}})
		return
	}
	detail := map[string]any{"method": method}
	if method == "recovery_code" {
		detail["recovery_codes_left"] = left
	}
	completeMFAFlow(w, r, f, "otp", detail)
}

// completeMFAFlow signs in, or steps the session up, once the second factor is passed. amr is the method:
// "otp" for a code, "hwk" for a security key.
func completeMFAFlow(w http.ResponseWriter, r *http.Request, f mfaFlow, amr string, detail map[string]any) {
	httpx.ClearFlowCookie(w, mfaCookie)
	ip := httpx.ClientIP(r)
	if f.Purpose == "stepup" {
		sess, ok := httpx.SessionFromRequest(r)
		if !ok || sess.AccountID != f.Account {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err := db.StepUpSession(sess.ID, amr); err != nil {
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
	method := "password_and_code"
	if amr == "hwk" {
		method = "password_and_key"
	} else if detail["method"] == "recovery_code" {
		method = "password_and_recovery_code"
	}
	finishSignIn(w, r, acct, method, detail, httpx.SafeReturnTo(f.ReturnTo), "pwd", amr)
}

// finishSignIn starts the session and continues: to the new-password page first if the account has a
// temporary password, else back into the app's sign-in, or Home. method is the label of guardian_logins_total.
func finishSignIn(w http.ResponseWriter, r *http.Request, acct db.Account, method string, detail map[string]any, returnTo string, amr ...string) {
	if _, err := httpx.StartSession(w, r, acct.ID, amr...); err != nil {
		slog.Error("failed to start a session", "error", err)
		Error(w, ServerError)
		return
	}
	loginsTotal.WithLabelValues(method).Inc()
	db.TouchLogin(acct.ID)
	db.Audit("login.success", acct.ID, "", httpx.ClientIP(r), detail)
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

// setupAccount reads a setup flow. A setup flow only adds the first second factor: once the account has
// one (added elsewhere since the flow began), the flow is over, so it can never add or replace a factor
// of an account that already has one.
func setupAccount(r *http.Request) (mfaFlow, db.Account, bool) {
	f, ok := readMFAFlow(r)
	if !ok || !f.Setup {
		return mfaFlow{}, db.Account{}, false
	}
	if has, err := db.HasSecondFactor(f.Account); err != nil || has {
		return mfaFlow{}, db.Account{}, false
	}
	acct, err := db.GetAccount(f.Account)
	return f, acct, err == nil
}

// confirmPassword checks the account's password before a step-up adds its first second factor (a step-up
// starts from a session, which may be old or someone else's browser). Wrong passwords count against the
// same limit as confirming it's you in the management UI. It returns the error to show, or "".
func confirmPassword(accountID, password string) string {
	key := "reauth:account:" + accountID
	n, err := db.RateLimitHit(key, ReauthWindow)
	if err != nil {
		return "Something went wrong. Try again."
	}
	if n > ReauthLimit {
		httpx.CountRefused("reauth")
		return "Too many wrong passwords. Try again in 15 minutes."
	}
	hash, err := db.GetPasswordHash(accountID)
	if err != nil || hash == "" || len(password) > 1024 || !auth.VerifyPassword(password, hash) {
		return "That password is wrong."
	}
	db.RateLimitReset(key, ReauthWindow)
	return ""
}

// ReauthWindow and ReauthLimit limit wrong passwords when confirming it's you: ReauthLimit per account in
// ReauthWindow.
const (
	ReauthWindow = 15 * time.Minute
	ReauthLimit  = 5
)

// renderSetup shows S15: the authenticator app (a QR code), or a security key (?method=key).
func renderSetup(w http.ResponseWriter, r *http.Request, f mfaFlow, acct db.Account, key bool, page Page, status int) {
	page.Title, page.Message, page.Key = "Set up two-factor", f.Reason, key
	page.AskPassword = f.Purpose == "stepup"
	if key {
		opts, token, err := passkey.BeginRegistration(acct.ID)
		if err != nil {
			slog.Error("failed to start adding a security key", "error", err)
			Error(w, ServerError)
			return
		}
		page.KeyOptions, page.Token = string(opts), token
	} else {
		view, err := NewTOTPSetup(acct)
		if err != nil {
			slog.Error("failed to start a two-factor setup", "error", err)
			Error(w, ServerError)
			return
		}
		// The QR code is a PNG that Guardian made itself, so it is safe as a data: URI.
		page.QRCode, page.SecretGroups, page.Token = template.URL(view.QRCode), auth.GroupSecret(view.Secret), view.SetupToken
	}
	page.CSRF = httpx.CSRFToken(w, r)
	Render(w, status, "mfasetup", page)
}

func mfaSetupPage(w http.ResponseWriter, r *http.Request) {
	f, acct, ok := setupAccount(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	renderSetup(w, r, f, acct, r.URL.Query().Get("method") == "key", Page{}, http.StatusOK)
}

func showCodes(w http.ResponseWriter, r *http.Request, codes []string, token string, errs map[string]string, status int) {
	Render(w, status, "recoverycodes", Page{Title: "Recovery codes", CSRF: httpx.CSRFToken(w, r),
		Codes: codes, Token: token, FieldErrors: errs})
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
	// A step-up's setup confirms the password first: otherwise anyone holding the session could add their own
	// second factor, and with it the right to make protected changes.
	if step := r.PostFormValue("step"); f.Purpose == "stepup" && (step == "scan" || step == "key") {
		if msg := confirmPassword(acct.ID, r.PostFormValue("current_password")); msg != "" {
			renderSetup(w, r, f, acct, step == "key", Page{FieldErrors: map[string]string{"current_password": msg}}, http.StatusBadRequest)
			return
		}
	}
	switch r.PostFormValue("step") {
	case "scan":
		codes, next, err := ConfirmTOTPSetup(acct.ID, r.PostFormValue("token"), r.PostFormValue("code"))
		switch {
		case errors.Is(err, ErrWrongCode):
			// A wrong code shows a new secret: the old one may have been scanned wrongly.
			renderSetup(w, r, f, acct, false, Page{FieldErrors: map[string]string{"code": "That code is wrong. Scan this new QR code and try again."}}, http.StatusBadRequest)
		case err != nil:
			http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
		default:
			showCodes(w, r, codes, next, nil, http.StatusOK)
		}
	case "key":
		name, valid := KeyName(r.PostFormValue("name"))
		if !valid {
			renderSetup(w, r, f, acct, true, Page{FieldErrors: map[string]string{"name": "Use at most 64 characters."}}, http.StatusBadRequest)
			return
		}
		k, err := passkey.FinishRegistration(acct.ID, r.PostFormValue("token"), []byte(r.PostFormValue("credential")))
		if errors.Is(err, passkey.ErrExpired) || errors.Is(err, passkey.ErrNotRecognised) {
			renderSetup(w, r, f, acct, true, Page{Error: "The security key could not be added. Try again."}, http.StatusBadRequest)
			return
		} else if err != nil {
			slog.Error("failed to add a security key", "error", err)
			Error(w, ServerError)
			return
		}
		saved, codes, next, err := AddKey(acct, name, k, httpx.ClientIP(r))
		switch {
		case errors.Is(err, db.ErrCredentialInUse):
			renderSetup(w, r, f, acct, true, Page{Error: "That security key is already registered. Use another one."}, http.StatusConflict)
		case err != nil:
			slog.Error("failed to add a security key", "error", err)
			Error(w, ServerError)
		case saved != nil:
			completeMFAFlow(w, r, f, "hwk", map[string]any{"method": "security_key", "set_up": true})
		default:
			showCodes(w, r, codes, next, nil, http.StatusOK)
		}
	case "codes":
		token := r.PostFormValue("token")
		amr, err := FinishSetup(acct, token, r.PostFormValue("code"), httpx.ClientIP(r))
		switch {
		case errors.Is(err, ErrWrongCode):
			showCodes(w, r, SetupCodes(acct.ID, token), token, map[string]string{"code": "That is not one of the codes above."}, http.StatusBadRequest)
		case err != nil:
			http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
		default:
			method := "totp"
			if amr == "hwk" {
				method = "security_key"
			}
			completeMFAFlow(w, r, f, amr, map[string]any{"method": method, "set_up": true})
		}
	default:
		http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
	}
}
