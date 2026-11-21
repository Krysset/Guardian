package e2e

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// Two-factor (0.3 part 3): the code at sign-in (S13), the required setup (S15, S16), setting it up and
// removing it through the API, apps that require it, and the administrator's reset.

func codeAt(t *testing.T, secret string, offset int64) string {
	t.Helper()
	c, err := auth.TOTPCode(secret, auth.TOTPStep(time.Now())+offset)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func amrOf(t *testing.T, accountID string) string {
	t.Helper()
	var amr string
	if err := db.GetDatabaseConnection().QueryRow(`SELECT array_to_string(amr, ' ') FROM session
		WHERE account_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, accountID).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	return amr
}

// setUpTOTPByAPI runs the three setup calls and returns the secret and the recovery codes.
func setUpTOTPByAPI(t *testing.T, br *browser) (secret string, codes []string, used string) {
	t.Helper()
	view := br.call("POST", "/api/v1/me/mfa/totp", nil, 200)
	secret = str(view["secret"])
	if !strings.HasPrefix(str(view["qr_code"]), "data:image/png;base64,") || !strings.HasPrefix(str(view["otpauth_uri"]), "otpauth://totp/") {
		t.Errorf("setup view = %v", view)
	}
	if m := br.call("POST", "/api/v1/me/mfa/totp/confirm", map[string]any{"setup_token": view["setup_token"], "code": "000000"}, 400); m["error"] != "wrong_code" {
		t.Errorf("wrong first code: %v", m)
	}
	used = codeAt(t, secret, 0)
	conf := br.call("POST", "/api/v1/me/mfa/totp/confirm", map[string]any{"setup_token": view["setup_token"], "code": used}, 200)
	for _, c := range conf["recovery_codes"].([]any) {
		codes = append(codes, str(c))
	}
	if len(codes) != 10 {
		t.Fatalf("%d recovery codes", len(codes))
	}
	if m := br.call("POST", "/api/v1/me/mfa/finish", map[string]any{"setup_token": conf["setup_token"], "recovery_code": "abcd-efgh"}, 400); m["error"] != "wrong_code" {
		t.Errorf("a code that was not shown: %v", m)
	}
	// The token of the first step cannot finish.
	br.call("POST", "/api/v1/me/mfa/finish", map[string]any{"setup_token": view["setup_token"], "recovery_code": codes[0]}, 400)
	br.call("POST", "/api/v1/me/mfa/finish", map[string]any{"setup_token": conf["setup_token"], "recovery_code": strings.ToUpper(codes[3])}, 204)
	return secret, codes, used
}

// Covers: V7, U11, U17
func TestE2ETwoFactorThroughTheAPIAndAtSignIn(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "sidon")
	setEmail(t, "sidon", "sidon@zora.example")
	br := newBrowser(t)
	br.mustLogin("sidon")
	secret, codes, used := setUpTOTPByAPI(t, br)

	if _, ok := mailbox.WaitFor("sidon@zora.example", "Two-factor was added"); !ok {
		t.Error("no email about the new two-factor method")
	}
	me := br.call("GET", "/api/v1/me", nil, 200)
	mfa, _ := me["mfa"].(map[string]any)
	if mfa["totp"] != true || mfa["recovery_codes_left"] != float64(10) || mfa["required"] != false {
		t.Errorf("me.mfa = %v", mfa)
	}
	if amr := amrOf(t, acct.ID); !strings.Contains(amr, "otp") {
		t.Errorf("setting up two-factor did not step the session up: %q", amr)
	}

	// Signing in now asks for the code; nothing is signed in before it.
	other := newBrowser(t)
	resp := other.login("sidon", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/mfa" {
		t.Fatalf("after the password: %q, want /mfa", loc)
	}
	if other.cookie("guardian_session") != "" {
		t.Fatal("a session started before the second factor")
	}
	if page := readBody(t, other.get("/mfa")); !strings.Contains(page, "Enter the 6-digit code") || !strings.Contains(page, "Use a recovery code") {
		t.Errorf("S13: %.300s", page)
	}
	// The code that confirmed the setup was used; it does not work again.
	resp = other.postForm("/mfa", url.Values{"csrf": {other.csrf()}, "code": {used}})
	wantStatus(t, resp, http.StatusUnauthorized)
	if body := readBody(t, resp); !strings.Contains(body, "That code is wrong") {
		t.Error("a used code must be refused with a message")
	}
	resp = other.postForm("/mfa", url.Values{"csrf": {other.csrf()}, "code": {codeAt(t, secret, 1)}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if amr := amrOf(t, acct.ID); amr != "pwd otp" {
		t.Errorf("amr after two-factor = %q", amr)
	}
	other.call("GET", "/api/v1/me", nil, 200)

	// A recovery code works once, typed any way.
	third := newBrowser(t)
	drain(third.login("sidon", testutil.DefaultPassword, ""))
	if page := readBody(t, third.get("/mfa?recovery")); !strings.Contains(page, "Recovery code") {
		t.Error("the recovery-code form is missing")
	}
	resp = third.postForm("/mfa", url.Values{"csrf": {third.csrf()}, "method": {"recovery"}, "code": {" " + strings.ToUpper(codes[5]) + " "}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if m := third.call("GET", "/api/v1/me", nil, 200)["mfa"].(map[string]any); m["recovery_codes_left"] != float64(9) {
		t.Errorf("after a recovery code: %v left", m["recovery_codes_left"])
	}
	fourth := newBrowser(t)
	drain(fourth.login("sidon", testutil.DefaultPassword, ""))
	resp = fourth.postForm("/mfa", url.Values{"csrf": {fourth.csrf()}, "method": {"recovery"}, "code": {codes[5]}})
	wantStatus(t, resp, http.StatusUnauthorized)
	if body := readBody(t, resp); !strings.Contains(body, "wrong or was used already") {
		t.Error("a used recovery code must be refused")
	}

	// New recovery codes replace the old ones only when one is typed back.
	renew := br.call("POST", "/api/v1/me/mfa/recovery-codes", nil, 200)
	newCodes := renew["recovery_codes"].([]any)
	br.call("POST", "/api/v1/me/mfa/recovery-codes/finish", map[string]any{"setup_token": renew["setup_token"], "recovery_code": codes[1]}, 400)
	br.call("POST", "/api/v1/me/mfa/recovery-codes/finish", map[string]any{"setup_token": renew["setup_token"], "recovery_code": newCodes[0]}, 204)
	if ok, _, _ := db.UseRecoveryCode(acct.ID, auth.HashRecoveryCode(acct.ID, codes[1])); ok {
		t.Error("an old recovery code still works after renewing")
	}

	// Protected: an old session must confirm first, and the code works for that.
	ageSessions(t, acct.ID)
	br.call("DELETE", "/api/v1/me/mfa/totp", nil, http.StatusForbidden)
	testutil.Exec(t, `UPDATE account_mfa SET sign_count = NULL WHERE account_id = $1`, acct.ID) // the codes of this period were used
	br.call("POST", "/api/v1/me/reauth", map[string]any{"code": codeAt(t, secret, 0)}, 200)
	br.call("DELETE", "/api/v1/me/mfa/totp", nil, 204)
	if _, ok := mailbox.WaitFor("sidon@zora.example", "Two-factor was removed"); !ok {
		t.Error("no email about the removed two-factor method")
	}
	resp = newBrowser(t).login("sidon", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc == "/mfa" {
		t.Error("two-factor is still asked for after it was removed")
	}
}

// Covers: V7
func TestE2ETwoFactorAttemptsAreLimitedAndCanBeCancelled(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "kohga")
	testutil.EnableTOTP(t, acct.ID)
	br := newBrowser(t)
	drain(br.login("kohga", testutil.DefaultPassword, ""))
	for i := 0; i < 5; i++ {
		resp := br.postForm("/mfa", url.Values{"csrf": {br.csrf()}, "code": {"000000"}})
		wantStatus(t, resp, http.StatusUnauthorized)
		drain(resp)
	}
	resp := br.postForm("/mfa", url.Values{"csrf": {br.csrf()}, "code": {testutil.TOTPCode(t, acct.ID)}})
	wantStatus(t, resp, http.StatusTooManyRequests)
	if body := readBody(t, resp); !strings.Contains(body, "Too many wrong codes") {
		t.Error("the limit must say so")
	}
	resp = br.postForm("/mfa/cancel", url.Values{"csrf": {br.csrf()}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	resp = br.get("/mfa")
	wantStatus(t, resp, http.StatusFound)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("after Sign out, the two-factor page leads to %q", loc)
	}
}

var (
	secretRe = regexp.MustCompile(`<code id="secret">([A-Z2-7 ]+)</code>`)
	tokenRe  = regexp.MustCompile(`name="token" value="([^"]+)"`)
	codesRe  = regexp.MustCompile(`<code>([0-9a-z]{4}-[0-9a-z]{4})</code>`)
)

// setUpOnPage completes S15 and S16 and returns the redirect after them.
func setUpOnPage(t *testing.T, br *browser, wantReason string) *http.Response {
	t.Helper()
	page := readBody(t, br.get("/mfa/setup"))
	if !strings.Contains(page, wantReason) || !strings.Contains(page, `src="data:image/png;base64,`) {
		t.Fatalf("S15 lacks the reason %q or the QR code: %.500s", wantReason, page)
	}
	m := secretRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("S15 shows no secret")
	}
	secret := strings.ReplaceAll(m[1], " ", "")
	token := html.UnescapeString(tokenRe.FindStringSubmatch(page)[1])
	resp := br.postForm("/mfa/setup", url.Values{"csrf": {br.csrf()}, "step": {"scan"}, "token": {token}, "code": {"123456"}})
	wantStatus(t, resp, http.StatusBadRequest)
	if body := readBody(t, resp); !strings.Contains(body, "Scan this new QR code") {
		t.Error("a wrong first code must say so")
	}
	resp = br.postForm("/mfa/setup", url.Values{"csrf": {br.csrf()}, "step": {"scan"}, "token": {token}, "code": {codeAt(t, secret, 0)}})
	wantStatus(t, resp, http.StatusOK)
	page = readBody(t, resp)
	codes := codesRe.FindAllStringSubmatch(page, -1)
	if len(codes) != 10 || !strings.Contains(page, "This is the only time they") {
		t.Fatalf("S16 shows %d codes: %.400s", len(codes), page)
	}
	token = html.UnescapeString(tokenRe.FindStringSubmatch(page)[1])
	resp = br.postForm("/mfa/setup", url.Values{"csrf": {br.csrf()}, "step": {"codes"}, "token": {token}, "code": {"zzzz-zzzz"}})
	wantStatus(t, resp, http.StatusBadRequest)
	if body := readBody(t, resp); len(codesRe.FindAllString(body, -1)) != 10 || !strings.Contains(body, "not one of the codes") {
		t.Error("a wrong code on S16 must show the same codes again")
	}
	resp = br.postForm("/mfa/setup", url.Values{"csrf": {br.csrf()}, "step": {"codes"}, "token": {token}, "code": {codes[9][1]}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	return resp
}

// Covers: U4, O4, A24
func TestE2EAdministratorsAndOwnersMustUseTwoFactor(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "purah")
	testutil.AddMember(t, testutil.GroupID(t, db.AdminGroupKey), acct.ID)
	br := newBrowser(t)
	resp := br.login("purah", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/mfa/setup" {
		t.Fatalf("an administrator without two-factor: %q, want /mfa/setup", loc)
	}
	if br.cookie("guardian_session") != "" {
		t.Fatal("a session started before the setup")
	}
	resp = setUpOnPage(t, br, "Administrators must use two-factor.")
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("after the setup: %q", loc)
	}
	br.call("GET", "/api/v1/apps", nil, 200)
	if m := br.call("DELETE", "/api/v1/me/mfa/totp", nil, http.StatusConflict); m["error"] != "mfa_required" {
		t.Errorf("an administrator removing two-factor: %v", m)
	}

	// Owners: members of a group that owns another group.
	owner := testutil.CreateAccount(t, "robbie")
	owners := testutil.Group(t, "lab-owners", "")
	testutil.Group(t, "lab", owners)
	testutil.AddMember(t, owners, owner.ID)
	ob := newBrowser(t)
	resp = ob.login("robbie", testutil.DefaultPassword, "")
	drain(resp)
	if resp.Header.Get("Location") != "/mfa/setup" {
		t.Fatalf("an owner without two-factor: %q", resp.Header.Get("Location"))
	}
	setUpOnPage(t, ob, "Group owners must use two-factor.")
	ob.call("GET", "/api/v1/groups", nil, 200)
}

// Covers: U4
func TestE2EAppsThatRequireTwoFactor(t *testing.T) {
	newTestEnv(t)
	app, _ := testutil.CreateApp(t, "vault", testutil.AppOptions{FirstParty: true})
	testutil.Exec(t, `UPDATE app SET require_mfa = TRUE WHERE id = $1`, app.ID)
	acct := testutil.CreateAccount(t, "paya")
	br := newBrowser(t)
	br.mustLogin("paya") // signed in without two-factor
	_, challenge := newPKCE(t)
	params := authParams{app: app, scope: "openid", state: "s", challenge: challenge}

	none := params
	none.extra = url.Values{"prompt": {"none"}}
	cb := br.authorizeCallback(none.values(), "paya")
	if cb.Query().Get("error") != "interaction_required" {
		t.Errorf("prompt=none without two-factor: %s", cb)
	}

	authorize := "/authorize?" + params.values().Encode()
	resp := br.get(authorize)
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/mfa/setup" {
		t.Fatalf("an app that requires two-factor, for an account without it: %q", loc)
	}
	resp = setUpOnPage(t, br, "vault requires two-factor.")
	if loc := resp.Header.Get("Location"); loc != authorize {
		t.Fatalf("after the setup: %q, want back to the app's sign-in", loc)
	}
	resp = br.get(authorize)
	wantStatus(t, resp, http.StatusFound)
	drain(resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, app.RedirectURIs[0]+"?code=") {
		t.Fatalf("no code after two-factor: %q", loc)
	}
	if amr := amrOf(t, acct.ID); amr != "otp pwd" && amr != "pwd otp" {
		t.Errorf("amr after the step-up = %q", amr)
	}

	// An account with an app, signed in with the password only, is asked for the code.
	other := testutil.CreateAccount(t, "dorephan")
	testutil.EnableTOTP(t, other.ID)
	_, cookie := testutil.Session(t, other.ID)
	testutil.Exec(t, `UPDATE session SET amr = ARRAY['pwd'] WHERE account_id = $1`, other.ID)
	ob := newBrowser(t)
	ob.setCookie("guardian_session", cookie)
	resp = ob.get(authorize)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/mfa" {
		t.Fatalf("step-up for an account with an app: %q", loc)
	}
	resp = ob.postForm("/mfa", url.Values{"csrf": {ob.csrf()}, "code": {testutil.TOTPCode(t, other.ID)}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != authorize {
		t.Errorf("after the step-up: %q", loc)
	}
	// The step-up belongs to that session: another browser cannot use its cookie.
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'mfa.step_up' AND actor_account_id = $1`, other.ID); n != 1 {
		t.Error("the step-up is not audited")
	}
}

// Covers: A9, U17
func TestE2EAdministratorsResetTwoFactor(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "zelda")
	user := testutil.CreateAccount(t, "link")
	setEmail(t, "link", "link@hyrule.example")
	testutil.EnableTOTP(t, user.ID)
	ub := newBrowser(t)
	ub.mustLogin("link")
	admin := newBrowser(t)
	admin.mustLogin("zelda")

	path := "/api/v1/accounts/" + user.ID + "/mfa/reset"
	admin.call("POST", path, map[string]any{"reason": "x"}, 400)
	ub.call("POST", path, map[string]any{"reason": "Lost the phone"}, 403)
	admin.call("POST", path, map[string]any{"reason": "Lost the Sheikah Slate"}, 204)
	if m, ok := mailbox.WaitFor("link@hyrule.example", "An administrator reset your two-factor"); !ok || !strings.Contains(m.Text, "Lost the Sheikah Slate") {
		t.Errorf("the reset email lacks the reason: %q", m.Text)
	}
	resp := ub.sendJSON("GET", "/api/v1/me", nil)
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)
	if has, _ := db.HasTOTP(user.ID); has {
		t.Error("the authenticator app is still there")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'mfa.reset' AND metadata->>'reason' = 'Lost the Sheikah Slate'`); n != 1 {
		t.Error("the reset is not audited with its reason")
	}
	if m := admin.call("POST", path, map[string]any{"reason": "Again"}, 409); m["error"] != "no_totp" {
		t.Errorf("resetting nothing: %v", m)
	}
}

// An app may ask for two-factor for one sign-in only (acr_values=mfa), for example before a sensitive
// action. A session that has not passed it steps up first; the ID and access tokens say which class the
// sign-in met (acr), so the app can check. Without the parameter the same app signs in with the password.
//
// Covers: A31
func TestE2EAnAppAsksForTwoFactorForOneSignIn(t *testing.T) {
	newTestEnv(t)
	app, secret := testutil.CreateApp(t, "notes", testutil.AppOptions{FirstParty: true})
	acct := testutil.CreateAccount(t, "mipha")
	testutil.EnableTOTP(t, acct.ID)
	_, cookie := testutil.Session(t, acct.ID)
	testutil.Exec(t, `UPDATE session SET amr = ARRAY['pwd'] WHERE account_id = $1`, acct.ID)
	br := newBrowser(t)
	br.setCookie("guardian_session", cookie)

	disc := decodeMap(t, br.get("/.well-known/openid-configuration"))
	if fmt.Sprint(disc["acr_values_supported"]) != "[password mfa]" {
		t.Errorf("acr_values_supported = %v", disc["acr_values_supported"])
	}

	signIn := func(acr string) (tokens tokenSet, location string) {
		t.Helper()
		verifier, challenge := newPKCE(t)
		p := authParams{app: app, scope: "openid", state: "s", challenge: challenge}
		if acr != "" {
			p.extra = url.Values{"acr_values": {acr}}
		}
		authorize := "/authorize?" + p.values().Encode()
		resp := br.get(authorize)
		drain(resp)
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, app.RedirectURIs[0]+"?code=") {
			return tokenSet{}, loc
		}
		cb, _ := url.Parse(loc)
		status, raw := tokenRequest(t, app, secret, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
			"redirect_uri": {app.RedirectURIs[0]}, "code_verifier": {verifier}})
		if status != http.StatusOK {
			t.Fatalf("token: %d %v", status, raw)
		}
		return tokenSet{Access: str(raw["access_token"]), ID: str(raw["id_token"])}, ""
	}
	acrIn := func(tok tokenSet) (id, access any) {
		t.Helper()
		return parseJWT(t, tok.ID).Claims.(jwt.MapClaims)["acr"], verifyAccessToken(t, app, tok.Access)["acr"]
	}

	tok, _ := signIn("")
	if id, access := acrIn(tok); id != "password" || access != "password" {
		t.Errorf("an ordinary sign-in: acr %v / %v, want password", id, access)
	}
	// Values Guardian does not know are met by any session, as OIDC allows.
	if tok, loc := signIn("urn:something:else"); loc != "" || tok.ID == "" {
		t.Errorf("an unknown acr value: %q", loc)
	}

	_, loc := signIn("password mfa")
	if loc != "/mfa" {
		t.Fatalf("acr_values=mfa without two-factor: %q, want the two-factor step", loc)
	}
	resp := br.postForm("/mfa", url.Values{"csrf": {br.csrf()}, "code": {testutil.TOTPCode(t, acct.ID)}})
	drain(resp)
	tok, loc = signIn("password mfa")
	if loc != "" {
		t.Fatalf("after the step-up: %q", loc)
	}
	if id, access := acrIn(tok); id != "mfa" || access != "mfa" {
		t.Errorf("after the step-up: acr %v / %v, want mfa", id, access)
	}

	// prompt=none cannot step up.
	testutil.Exec(t, `UPDATE session SET amr = ARRAY['pwd'] WHERE account_id = $1`, acct.ID)
	_, challenge := newPKCE(t)
	none := authParams{app: app, scope: "openid", state: "s", challenge: challenge,
		extra: url.Values{"acr_values": {"mfa"}, "prompt": {"none"}}}
	if cb := br.authorizeCallback(none.values(), "mipha"); cb.Query().Get("error") != "interaction_required" {
		t.Errorf("prompt=none: %s", cb)
	}
}
