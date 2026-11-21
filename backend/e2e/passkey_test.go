package e2e

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// Security keys and passkeys (V7, V8, U11, U16), driven by a software authenticator that answers the
// options exactly as the pages and the API hand them to the browser.

var (
	optionsRe = regexp.MustCompile(`data-options="([^"]+)"`)
)

// pageParts returns what a sign-in page carries for its script: the CSRF token, the WebAuthn options and
// (when there is one) the ceremony token.
func pageParts(t *testing.T, body string) (csrf, options, token string) {
	t.Helper()
	m := optionsRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no WebAuthn options on the page: %.300s", body)
	}
	if c := csrfRe.FindStringSubmatch(body); c != nil {
		csrf = c[1]
	}
	if k := tokenRe.FindStringSubmatch(body); k != nil {
		token = html.UnescapeString(k[1])
	}
	return csrf, html.UnescapeString(m[1]), token
}

// addKey registers a key through the API and returns the recovery codes, if this was the first method.
func addKey(t *testing.T, br *browser, key *testutil.Authenticator, name string) []string {
	t.Helper()
	begun := br.call("POST", "/api/v1/me/mfa/keys", nil, 200)
	cred, err := key.Create(mustJSON(t, begun["options"]))
	if err != nil {
		t.Fatal(err)
	}
	resp := br.sendJSON("POST", "/api/v1/me/mfa/keys/finish", map[string]any{
		"setup_token": begun["setup_token"], "credential": rawJSON(cred), "name": name})
	m := decodeMap(t, resp)
	switch resp.StatusCode {
	case http.StatusCreated:
		return nil
	case http.StatusOK:
		var codes []string
		for _, c := range m["recovery_codes"].([]any) {
			codes = append(codes, c.(string))
		}
		br.call("POST", "/api/v1/me/mfa/finish", map[string]any{"setup_token": m["setup_token"], "recovery_code": codes[2]}, 204)
		return codes
	}
	t.Fatalf("adding a key: %d %v", resp.StatusCode, m)
	return nil
}

func passkeySignIn(t *testing.T, br *browser, key *testutil.Authenticator) *http.Response {
	t.Helper()
	csrf, options, _ := pageParts(t, readBody(t, br.get("/login")))
	cred, err := key.Get([]byte(options))
	if err != nil {
		t.Fatal(err)
	}
	return br.postForm("/login/passkey", url.Values{"csrf": {csrf}, "credential": {string(cred)}})
}

func sessionAMR(t *testing.T, accountID string) string {
	t.Helper()
	var amr string
	if err := db.GetDatabaseConnection().QueryRow(
		`SELECT array_to_string(amr, ',') FROM session WHERE account_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`,
		accountID).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	return amr
}

// Covers: V8, U11
func TestE2EPasskeySignsInWithoutAPassword(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "mipha")
	key := testutil.NewAuthenticator(testIssuer)
	key.BackupEligible, key.FrozenCounter = true, true // a synced passkey
	br := newBrowser(t)
	br.mustLogin("mipha")
	codes := addKey(t, br, key, "Phone")
	if len(codes) != 10 {
		t.Fatalf("the first key brings recovery codes: %v", codes)
	}
	me := br.call("GET", "/api/v1/me", nil, 200)
	mfa := me["mfa"].(map[string]any)
	keys := mfa["security_keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["name"] != "Phone" || keys[0].(map[string]any)["passkey"] != true || mfa["recovery_codes_left"] != 10.0 {
		t.Fatalf("after adding a passkey: %v", mfa)
	}

	// A new browser signs in with the passkey alone, and the session counts as two-factor.
	other := newBrowser(t)
	resp := passkeySignIn(t, other, key)
	wantStatus(t, resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("after a passkey sign-in: %q", loc)
	}
	drain(resp)
	if amr := sessionAMR(t, acct.ID); amr != "hwk,user" {
		t.Errorf("a passkey session's amr = %q", amr)
	}
	other.call("GET", "/api/v1/me", nil, 200)

	// The same answer cannot be sent twice, even with the challenge's cookie put back.
	third := newBrowser(t)
	csrf, options, _ := pageParts(t, readBody(t, third.get("/login")))
	sealed := third.cookie("guardian_passkey")
	cred, _ := key.Get([]byte(options))
	first := third.postForm("/login/passkey", url.Values{"csrf": {csrf}, "credential": {string(cred)}})
	wantStatus(t, first, http.StatusSeeOther)
	drain(first)
	replay := newBrowser(t)
	replayCSRF, _, _ := pageParts(t, readBody(t, replay.get("/login")))
	replay.setCookie("guardian_passkey", sealed)
	again := replay.postForm("/login/passkey", url.Values{"csrf": {replayCSRF}, "credential": {string(cred)}})
	if body := readBody(t, again); again.StatusCode != http.StatusBadRequest || !strings.Contains(body, "took too long") {
		t.Errorf("a replayed passkey answer: %d", again.StatusCode)
	}

	// A disabled account cannot sign in with its passkey.
	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, acct.ID)
	refused := passkeySignIn(t, newBrowser(t), key)
	if body := readBody(t, refused); refused.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "isn&#39;t registered here") {
		t.Errorf("a disabled account's passkey: %d", refused.StatusCode)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'login.failure' AND metadata->>'method' = 'passkey'`); n != 1 {
		t.Errorf("%d failed passkey sign-ins audited", n)
	}
}

// Covers: V8, U11
func TestE2EPasskeyOfARemovedKeyIsRefused(t *testing.T) {
	newTestEnv(t)
	testutil.CreateAccount(t, "revali")
	key := testutil.NewAuthenticator(testIssuer)
	br := newBrowser(t)
	br.mustLogin("revali")
	addKey(t, br, key, "Key")
	id := br.call("GET", "/api/v1/me", nil, 200)["mfa"].(map[string]any)["security_keys"].([]any)[0].(map[string]any)["id"]
	br.call("DELETE", "/api/v1/me/mfa/keys/"+str(id), nil, 204)
	resp := passkeySignIn(t, newBrowser(t), key)
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)
	if left := br.call("GET", "/api/v1/me", nil, 200)["mfa"].(map[string]any)["recovery_codes_left"]; left != 0.0 {
		t.Errorf("the recovery codes go with the last method: %v left", left)
	}
}

// Covers: V7
func TestE2ESecurityKeyIsASecondFactor(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "urbosa")
	key := testutil.NewAuthenticator(testIssuer)
	br := newBrowser(t)
	br.mustLogin("urbosa")
	addKey(t, br, key, "YubiKey")

	// With only a key, the password leads straight to the key (S14).
	other := newBrowser(t)
	resp := other.login("urbosa", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	page := readBody(t, other.get("/mfa"))
	if !strings.Contains(page, `data-webauthn="get"`) || strings.Contains(page, "Use the authenticator app") || !strings.Contains(page, "Use a recovery code") {
		t.Fatalf("S14 for an account with only a key: %.400s", page)
	}
	csrf, options, token := pageParts(t, page)
	cred, _ := key.Get([]byte(options))
	// A tampered signature is refused and counted.
	bad := strings.Replace(string(cred), `"signature":"M`, `"signature":"N`, 1)
	refused := other.postForm("/mfa", url.Values{"csrf": {csrf}, "method": {"key"}, "token": {token}, "credential": {bad}})
	wantStatus(t, refused, http.StatusUnauthorized)
	drain(refused)

	csrf, options, token = pageParts(t, readBody(t, other.get("/mfa")))
	cred, _ = key.Get([]byte(options))
	ok := other.postForm("/mfa", url.Values{"csrf": {csrf}, "method": {"key"}, "token": {token}, "credential": {string(cred)}})
	wantStatus(t, ok, http.StatusSeeOther)
	drain(ok)
	if amr := sessionAMR(t, acct.ID); amr != "pwd,hwk" {
		t.Errorf("password and key amr = %q", amr)
	}

	// A key whose counter went backwards may have been copied: refused.
	third := newBrowser(t)
	drain(third.login("urbosa", testutil.DefaultPassword, ""))
	key.SetCounter(0)
	csrf, options, token = pageParts(t, readBody(t, third.get("/mfa")))
	cred, _ = key.Get([]byte(options))
	cloned := third.postForm("/mfa", url.Values{"csrf": {csrf}, "method": {"key"}, "token": {token}, "credential": {string(cred)}})
	wantStatus(t, cloned, http.StatusUnauthorized)
	drain(cloned)
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'mfa.failure' AND metadata->>'method' = 'security_key'`); n != 2 {
		t.Errorf("%d key failures audited, want the tampered and the copied one", n)
	}
}

// Covers: U11, U16
func TestE2EKeysConfirmItsYouAndFollowTheRemovalRules(t *testing.T) {
	newTestEnv(t)
	admin := testutil.AdminAccount(t, "zelda")
	key := testutil.NewAuthenticator(testIssuer)
	br := newBrowser(t)
	br.mustLogin("zelda") // with the authenticator app testutil sets up
	if codes := addKey(t, br, key, "Sheikah Slate"); codes != nil {
		t.Error("a second method must not replace the recovery codes")
	}
	keyID := str(br.call("GET", "/api/v1/me", nil, 200)["mfa"].(map[string]any)["security_keys"].([]any)[0].(map[string]any)["id"])

	// Confirm it's you with the key.
	testutil.Exec(t, `UPDATE session SET auth_time = now() - interval '10 minutes' WHERE account_id = $1`, admin.ID)
	br.call("PATCH", "/api/v1/me/mfa/keys/"+keyID, map[string]any{"name": "Slate"}, 200)
	br.call("DELETE", "/api/v1/me/mfa/totp", nil, 403) // reauth_required
	begun := br.call("POST", "/api/v1/me/reauth/key", nil, 200)
	cred, _ := key.Get(mustJSON(t, begun["options"]))
	br.call("POST", "/api/v1/me/reauth", map[string]any{"key": map[string]any{"token": begun["token"], "credential": rawJSON(cred)}}, 200)

	// An administrator may drop the app while the key remains, but never the last method.
	br.call("DELETE", "/api/v1/me/mfa/totp", nil, 204)
	if got := br.call("DELETE", "/api/v1/me/mfa/keys/"+keyID, nil, 409); got["error"] != "mfa_required" {
		t.Errorf("removing an administrator's last method: %v", got)
	}
	mfa := br.call("GET", "/api/v1/me", nil, 200)["mfa"].(map[string]any)
	if mfa["totp"] != false || len(mfa["security_keys"].([]any)) != 1 || mfa["security_keys"].([]any)[0].(map[string]any)["name"] != "Slate" {
		t.Errorf("after removing the app: %v", mfa)
	}
	br.call("PATCH", "/api/v1/me/mfa/keys/"+keyID, map[string]any{"name": strings.Repeat("x", 65)}, 400)
	br.call("DELETE", "/api/v1/me/mfa/keys/00000000-0000-0000-0000-000000000000", nil, 404)
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type IN ('mfa.key_added', 'mfa.key_renamed', 'mfa.totp_removed', 'reauth.success')`); n != 4 {
		t.Errorf("%d key events audited", n)
	}
}

// Covers: U4, A24
func TestE2ERequiredSetupWithASecurityKey(t *testing.T) {
	newTestEnv(t)
	admin := testutil.AdminAccount(t, "impa")
	testutil.Exec(t, `DELETE FROM account_mfa WHERE account_id = $1`, admin.ID)
	key := testutil.NewAuthenticator(testIssuer)
	br := newBrowser(t)
	resp := br.login("impa", testutil.DefaultPassword, "")
	if resp.Header.Get("Location") != "/mfa/setup" {
		t.Fatalf("an administrator without two-factor: %q", resp.Header.Get("Location"))
	}
	drain(resp)
	page := readBody(t, br.get("/mfa/setup?method=key"))
	csrf, options, token := pageParts(t, page)
	cred, err := key.Create([]byte(options))
	if err != nil {
		t.Fatal(err)
	}
	codesPage := br.postForm("/mfa/setup", url.Values{"csrf": {csrf}, "step": {"key"}, "token": {token}, "credential": {string(cred)}, "name": {"Desk key"}})
	body := readBody(t, codesPage)
	codes := codesRe.FindAllStringSubmatch(body, -1)
	if codesPage.StatusCode != http.StatusOK || len(codes) != 10 {
		t.Fatalf("the recovery codes after the key: %d %.300s", codesPage.StatusCode, body)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM account_mfa WHERE account_id = $1`, admin.ID); n != 0 {
		t.Error("nothing may be saved before a recovery code is typed back")
	}
	csrf = csrfRe.FindStringSubmatch(body)[1]
	token = html.UnescapeString(tokenRe.FindStringSubmatch(body)[1])
	done := br.postForm("/mfa/setup", url.Values{"csrf": {csrf}, "step": {"codes"}, "token": {token}, "code": {codes[4][1]}})
	wantStatus(t, done, http.StatusSeeOther)
	drain(done)
	if amr := sessionAMR(t, admin.ID); amr != "pwd,hwk" {
		t.Errorf("after setting up a key: amr %q", amr)
	}
	br.call("GET", "/api/v1/overview", nil, 200) // an administrator's rights need two-factor: the key counts
	if n := testutil.Count(t, `SELECT count(*) FROM account_mfa WHERE account_id = $1 AND type = 'webauthn' AND name = 'Desk key'`, admin.ID); n != 1 {
		t.Error("the key was not saved")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rawJSON(b []byte) json.RawMessage { return json.RawMessage(b) }
