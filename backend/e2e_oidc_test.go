package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"guardian/auth"
	db "guardian/database"
	"guardian/internal/testutil"
)

func TestE2ELoginIssuesOpaqueAccessTokenAndVerifiableIDToken(t *testing.T) {
	testutil.Reset(t)
	user := testutil.CreateAccount(t, "alice")
	if _, err := db.UpdateProfile(db.Account{ID: user.ID, DisplayName: "Alice A", Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	b := newBrowser(t)
	tok := b.signIn(app, secret, "alice", "openid profile email offline_access")

	// the access token is an opaque random string, not a JWT, and only its hash is stored
	if len(tok.Access) != 43 || strings.Contains(tok.Access, ".") {
		t.Errorf("access token should be 43 opaque characters, got %q", tok.Access)
	}
	if testutil.Count(t, `SELECT count(*) FROM access_token WHERE token_hash = $1`, tok.Access) != 0 ||
		testutil.Count(t, `SELECT count(*) FROM access_token WHERE token_hash = $1`, auth.HashToken(tok.Access)) != 1 {
		t.Error("access token must be stored hashed only")
	}
	if testutil.Count(t, `SELECT count(*) FROM refresh_token WHERE token_hash = $1`, tok.Refresh) != 0 {
		t.Error("refresh token stored in plaintext")
	}
	if tok.Raw["token_type"] != "Bearer" || tok.Raw["expires_in"] != float64(900) || tok.Raw["scope"] != "openid profile email offline_access" {
		t.Errorf("token response = %v", tok.Raw)
	}

	// the ID token verifies with Guardian's key and carries the right identity claims
	idt := parseJWT(t, tok.ID, jwt.WithIssuer(testIssuer), jwt.WithAudience(app.ClientID))
	claims := idt.Claims.(jwt.MapClaims)
	if claims["sub"] != user.ID || claims["nonce"] != "n-1" || claims["email"] != "alice@example.com" ||
		claims["email_verified"] != false || claims["name"] != "Alice A" || claims["preferred_username"] != "alice" {
		t.Errorf("ID token claims = %v", claims)
	}
	if str(claims["sid"]) == "" {
		t.Error("ID token needs a sid for back-channel logout")
	}
	if authTime, _ := claims["auth_time"].(float64); time.Since(time.Unix(int64(authTime), 0)) > time.Minute {
		t.Errorf("auth_time = %v", claims["auth_time"])
	}
	if _, leaked := claims["permissions"]; leaked {
		t.Error("ID tokens must not carry permissions")
	}

	// userinfo honours the granted scopes and the response is not cacheable
	status, info := userinfoStatus(t, tok.Access)
	if status != 200 || info["sub"] != user.ID || info["email"] != "alice@example.com" || info["preferred_username"] != "alice" {
		t.Errorf("userinfo = %d %v", status, info)
	}
	narrow := b.signIn(app, secret, "alice", "openid")
	if status, only := userinfoStatus(t, narrow.Access); status != 200 || len(only) != 1 || only["sub"] != user.ID {
		t.Errorf("a token with only the openid scope must reveal only sub, got %d %v", status, only)
	}
	if status, _ := userinfoStatus(t, "garbage"); status != http.StatusUnauthorized {
		t.Errorf("userinfo with a bogus token = %d", status)
	}

	// the session works against the JSON API
	resp := b.get("/api/account/me")
	wantStatus(t, resp, 200)
	if me := decodeMap(t, resp); me["username"] != "alice" {
		t.Errorf("me = %v", me)
	}
}

func TestE2ESessionCookieIsHardenedAndStoredHashed(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	b := newBrowser(t)
	resp := b.login("alice", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusSeeOther)
	if resp.Header.Get("Location") != "/login" {
		t.Errorf("login without return_to goes to %q", resp.Header.Get("Location"))
	}
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "guardian_session" {
			session = c
		}
	}
	drain(resp)
	if session == nil {
		t.Fatal("no session cookie")
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Path != "/" || session.Value == "" {
		t.Errorf("cookie not hardened: %+v", session)
	}
	if session.MaxAge < 3500 || session.MaxAge > 3600 {
		t.Errorf("cookie lifetime = %ds, want about SESSION_TTL (1h)", session.MaxAge)
	}
	if testutil.Count(t, `SELECT count(*) FROM session WHERE session_hash = $1`, session.Value) != 0 {
		t.Error("session cookie stored in plaintext")
	}
	if testutil.Count(t, `SELECT count(*) FROM session WHERE session_hash = $1`, auth.HashToken(session.Value)) != 1 {
		t.Error("hashed session not stored")
	}

	// logging in again never reuses the session id (no session fixation)
	first := b.cookie("guardian_session")
	b.mustLogin("alice")
	if second := b.cookie("guardian_session"); second == first || second == "" {
		t.Error("a new login must issue a fresh session cookie")
	}
}

func TestE2ESingleSignOnAndLogoutEverywhere(t *testing.T) {
	testutil.Reset(t)
	user := testutil.CreateAccount(t, "alice")
	endpointA, tokensA := startReceiver(t)
	endpointB, tokensB := startReceiver(t)
	appA, secA := testutil.CreateApp(t, "appa", testutil.AppOptions{FirstParty: true, BackchannelURI: endpointA})
	appB, secB := testutil.CreateApp(t, "appb", testutil.AppOptions{FirstParty: true, BackchannelURI: endpointB})
	b := newBrowser(t)

	a := b.signIn(appA, secA, "alice", "openid offline_access")
	bb := b.signIn(appB, secB, "alice", "openid offline_access")
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'login.success'`); n != 1 {
		t.Fatalf("%d password logins happened, want 1 (the second app must reuse the SSO session)", n)
	}

	infoA := mustActive(t, appA, secA, a.Access)
	infoB := mustActive(t, appB, secB, bb.Access)
	if infoA["sid"] == nil || infoA["sid"] != infoB["sid"] {
		t.Fatalf("both apps must hang off the same SSO session: %v vs %v", infoA["sid"], infoB["sid"])
	}

	resp := b.logout()
	wantStatus(t, resp, 200)
	drain(resp)

	// everything dies at once
	mustInactive(t, appA, secA, a.Access)
	mustInactive(t, appB, secB, bb.Access)
	for _, tk := range []string{a.Access, bb.Access} {
		if status, _ := userinfoStatus(t, tk); status != http.StatusUnauthorized {
			t.Errorf("userinfo after logout = %d", status)
		}
	}
	if status, m := refreshRequest(t, appA, secA, a.Refresh); status != 400 || m["error"] != "invalid_grant" {
		t.Errorf("refresh token survived logout: %d %v", status, m)
	}
	if status, m := refreshRequest(t, appB, secB, bb.Refresh); status != 400 || m["error"] != "invalid_grant" {
		t.Errorf("refresh token survived logout: %d %v", status, m)
	}
	r2 := b.get("/api/account/me")
	wantStatus(t, r2, http.StatusUnauthorized)
	drain(r2)

	// both apps are told, with a correct signed logout token
	for _, c := range []struct {
		app  db.App
		ch   <-chan string
		info map[string]any
	}{{appA, tokensA, infoA}, {appB, tokensB, infoB}} {
		raw := waitToken(t, c.ch)
		lt := parseJWT(t, raw, jwt.WithIssuer(testIssuer), jwt.WithAudience(c.app.ClientID))
		claims := lt.Claims.(jwt.MapClaims)
		if lt.Header["typ"] != "logout+jwt" {
			t.Errorf("typ = %v", lt.Header["typ"])
		}
		if claims["sub"] != user.ID || claims["sid"] != c.info["sid"] || str(claims["jti"]) == "" {
			t.Errorf("logout token claims = %v", claims)
		}
		if _, has := claims["nonce"]; has {
			t.Error("a logout token must not contain a nonce")
		}
		events, _ := claims["events"].(map[string]any)
		if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
			t.Errorf("events = %v", claims["events"])
		}
		if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat > 180 {
			t.Errorf("logout token lives %vs, should be short", exp-iat)
		}
	}

	// no SSO session left: the next authorization asks for a login again
	resp = b.get("/authorize?" + authParams{app: appA, challenge: strings.Repeat("a", 43)}.values().Encode())
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?") {
		t.Errorf("after logout /authorize redirected to %q", loc)
	}
	drain(resp)
}

func TestE2EAuthorizationCodeAndPKCE(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	other, otherSecret := testutil.CreateApp(t, "other", testutil.AppOptions{FirstParty: true})
	b := newBrowser(t)

	newCode := func() (code, verifier string) {
		v, ch := newPKCE(t)
		cb := b.authorizeCallback(authParams{app: app, state: "s", challenge: ch}.values(), "alice")
		return cb.Query().Get("code"), v
	}
	exchange := func(a db.App, sec, code, verifier, redirect string) (int, map[string]any) {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
		if verifier != "" {
			form.Set("code_verifier", verifier)
		}
		return tokenRequest(t, a, sec, form)
	}
	redirect := app.RedirectURIs[0]

	// wrong verifier: rejected, and the code is burned
	code, verifier := newCode()
	if status, m := exchange(app, secret, code, verifier+"x", redirect); status != 400 || m["error"] != "invalid_grant" {
		t.Errorf("wrong verifier: %d %v", status, m)
	}
	if status, _ := exchange(app, secret, code, verifier, redirect); status != 400 {
		t.Error("a code must be unusable after a failed attempt")
	}

	// missing verifier
	code, _ = newCode()
	if status, _ := exchange(app, secret, code, "", redirect); status != 400 {
		t.Error("exchange without the PKCE verifier succeeded")
	}

	// success once, never twice
	code, verifier = newCode()
	if status, m := exchange(app, secret, code, verifier, redirect); status != 200 || m["access_token"] == nil {
		t.Fatalf("valid exchange: %d %v", status, m)
	}
	if status, m := exchange(app, secret, code, verifier, redirect); status != 400 || m["error"] != "invalid_grant" {
		t.Errorf("code replay: %d %v", status, m)
	}

	// bound to the redirect_uri and to the client
	code, verifier = newCode()
	if status, _ := exchange(app, secret, code, verifier, "https://billing.test/other"); status != 400 {
		t.Error("redirect_uri mismatch accepted")
	}
	code, verifier = newCode()
	if status, _ := exchange(other, otherSecret, code, verifier, redirect); status != 400 {
		t.Error("another client redeemed the code")
	}

	// unsupported grants
	for _, g := range []string{"password", "client_credentials", "implicit", ""} {
		if status, m := tokenRequest(t, app, secret, url.Values{"grant_type": {g}, "username": {"alice"}, "password": {testutil.DefaultPassword}}); status != 400 || m["error"] != "unsupported_grant_type" {
			t.Errorf("grant %q: %d %v", g, status, m)
		}
	}
}

func TestE2ETokenEndpointResponsesAreNotCacheable(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	b := newBrowser(t)
	verifier, ch := newPKCE(t)
	cb := b.authorizeCallback(authParams{app: app, state: "s", challenge: ch}.values(), "alice")

	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {app.RedirectURIs[0]}, "code_verifier": {verifier}}
	req, _ := http.NewRequest("POST", pubSrv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resp, 200)
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
		t.Errorf("token responses must not be cached: %v", resp.Header)
	}
	drain(resp)
}

func TestE2EPublicClientsUsePKCEWithoutASecret(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	spa, _ := testutil.CreateApp(t, "spa", testutil.AppOptions{Public: true, FirstParty: true})
	b := newBrowser(t)

	tok := b.signIn(spa, "", "alice", "openid profile")
	if tok.Access == "" || tok.Raw["refresh_token"] != nil {
		t.Errorf("public client tokens: %v", tok.Raw)
	}
	// without a code_challenge a public client is refused at /authorize
	cb := b.authorizeCallback(authParams{app: spa, state: "s"}.values(), "alice")
	if cb.Query().Get("error") != "invalid_request" {
		t.Errorf("missing PKCE: %s", cb)
	}
	// and cannot call introspection (no secret to authenticate with)
	if status, _ := introspectToken(t, spa, "", tok.Access); status != http.StatusUnauthorized {
		t.Errorf("public client introspection = %d, want 401", status)
	}
}

func TestE2ERefreshTokenRotationAndReuseDetection(t *testing.T) {
	testutil.Reset(t)
	user := testutil.CreateAccount(t, "alice")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	other, otherSecret := testutil.CreateApp(t, "other", testutil.AppOptions{FirstParty: true})
	b := newBrowser(t)

	noOffline := b.signIn(app, secret, "alice", "openid")
	if noOffline.Refresh != "" {
		t.Error("a refresh token must only be issued with the offline_access scope")
	}

	tok := b.signIn(app, secret, "alice", "openid offline_access")
	if tok.Refresh == "" {
		t.Fatal("no refresh token despite offline_access")
	}
	if status, _ := refreshRequest(t, other, otherSecret, tok.Refresh); status != 400 {
		t.Error("another client used the refresh token")
	}

	status, second := refreshRequest(t, app, secret, tok.Refresh)
	if status != 200 || str(second["access_token"]) == "" || str(second["refresh_token"]) == "" {
		t.Fatalf("refresh: %d %v", status, second)
	}
	if second["access_token"] == tok.Access || second["refresh_token"] == tok.Refresh {
		t.Error("rotation must issue new tokens")
	}
	if second["id_token"] != nil {
		t.Error("refresh responses carry no ID token")
	}
	mustActive(t, app, secret, str(second["access_token"]))

	// replaying the old refresh token is a theft signal: the whole family dies
	if status, m := refreshRequest(t, app, secret, tok.Refresh); status != 400 || m["error"] != "invalid_grant" {
		t.Errorf("replay: %d %v", status, m)
	}
	if status, _ := refreshRequest(t, app, secret, str(second["refresh_token"])); status != 400 {
		t.Error("the newest refresh token must be revoked after a replay was detected")
	}

	// a disabled account cannot refresh either
	fresh := b.signIn(app, secret, "alice", "openid offline_access")
	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, user.ID)
	if status, m := refreshRequest(t, app, secret, fresh.Refresh); status != 400 || m["error"] != "invalid_grant" {
		t.Errorf("disabled account refreshed: %d %v", status, m)
	}
}

func TestE2EAuthorizeRequestValidation(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	_, challenge := newPKCE(t)
	b := newBrowser(t)
	good := func() authParams { return authParams{app: app, state: "st-9", challenge: challenge} }

	// problems with client_id / redirect_uri are shown to the user and NEVER redirected to
	unredirectable := map[string]url.Values{
		"unknown client":             func() url.Values { v := good().values(); v.Set("client_id", "11111111-1111-1111-1111-111111111111"); return v }(),
		"malformed client":           func() url.Values { v := good().values(); v.Set("client_id", "nope"); return v }(),
		"unregistered redirect":      authParams{app: app, state: "s", challenge: challenge, redirect: "https://evil.example/cb"}.values(),
		"redirect with extra path":   authParams{app: app, state: "s", challenge: challenge, redirect: "https://billing.test/callback/x"}.values(),
		"redirect with query":        authParams{app: app, state: "s", challenge: challenge, redirect: "https://billing.test/callback?x=1"}.values(),
		"redirect with other case":   authParams{app: app, state: "s", challenge: challenge, redirect: "https://BILLING.test/callback"}.values(),
	}
	for name, v := range unredirectable {
		resp := b.get("/authorize?" + v.Encode())
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d, Location %q (must be a 400 page, never a redirect)", name, resp.StatusCode, resp.Header.Get("Location"))
		}
		drain(resp)
	}

	// everything else is reported to the client's redirect_uri, with state and iss
	redirected := map[string]struct {
		mutate func(v url.Values)
		want   string
	}{
		"implicit flow":         {func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
		"missing openid scope":  {func(v url.Values) { v.Set("scope", "profile") }, "invalid_scope"},
		"scope the app lacks":   {func(v url.Values) { v.Set("scope", "openid phone") }, "invalid_scope"},
		"no PKCE challenge":     {func(v url.Values) { v.Del("code_challenge"); v.Del("code_challenge_method") }, "invalid_request"},
		"plain PKCE":            {func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		"short challenge":       {func(v url.Values) { v.Set("code_challenge", "short") }, "invalid_request"},
		"negative max_age":      {func(v url.Values) { v.Set("max_age", "-1") }, "invalid_request"},
		"non-numeric max_age":   {func(v url.Values) { v.Set("max_age", "abc") }, "invalid_request"},
		"prompt none, no login": {func(v url.Values) { v.Set("prompt", "none") }, "login_required"},
	}
	for name, c := range redirected {
		v := good().values()
		c.mutate(v)
		resp := b.get("/authorize?" + v.Encode())
		loc := resp.Header.Get("Location")
		drain(resp)
		u, err := url.Parse(loc)
		if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc, "https://billing.test/callback?") {
			t.Errorf("%s: status %d, Location %q", name, resp.StatusCode, loc)
			continue
		}
		q := u.Query()
		if q.Get("error") != c.want || q.Get("state") != "st-9" || q.Get("iss") != testIssuer || q.Get("code") != "" {
			t.Errorf("%s: callback query = %v, want error=%s with state and iss", name, q, c.want)
		}
	}
}

func TestE2EPromptAndMaxAgeForceReauthentication(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	_, challenge := newPKCE(t)
	b := newBrowser(t)
	b.mustLogin("alice")

	ok := b.get("/authorize?" + authParams{app: app, state: "s", challenge: challenge, extra: url.Values{"prompt": {"none"}}}.values().Encode())
	if !strings.Contains(ok.Header.Get("Location"), "code=") {
		t.Errorf("prompt=none with a session should issue a code, got %q", ok.Header.Get("Location"))
	}
	drain(ok)

	for name, extra := range map[string]url.Values{"prompt=login": {"prompt": {"login"}}, "max_age=0": {"max_age": {"0"}}} {
		resp := b.get("/authorize?" + authParams{app: app, state: "s", challenge: challenge, extra: extra}.values().Encode())
		loc := resp.Header.Get("Location")
		drain(resp)
		if !strings.HasPrefix(loc, "/login?") {
			t.Fatalf("%s: expected a login redirect, got %q", name, loc)
		}
		u, _ := url.Parse(loc)
		returnTo := u.Query().Get("return_to")
		if strings.Contains(returnTo, "prompt=") || strings.Contains(returnTo, "max_age=") {
			t.Errorf("%s: return_to %q would loop forever", name, returnTo)
		}
		lr := b.login("alice", testutil.DefaultPassword, returnTo)
		wantStatus(t, lr, http.StatusSeeOther)
		drain(lr)
		final := b.get(returnTo)
		if !strings.Contains(final.Header.Get("Location"), "code=") {
			t.Errorf("%s: no code after re-authentication: %q", name, final.Header.Get("Location"))
		}
		drain(final)
	}
}

func TestE2EConsentFlowForThirdPartyApps(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, secret := testutil.CreateApp(t, "thirdparty", testutil.AppOptions{
		Scopes: []string{"openid", "profile", "email", "phone"}})
	b := newBrowser(t)
	b.mustLogin("alice")
	_, ch := newPKCE(t)
	query := func(scope string, extra url.Values) string {
		return "/authorize?" + authParams{app: app, scope: scope, state: "s", challenge: ch, extra: extra}.values().Encode()
	}

	// first request: a consent page that names the app and the data requested
	resp := b.get(query("openid email", nil))
	wantStatus(t, resp, 200)
	page := readBody(t, resp)
	for _, want := range []string{"App thirdparty", "Your email address", "Verify your identity"} {
		if !strings.Contains(page, want) {
			t.Errorf("consent page lacks %q", want)
		}
	}
	csrf := csrfRe.FindStringSubmatch(page)[1]
	req := html.UnescapeString(reqRe.FindStringSubmatch(page)[1])

	// consent forms are CSRF-protected
	bad := b.postForm("/consent", url.Values{"req": {req}, "decision": {"allow"}})
	wantStatus(t, bad, http.StatusForbidden)
	drain(bad)

	// deny: the client hears access_denied
	deny := b.postForm("/consent", url.Values{"csrf": {csrf}, "req": {req}, "decision": {"deny"}})
	loc := deny.Header.Get("Location")
	drain(deny)
	if !strings.Contains(loc, "error=access_denied") || !strings.Contains(loc, "state=s") {
		t.Errorf("deny redirected to %q", loc)
	}
	if testutil.Count(t, `SELECT count(*) FROM account_consent`) != 0 {
		t.Error("a denial must not store consent")
	}

	// allow: stored, then the flow continues and yields a code
	allow := b.postForm("/consent", url.Values{"csrf": {csrf}, "req": {req}, "decision": {"allow"}})
	wantStatus(t, allow, http.StatusSeeOther)
	next := allow.Header.Get("Location")
	drain(allow)
	if !strings.HasPrefix(next, "/authorize?") {
		t.Fatalf("after consent: %q", next)
	}
	done := b.get(next)
	if !strings.Contains(done.Header.Get("Location"), "code=") {
		t.Errorf("no code after consent: %q", done.Header.Get("Location"))
	}
	drain(done)

	// the same scopes are not asked again; more scopes are; prompt=consent asks again
	again := b.get(query("openid email", nil))
	if !strings.Contains(again.Header.Get("Location"), "code=") {
		t.Errorf("repeat request should not prompt, status %d", again.StatusCode)
	}
	drain(again)
	more := b.get(query("openid email phone", nil))
	wantStatus(t, more, 200)
	drain(more)
	forced := b.get(query("openid email", url.Values{"prompt": {"consent"}}))
	wantStatus(t, forced, 200)
	drain(forced)
	silent := b.get(query("openid email phone", url.Values{"prompt": {"none"}}))
	if !strings.Contains(silent.Header.Get("Location"), "error=consent_required") {
		t.Errorf("prompt=none without consent: %q", silent.Header.Get("Location"))
	}
	drain(silent)
	_ = secret
}

func TestE2ERPInitiatedLogout(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	testutil.CreateAccount(t, "mallory")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	logoutURL := func(hint, redirect, state, clientID string) string {
		v := url.Values{}
		for k, val := range map[string]string{"id_token_hint": hint, "post_logout_redirect_uri": redirect, "state": state, "client_id": clientID} {
			if val != "" {
				v.Set(k, val)
			}
		}
		return "/logout?" + v.Encode()
	}
	loggedIn := func(b *browser) bool {
		resp := b.get("/api/account/me")
		defer drain(resp)
		return resp.StatusCode == 200
	}

	// a valid hint for this user logs out immediately and redirects to the registered URI with state
	b := newBrowser(t)
	tok := b.signIn(app, secret, "alice", "openid")
	resp := b.get(logoutURL(tok.ID, "https://billing.test/", "xyz", ""))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://billing.test/?state=xyz" {
		t.Errorf("status %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	drain(resp)
	if loggedIn(b) {
		t.Error("still logged in after RP-initiated logout")
	}

	// an unregistered redirect URI is never followed (but the logout still happens)
	b = newBrowser(t)
	tok = b.signIn(app, secret, "alice", "openid")
	resp = b.get(logoutURL(tok.ID, "https://evil.example/", "s", ""))
	if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
		t.Errorf("unregistered redirect: status %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	drain(resp)
	if loggedIn(b) {
		t.Error("logout with a valid hint must still happen")
	}

	// a forged / foreign / access-token hint must not log anyone out without confirmation
	b = newBrowser(t)
	tok = b.signIn(app, secret, "alice", "openid")
	mb := newBrowser(t)
	mtok := mb.signIn(app, secret, "mallory", "openid")
	for name, hint := range map[string]string{"garbage": "not.a.jwt", "someone else's ID token": mtok.ID, "an access token": tok.Access} {
		resp := b.get(logoutURL(hint, "https://billing.test/", "s", ""))
		page := readBody(t, resp)
		if resp.StatusCode != 200 || !strings.Contains(page, `action="/logout"`) {
			t.Errorf("%s: expected a confirmation page, got %d", name, resp.StatusCode)
		}
		if !loggedIn(b) {
			t.Fatalf("%s: the session was ended without confirmation", name)
		}
	}

	// an ID token that has expired is still a valid hint
	testutil.Exec(t, `UPDATE app SET access_token_ttl_seconds = 1 WHERE id = $1`, app.ID)
	b = newBrowser(t)
	short := b.signIn(app, secret, "alice", "openid")
	time.Sleep(2200 * time.Millisecond)
	if _, err := jwt.Parse(short.ID, testKeys.Keyfunc, jwt.WithValidMethods([]string{"RS256"})); err == nil {
		t.Fatal("test setup: the ID token should have expired")
	}
	resp = b.get(logoutURL(short.ID, "https://billing.test/", "late", ""))
	if resp.Header.Get("Location") != "https://billing.test/?state=late" {
		t.Errorf("expired hint: Location %q", resp.Header.Get("Location"))
	}
	drain(resp)

	// without a session, a registered redirect given via client_id still works
	resp = newBrowser(t).get(logoutURL("", "https://billing.test/", "q", app.ClientID))
	if resp.Header.Get("Location") != "https://billing.test/?state=q" {
		t.Errorf("anonymous logout redirect: %q", resp.Header.Get("Location"))
	}
	drain(resp)
}

func TestE2EDiscoveryAndJWKS(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	b := newBrowser(t)

	resp := b.get("/.well-known/openid-configuration")
	wantStatus(t, resp, 200)
	disc := decodeMap(t, resp)
	if disc["issuer"] != testIssuer || disc["jwks_uri"] != testIssuer+"/jwks.json" || disc["introspection_endpoint"] != "http://internal.test/introspect" {
		t.Errorf("discovery = %v", disc)
	}

	resp = b.get("/jwks.json")
	wantStatus(t, resp, 200)
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("JWKS should be cacheable, Cache-Control = %q", cc)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(readBody(t, resp)), &jwks); err != nil || len(jwks.Keys) == 0 {
		t.Fatalf("JWKS: %v %v", jwks, err)
	}
	for _, k := range jwks.Keys {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, leaked := k[private]; leaked {
				t.Fatalf("JWKS leaks private key material (%s)", private)
			}
		}
	}

	// a relying party can verify an ID token using ONLY what is published
	tok := b.signIn(app, secret, "alice", "openid")
	idt, _, err := jwt.NewParser().ParseUnverified(tok.ID, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := idt.Header["kid"].(string)
	var pub *rsa.PublicKey
	for _, k := range jwks.Keys {
		if k["kid"] == kid {
			n, _ := base64.RawURLEncoding.DecodeString(k["n"])
			e, _ := base64.RawURLEncoding.DecodeString(k["e"])
			pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		}
	}
	if pub == nil {
		t.Fatalf("the ID token's kid %q is not published in the JWKS", kid)
	}
	if _, err := jwt.Parse(tok.ID, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"RS256"})); err != nil {
		t.Errorf("ID token does not verify against the published JWKS: %v", err)
	}
}
