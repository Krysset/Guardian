package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	"guardian/internal/config"
	"guardian/internal/httpx"
	"guardian/internal/mail"
	"guardian/internal/server"
	db "guardian/internal/store"
	"guardian/internal/testutil"
	"guardian/internal/web"
)

const testIssuer = "http://guardian.test"

var (
	pubSrv   *httptest.Server // the public listener (what browsers and apps reach through the ingress)
	intSrv   *httptest.Server // the internal listener (metrics, probes)
	testKeys *auth.Keys
	// testConfig is the configuration the servers run with.
	testConfig config.Config
	// mailbox catches every email; email is on in the end-to-end tests.
	mailbox = &mail.Capture{}
)

func TestMain(m *testing.M) {
	// Hundreds of passwords are hashed and checked here; at 64 MiB each the race detector makes that most of
	// the run. The hashing code is the same, and auth's own tests keep the real parameters.
	auth.UseCheapHashesInTests()
	captureLogs()
	if testutil.Enabled() {
		if err := testutil.Setup(); err != nil {
			fmt.Fprintln(os.Stderr, "test setup:", err)
			os.Exit(1)
		}
		os.Setenv("ISSUER_URL", testIssuer)
		os.Setenv("SESSION_IDLE_TIMEOUT", "30m")
		os.Setenv("SESSION_MAX_LIFETIME", "1h")
		os.Setenv("TRUSTED_PROXY_HOPS", "1") // requests without X-Forwarded-For still use their own address
		os.Setenv("KEY_ENCRYPTION_KEYS", "k1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
		testutil.DeleteSigningKeys()
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "configuration:", err)
			os.Exit(1)
		}
		if err := server.UseKeyring(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "keyring:", err)
			os.Exit(1)
		}
		k, err := auth.LoadKeys()
		if err != nil {
			fmt.Fprintln(os.Stderr, "load keys:", err)
			os.Exit(1)
		}
		testKeys, testConfig = k, cfg
		server.Configure(cfg, k)
		httpx.RegisterDBMetrics(cfg.SigningKeyLifetime)
		web.PoWMax = 200             // a quick puzzle: the tests solve hundreds
		httpx.StateMetricsMaxAge = 0 // every scrape reads the database
		mail.Configure(mailbox, mail.Site{Name: "Test Guardian", Host: "guardian.test"})
		pubSrv = httptest.NewServer(server.PublicRouter())
		intSrv = httptest.NewServer(server.InternalRouter())
	}
	code := m.Run()
	if code == 0 {
		code = checkLogs()
	}
	if pubSrv != nil {
		pubSrv.Close()
		intSrv.Close()
	}
	os.Exit(code)
}

// ---- HTTP plumbing ----------------------------------------------------------

func drain(resp *http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func decodeMap(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body := readBody(t, resp)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("response is not a JSON object (status %d): %.300s", resp.StatusCode, body)
	}
	return m
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d, want %d; body: %.300s", resp.StatusCode, want, b)
	}
}

func str(v any) string { s, _ := v.(string); return s }

// browser is an HTTP client with a cookie jar that does NOT follow redirects, so tests can inspect each hop.
type browser struct {
	t  *testing.T
	c  *http.Client
	ip string // sent as X-Forwarded-For when set: the servers trust one proxy hop, like behind an ingress
}

func newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, c: &http.Client{
		Jar:           jar,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) abs(p string) string {
	if strings.HasPrefix(p, "http") {
		return p
	}
	return pubSrv.URL + p
}

func (b *browser) do(req *http.Request) *http.Response {
	b.t.Helper()
	if b.ip != "" {
		req.Header.Set("X-Forwarded-For", b.ip)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	return resp
}

func (b *browser) get(p string) *http.Response {
	req, _ := http.NewRequest("GET", b.abs(p), nil)
	return b.do(req)
}

// postForm posts a form. Like a browser running the pages' script, it answers the proof-of-work puzzle of
// the sign-up, forgot-password and sign-in forms when the page carries one. pow=- sends no answer, as a
// browser without JavaScript.
func (b *browser) postForm(p string, v url.Values) *http.Response {
	if form := strings.SplitN(p, "?", 2)[0]; (form == "/signup" || form == "/forgot" || form == "/login") && v.Get("pow") == "" {
		if token, number, ok := b.solvePage(form); ok {
			v = cloneValues(v)
			v.Set("pow", token)
			v.Set("pow_number", number)
		}
	} else if v.Get("pow") == "-" {
		v = cloneValues(v)
		v.Del("pow")
	}
	req, _ := http.NewRequest("POST", b.abs(p), strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

var powRe = regexp.MustCompile(`name="pow" value="([^"]+)" data-pow-salt="([0-9a-f]+)" data-pow-challenge="([0-9a-f]+)" data-pow-max="(\d+)"`)

// solvePage opens the form's page and answers its puzzle, if it has one.
func (b *browser) solvePage(form string) (token, number string, ok bool) {
	b.t.Helper()
	m := powRe.FindStringSubmatch(readBody(b.t, b.get(form)))
	if m == nil {
		return "", "", false
	}
	return html.UnescapeString(m[1]), solvePoW(b.t, m[2], m[3], m[4]), true
}

// solvePoW finds the number whose SHA-256 with the salt is the challenge, as guardian.js does.
func solvePoW(t *testing.T, salt, challenge, max string) string {
	t.Helper()
	n, _ := strconv.Atoi(max)
	for i := 0; i <= n; i++ {
		sum := sha256.Sum256([]byte(salt + strconv.Itoa(i)))
		if hex.EncodeToString(sum[:]) == challenge {
			return strconv.Itoa(i)
		}
	}
	t.Fatalf("no answer to the puzzle %s", challenge)
	return ""
}

// signupBody adds the answer to a puzzle from GET /api/v1/signup/challenge to a sign-up request.
func (b *browser) signupBody(body map[string]any) map[string]any {
	b.t.Helper()
	p := decodeMap(b.t, b.get("/api/v1/signup/challenge"))
	out := map[string]any{"pow_token": p["token"], "pow_number": solvePoW(b.t, str(p["salt"]), str(p["challenge"]), fmt.Sprint(p["max"]))}
	for k, v := range body {
		out[k] = v
	}
	return out
}

// sendJSON sends a JSON request; headers are name/value pairs (e.g. "Origin", "https://evil.example").
func (b *browser) sendJSON(method, p string, body any, headers ...string) *http.Response {
	if m, ok := body.(map[string]any); ok && method == "POST" && p == "/api/v1/signup" && m["pow_token"] == nil {
		body = b.signupBody(m)
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, b.abs(p), bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	return b.do(req)
}

func (b *browser) postJSON(p string, body any, headers ...string) *http.Response {
	return b.sendJSON("POST", p, body, headers...)
}

func (b *browser) cookie(name string) string {
	u, _ := url.Parse(pubSrv.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// setCookie puts a cookie into the browser, such as a session made with testutil.Session.
func (b *browser) setCookie(name, value string) {
	u, _ := url.Parse(pubSrv.URL)
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/"}})
}

var (
	csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	reqRe  = regexp.MustCompile(`name="req" value="([^"]*)"`)
)

// csrf fetches /login (works logged in or out) and returns the form token, which also sets the csrf cookie.
func (b *browser) csrf() string {
	b.t.Helper()
	body := readBody(b.t, b.get("/login"))
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		b.t.Fatalf("no csrf token on /login: %.200s", body)
	}
	return m[1]
}

func (b *browser) login(username, password, returnTo string) *http.Response {
	b.t.Helper()
	return b.postForm("/login", url.Values{"csrf": {b.csrf()}, "username": {username}, "password": {password}, "return_to": {returnTo}})
}

func (b *browser) mustLogin(username string) {
	b.t.Helper()
	b.mustLoginWith(username, testutil.DefaultPassword)
}

// mustLoginWith signs in, passing two-factor when Guardian asks for it: with the account's code from
// testutil.EnableTOTP, which it calls first if Guardian asks to set two-factor up.
func (b *browser) mustLoginWith(username, password string) {
	b.t.Helper()
	resp := b.login(username, password, "")
	wantStatus(b.t, resp, http.StatusSeeOther)
	drain(resp)
	switch resp.Header.Get("Location") {
	case "/mfa/setup":
		acct, _, err := db.GetAccountForLogin(username)
		if err != nil {
			b.t.Fatal(err)
		}
		testutil.EnableTOTP(b.t, acct.ID)
		b.mustLoginWith(username, password)
	case "/mfa":
		b.passMFA(username)
	}
}

// passMFA answers the two-factor page with the account's current code.
func (b *browser) passMFA(username string) *http.Response {
	b.t.Helper()
	acct, _, err := db.GetAccountForLogin(username)
	if err != nil {
		b.t.Fatal(err)
	}
	resp := b.postForm("/mfa", url.Values{"csrf": {b.csrf()}, "code": {testutil.TOTPCode(b.t, acct.ID)}})
	wantStatus(b.t, resp, http.StatusSeeOther)
	drain(resp)
	return resp
}

func (b *browser) logout() *http.Response {
	b.t.Helper()
	return b.postForm("/logout", url.Values{"csrf": {b.csrf()}})
}

// ---- OIDC helpers -----------------------------------------------------------

func newPKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()
	v, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

type authParams struct {
	app                                      db.App
	scope, state, nonce, challenge, redirect string
	extra                                    url.Values
}

func (p authParams) values() url.Values {
	v := url.Values{"client_id": {p.app.ClientID}, "response_type": {"code"}, "state": {p.state}}
	redirect := p.redirect
	if redirect == "" {
		redirect = p.app.RedirectURIs[0]
	}
	v.Set("redirect_uri", redirect)
	scope := p.scope
	if scope == "" {
		scope = "openid profile email"
	}
	v.Set("scope", scope)
	if p.nonce != "" {
		v.Set("nonce", p.nonce)
	}
	if p.challenge != "" {
		v.Set("code_challenge", p.challenge)
		v.Set("code_challenge_method", "S256")
	}
	for k, vs := range p.extra {
		v[k] = vs
	}
	return v
}

// authorizeCallback runs /authorize (logging in as username first if the browser has no session)
// and returns the URL the browser is finally redirected to (the app's callback or an error redirect).
func (b *browser) authorizeCallback(v url.Values, username string) *url.URL {
	b.t.Helper()
	resp := b.get("/authorize?" + v.Encode())
	loc, status := resp.Header.Get("Location"), resp.StatusCode
	drain(resp)
	if status == http.StatusFound && strings.HasPrefix(loc, "/login?") {
		u, _ := url.Parse(loc)
		returnTo := u.Query().Get("return_to")
		lr := b.login(username, testutil.DefaultPassword, returnTo)
		wantStatus(b.t, lr, http.StatusSeeOther)
		drain(lr)
		if lr.Header.Get("Location") == "/mfa" {
			b.passMFA(username)
		}
		resp = b.get(returnTo)
		loc, status = resp.Header.Get("Location"), resp.StatusCode
		drain(resp)
	}
	if status != http.StatusFound {
		b.t.Fatalf("authorize: status %d, location %q", status, loc)
	}
	cb, err := url.Parse(loc)
	if err != nil {
		b.t.Fatal(err)
	}
	return cb
}

type tokenSet struct {
	Access, Refresh, ID string
	Raw                 map[string]any
}

// signIn performs the whole authorization-code + PKCE flow and returns the issued tokens.
func (b *browser) signIn(app db.App, secret, username, scope string) tokenSet {
	b.t.Helper()
	verifier, challenge := newPKCE(b.t)
	cb := b.authorizeCallback(authParams{app: app, scope: scope, state: "st-1", nonce: "n-1", challenge: challenge}.values(), username)
	if e := cb.Query().Get("error"); e != "" {
		b.t.Fatalf("authorize returned error %q: %s", e, cb.Query().Get("error_description"))
	}
	if cb.Query().Get("state") != "st-1" || cb.Query().Get("iss") != testIssuer {
		b.t.Fatalf("callback lacks state/iss: %s", cb)
	}
	status, raw := tokenRequest(b.t, app, secret, url.Values{
		"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {app.RedirectURIs[0]}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		b.t.Fatalf("token endpoint: %d %v", status, raw)
	}
	return tokenSet{Access: str(raw["access_token"]), Refresh: str(raw["refresh_token"]), ID: str(raw["id_token"]), Raw: raw}
}

func tokenRequest(t *testing.T, app db.App, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	if secret == "" {
		form.Set("client_id", app.ClientID)
	}
	req, _ := http.NewRequest("POST", pubSrv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(app.ClientID, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, decodeMap(t, resp)
}

func refreshRequest(t *testing.T, app db.App, secret, refreshToken string) (int, map[string]any) {
	return tokenRequest(t, app, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

// verifyAccessToken checks an access token the way an app does on its own, without asking Guardian:
// signature, issuer, audience, expiry and the at+jwt type. It returns the claims.
func verifyAccessToken(t *testing.T, app db.App, token string) jwt.MapClaims {
	t.Helper()
	tok := parseJWT(t, token, jwt.WithIssuer(testIssuer), jwt.WithAudience(app.ClientID), jwt.WithExpirationRequired())
	if tok.Header["typ"] != "at+jwt" {
		t.Fatalf("access token typ = %v, want at+jwt", tok.Header["typ"])
	}
	return tok.Claims.(jwt.MapClaims)
}

// refreshed uses the refresh token and requires fresh tokens back.
func refreshed(t *testing.T, app db.App, secret, refreshToken string) tokenSet {
	t.Helper()
	status, raw := refreshRequest(t, app, secret, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, raw)
	}
	return tokenSet{Access: str(raw["access_token"]), Refresh: str(raw["refresh_token"]), ID: str(raw["id_token"]), Raw: raw}
}

// refreshRefused requires the refresh to be refused with invalid_grant, which an app treats as a logout.
func refreshRefused(t *testing.T, app db.App, secret, refreshToken string) {
	t.Helper()
	if status, raw := refreshRequest(t, app, secret, refreshToken); status != http.StatusBadRequest || raw["error"] != "invalid_grant" {
		t.Fatalf("refresh should be refused with invalid_grant: %d %v", status, raw)
	}
}

// groupList returns the "groups" claim of a token or a userinfo answer.
func groupList(m map[string]any) []string {
	out := []string{}
	if arr, ok := m["groups"].([]any); ok {
		for _, v := range arr {
			out = append(out, str(v))
		}
	}
	return out
}

func userinfoStatus(t *testing.T, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", pubSrv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, decodeMap(t, resp)
}

func parseJWT(t *testing.T, token string, opts ...jwt.ParserOption) *jwt.Token {
	t.Helper()
	opts = append([]jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}, opts...)
	tok, err := jwt.Parse(token, testKeys.Keyfunc, opts...)
	if err != nil {
		t.Fatalf("JWT rejected: %v", err)
	}
	return tok
}

// startReceiver is a fake app endpoint that records back-channel logout tokens.
func startReceiver(t *testing.T) (endpoint string, tokens <-chan string) {
	t.Helper()
	ch := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		ch <- r.PostForm.Get("logout_token")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/bcl", ch
}

func waitToken(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("no back-channel logout request arrived")
		return ""
	}
}

func contains(list []string, s string) bool { return slices.Contains(list, s) }

func newTestEnv(t *testing.T) {
	t.Helper()
	testutil.Reset(t)
	mailbox.Reset()
}
