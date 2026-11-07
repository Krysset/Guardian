package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	api "guardian/api"
	"guardian/auth"
	db "guardian/database"
	"guardian/internal/testutil"
)

const testIssuer = "http://guardian.test"

var (
	pubSrv   *httptest.Server // the public listener (what browsers and apps reach through the ingress)
	intSrv   *httptest.Server // the internal listener (introspection, metrics, probes)
	testKeys *auth.Keys
)

func TestMain(m *testing.M) {
	if testutil.Enabled() {
		if err := testutil.Setup(); err != nil {
			fmt.Fprintln(os.Stderr, "test setup:", err)
			os.Exit(1)
		}
		os.Setenv("ISSUER_URL", testIssuer)
		os.Setenv("INTROSPECTION_URL", "http://internal.test/introspect")
		os.Setenv("SESSION_TTL", "1h")
		os.Setenv("KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
		testutil.DeleteSigningKeys()
		k, err := auth.LoadKeys()
		if err != nil {
			fmt.Fprintln(os.Stderr, "load keys:", err)
			os.Exit(1)
		}
		testKeys = k
		if err := api.Configure(k); err != nil {
			fmt.Fprintln(os.Stderr, "configure:", err)
			os.Exit(1)
		}
		pubSrv = httptest.NewServer(publicRouter())
		intSrv = httptest.NewServer(api.GetInternalRouter())
	}
	code := m.Run()
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
	t *testing.T
	c *http.Client
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

func (b *browser) postForm(p string, v url.Values) *http.Response {
	req, _ := http.NewRequest("POST", b.abs(p), strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

// sendJSON sends a JSON request; headers are name/value pairs (e.g. "Origin", "https://evil.example").
func (b *browser) sendJSON(method, p string, body any, headers ...string) *http.Response {
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
	resp := b.login(username, testutil.DefaultPassword, "")
	wantStatus(b.t, resp, http.StatusSeeOther)
	drain(resp)
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
	app                                    db.App
	scope, state, nonce, challenge, redirect string
	extra                                  url.Values
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
		scope = "openid profile email offline_access"
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

func introspectToken(t *testing.T, caller db.App, secret, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", intSrv.URL+"/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(caller.ClientID, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, decodeMap(t, resp)
}

func mustActive(t *testing.T, caller db.App, secret, token string) map[string]any {
	t.Helper()
	status, m := introspectToken(t, caller, secret, token)
	if status != 200 || m["active"] != true {
		t.Fatalf("token should be active: %d %v", status, m)
	}
	return m
}

func mustInactive(t *testing.T, caller db.App, secret, token string) {
	t.Helper()
	status, m := introspectToken(t, caller, secret, token)
	if status != 200 || m["active"] != false || len(m) != 1 {
		t.Fatalf("token should be inactive with nothing else disclosed: %d %v", status, m)
	}
}

func permList(m map[string]any) []string {
	var out []string
	if arr, ok := m["permissions"].([]any); ok {
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
}
