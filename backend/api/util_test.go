package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	db "guardian/database"
)

func withHops(t *testing.T, n int) {
	t.Helper()
	old := trustedProxyHops
	trustedProxyHops = n
	t.Cleanup(func() { trustedProxyHops = old })
}

func reqFrom(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name   string
		hops   int
		remote string
		xff    []string
		want   string
	}{
		{"header ignored without trusted proxies", 0, "10.0.0.1:5000", []string{"1.2.3.4"}, "10.0.0.1"},
		{"one proxy: take the entry it appended", 1, "10.0.0.1:5000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"one proxy: client-supplied prefix is ignored", 1, "10.0.0.1:5000", []string{"6.6.6.6, 203.0.113.7"}, "203.0.113.7"},
		{"two proxies", 2, "10.0.0.1:5000", []string{"203.0.113.7, 10.1.1.1"}, "203.0.113.7"},
		{"two proxies: spoofed prefix ignored", 2, "10.0.0.1:5000", []string{"6.6.6.6, 203.0.113.7, 10.1.1.1"}, "203.0.113.7"},
		{"fewer entries than trusted hops falls back to peer", 2, "10.0.0.1:5000", []string{"203.0.113.7"}, "10.0.0.1"},
		{"garbage entry falls back to peer", 1, "10.0.0.1:5000", []string{"not-an-ip"}, "10.0.0.1"},
		{"missing header falls back to peer", 1, "10.0.0.1:5000", nil, "10.0.0.1"},
		{"several header lines are joined", 1, "10.0.0.1:5000", []string{"6.6.6.6", "203.0.113.7"}, "203.0.113.7"},
		{"ipv6 in header", 1, "10.0.0.1:5000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"ipv6 peer", 0, "[::1]:8080", nil, "::1"},
		{"peer without port", 0, "10.0.0.9", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withHops(t, c.hops)
			if got := clientIP(reqFrom(c.remote, c.xff...)); got != c.want {
				t.Errorf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSafeReturnToOnlyAllowsOwnAuthorizeEndpoint(t *testing.T) {
	ok := []string{"/authorize?client_id=x", "/authorize?redirect_uri=//evil.example"}
	bad := []string{
		"", "/", "/login", "/authorize", "/authorizeevil?x=1", "//evil.example", "https://evil.example/authorize?x=1",
		"\\\\evil.example", "/\\evil.example", "javascript:alert(1)", " /authorize?x=1",
	}
	for _, p := range ok {
		if safeReturnTo(p) != p {
			t.Errorf("%q should be allowed", p)
		}
	}
	for _, p := range bad {
		if safeReturnTo(p) != "" {
			t.Errorf("%q must be rejected", p)
		}
	}
}

func TestValidRedirectURI(t *testing.T) {
	ok := []string{
		"https://app.example.com/cb", "https://app.example.com:8443/cb?x=1",
		"http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb",
	}
	bad := []string{
		"", "http://example.com/cb", "ftp://example.com/cb", "https://", "https:///path", "https://app.example.com/cb#frag",
		"https://user:pw@app.example.com/cb", "javascript:alert(1)", "/relative", "//evil.example/cb", "app.example.com/cb",
	}
	for _, u := range ok {
		if !validRedirectURI(u) {
			t.Errorf("%q should be valid", u)
		}
	}
	for _, u := range bad {
		if validRedirectURI(u) {
			t.Errorf("%q must be rejected", u)
		}
	}
}

func TestSliceHelpers(t *testing.T) {
	if !contains([]string{"a", "b"}, "b") || contains([]string{"a"}, "z") || contains(nil, "a") {
		t.Error("contains")
	}
	if !subset([]string{"a"}, []string{"a", "b"}) || subset([]string{"a", "c"}, []string{"a", "b"}) || !subset(nil, nil) {
		t.Error("subset")
	}
	in := []string{"a", "b", "a"}
	if got := without(in, "a"); !reflect.DeepEqual(got, []string{"b"}) {
		t.Errorf("without = %v", got)
	}
	if !reflect.DeepEqual(in, []string{"a", "b", "a"}) {
		t.Error("without mutated its input")
	}
	base := []string{"a", "b"}
	if got := union(base, []string{"b", "c", "c"}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("union = %v", got)
	}
	if !reflect.DeepEqual(base, []string{"a", "b"}) {
		t.Error("union mutated its input")
	}
}

// RFC 7636 appendix B test vector.
func TestVerifyPKCE(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE(verifier, challenge) {
		t.Fatal("RFC 7636 vector rejected")
	}
	if verifyPKCE(verifier+"x", challenge) || verifyPKCE(challenge, challenge) {
		t.Error("wrong verifier accepted")
	}
	if verifyPKCE("short", challenge) {
		t.Error("verifier shorter than 43 characters must be rejected")
	}
	if verifyPKCE(strings.Repeat("a", 129), challenge) {
		t.Error("verifier longer than 128 characters must be rejected")
	}
	if verifyPKCE(verifier, "") {
		t.Error("empty challenge accepted")
	}
}

func TestBuildClaimsReleasesOnlyWhatScopesAllow(t *testing.T) {
	acct := db.Account{
		ID: "11111111-1111-1111-1111-111111111111", Username: "alice", DisplayName: "Alice A", GivenName: "Alice",
		Email: "alice@example.com", EmailVerified: true, PhoneNumber: "+46700000000", PhoneVerified: false,
		PictureURL: "https://x.test/a.png", Locale: "sv-SE",
	}
	keys := func(m map[string]any) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		return out
	}

	only := buildClaims(acct, nil)
	if len(only) != 1 || only["sub"] != acct.ID {
		t.Fatalf("with no scopes only sub may be released, got %v", keys(only))
	}

	email := buildClaims(acct, []string{"email", "email_verified"})
	if email["email"] != "alice@example.com" || email["email_verified"] != true {
		t.Errorf("email claims = %v", email)
	}
	for _, leaked := range []string{"name", "preferred_username", "phone_number", "picture", "locale"} {
		if _, ok := email[leaked]; ok {
			t.Errorf("email scope leaked %q", leaked)
		}
	}

	profile := buildClaims(acct, []string{"name", "given_name", "preferred_username", "picture", "locale", "updated_at"})
	if profile["name"] != "Alice A" || profile["preferred_username"] != "alice" || profile["given_name"] != "Alice" {
		t.Errorf("profile claims = %v", profile)
	}
	if _, ok := profile["updated_at"]; !ok {
		t.Error("updated_at missing")
	}
	if _, ok := profile["email"]; ok {
		t.Error("profile scope leaked email")
	}
	if _, ok := profile["family_name"]; ok {
		t.Error("empty values must be omitted")
	}

	phone := buildClaims(acct, []string{"phone_number", "phone_number_verified"})
	if phone["phone_number"] != "+46700000000" || phone["phone_number_verified"] != false {
		t.Errorf("phone claims = %v", phone)
	}

	// email_verified alone must not reveal the address, and an account without email releases no email claims
	if got := buildClaims(acct, []string{"email_verified"}); len(got) != 1 {
		t.Errorf("email_verified without email leaked %v", keys(got))
	}
	acct.Email = ""
	if got := buildClaims(acct, []string{"email", "email_verified"}); len(got) != 1 {
		t.Errorf("account without email released %v", keys(got))
	}
}

func csrfRequest(cookie, field string) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{"csrf": {field}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: cookie})
	}
	return r
}

func TestCSRFValidation(t *testing.T) {
	good := strings.Repeat("a", 43)
	cases := []struct {
		name          string
		cookie, field string
		want          bool
	}{
		{"matching", good, good, true},
		{"mismatch", good, strings.Repeat("b", 43), false},
		{"missing cookie", "", good, false},
		{"missing field", good, "", false},
		{"short but equal", "abc", "abc", false},
	}
	for _, c := range cases {
		if got := csrfValid(csrfRequest(c.cookie, c.field)); got != c.want {
			t.Errorf("%s: csrfValid = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCSRFTokenIssuedOnceAndHardened(t *testing.T) {
	rec := httptest.NewRecorder()
	token := csrfToken(rec, httptest.NewRequest("GET", "/", nil))
	if len(token) != 43 {
		t.Fatalf("token length = %d", len(token))
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != token || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("csrf cookie not hardened: %+v", cookies)
	}

	again := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	if csrfToken(again, r) != token || len(again.Result().Cookies()) != 0 {
		t.Error("an existing token must be reused without setting a new cookie")
	}
}

func TestRequireSameOrigin(t *testing.T) {
	old := allowedOrigins
	allowedOrigins = map[string]bool{"https://auth.test": true}
	t.Cleanup(func() { allowedOrigins = old })

	h := RequireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	cases := []struct {
		method, origin string
		want           int
	}{
		{"POST", "https://evil.example", http.StatusForbidden},
		{"POST", "https://auth.test.evil.example", http.StatusForbidden},
		{"POST", "http://auth.test", http.StatusForbidden}, // scheme matters
		{"DELETE", "https://evil.example", http.StatusForbidden},
		{"PUT", "null", http.StatusForbidden},
		{"POST", "https://auth.test", http.StatusNoContent},
		{"POST", "", http.StatusNoContent}, // not a browser request
		{"GET", "https://evil.example", http.StatusNoContent},
		{"OPTIONS", "https://evil.example", http.StatusNoContent},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "/", nil)
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != c.want {
			t.Errorf("%s with Origin %q: status %d, want %d", c.method, c.origin, rec.Code, c.want)
		}
	}
}
