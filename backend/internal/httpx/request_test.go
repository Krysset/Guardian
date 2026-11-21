package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
			if got := ClientIP(reqFrom(c.remote, c.xff...)); got != c.want {
				t.Errorf("ClientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSafeReturnToOnlyAllowsAuthorizeAndTheManagementUI(t *testing.T) {
	ok := []string{"/authorize?client_id=x", "/authorize?redirect_uri=//evil.example",
		"/account", "/account/security", "/admin", "/admin/accounts?q=link&page=2", "/account?x=//y"}
	bad := []string{
		"", "/", "/login", "/authorize", "/authorizeevil?x=1", "//evil.example", "https://evil.example/authorize?x=1",
		"\\\\evil.example", "/\\evil.example", "javascript:alert(1)", " /authorize?x=1",
		"/accounts", "/administrator", "/account//evil.example", "/admin/..//x", "/account/\\evil", "/account/\x00",
		"/account/ä", "/account#x", "/admin/../login",
	}
	for _, p := range ok {
		if SafeReturnTo(p) != p {
			t.Errorf("%q should be allowed", p)
		}
	}
	for _, p := range bad {
		if SafeReturnTo(p) != "" {
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
		if !ValidRedirectURI(u) {
			t.Errorf("%q should be valid", u)
		}
	}
	for _, u := range bad {
		if ValidRedirectURI(u) {
			t.Errorf("%q must be rejected", u)
		}
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
		if got := CSRFValid(csrfRequest(c.cookie, c.field)); got != c.want {
			t.Errorf("%s: CSRFValid = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCSRFTokenIssuedOnceAndHardened(t *testing.T) {
	rec := httptest.NewRecorder()
	token := CSRFToken(rec, httptest.NewRequest("GET", "/", nil))
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
	if CSRFToken(again, r) != token || len(again.Result().Cookies()) != 0 {
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

// Covers: V2
func TestLimitAddressGroupsIPv6PerBlock(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":          "203.0.113.9",
		"2001:db8:1:2::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"::ffff:203.0.113.9":   "::ffff:203.0.113.9", // an IPv4 address written as IPv6 stays one address
		"not an address":       "not an address",
	} {
		if got := LimitAddress(in); got != want {
			t.Errorf("LimitAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
