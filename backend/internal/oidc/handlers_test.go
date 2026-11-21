package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"guardian/internal/httpx"
)

func call(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

func TestDiscoveryDocument(t *testing.T) {
	oldIssuer := httpx.Issuer
	httpx.Issuer = "https://auth.test"
	t.Cleanup(func() { httpx.Issuer = oldIssuer })

	fetch := func() map[string]any {
		rec := call(discovery, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	m := fetch()
	for key, want := range map[string]string{
		"issuer": "https://auth.test", "authorization_endpoint": "https://auth.test/authorize",
		"token_endpoint": "https://auth.test/token", "userinfo_endpoint": "https://auth.test/userinfo",
		"jwks_uri": "https://auth.test/jwks.json", "end_session_endpoint": "https://auth.test/logout",
		"revocation_endpoint": "https://auth.test/revoke",
	} {
		if m[key] != want {
			t.Errorf("%s = %v, want %s", key, m[key], want)
		}
	}
	if _, present := m["introspection_endpoint"]; present {
		t.Error("introspection was removed and must not be advertised")
	}
	asStrings := func(key string) []string {
		var out []string
		for _, v := range m[key].([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	if got := asStrings("response_types_supported"); len(got) != 1 || got[0] != "code" {
		t.Errorf("response types = %v (implicit flows must not be offered)", got)
	}
	if got := asStrings("code_challenge_methods_supported"); len(got) != 1 || got[0] != "S256" {
		t.Errorf("PKCE methods = %v (plain must not be offered)", got)
	}
	if got := asStrings("grant_types_supported"); strings.Join(got, ",") != "authorization_code,refresh_token,client_credentials" {
		t.Errorf("grant types = %v", got)
	}
	if got := asStrings("id_token_signing_alg_values_supported"); len(got) != 1 || got[0] != "RS256" {
		t.Errorf("signing algs = %v", got)
	}
	if m["backchannel_logout_supported"] != true || m["backchannel_logout_session_supported"] != true {
		t.Error("back-channel logout must be advertised")
	}
	scopes := strings.Join(asStrings("scopes_supported"), ",")
	if !strings.Contains(scopes, "groups") || strings.Contains(scopes, "phone") {
		t.Errorf("scopes = %v, want groups and no phone", scopes)
	}
	claims := strings.Join(asStrings("claims_supported"), ",")
	if !strings.Contains(claims, "groups") || !strings.Contains(claims, "amr") || strings.Contains(claims, "phone") {
		t.Errorf("claims = %v, want groups and amr and no phone claims", claims)
	}
}

func postForm(h http.HandlerFunc, body, basicUser, basicPass string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		r.SetBasicAuth(basicUser, basicPass)
	}
	return call(h, r)
}

func TestTokenAndRevokeRejectUnauthenticatedClients(t *testing.T) {
	// A client id nobody registered is counted as the app "unknown", never under the id it sent.
	before := promtest.ToFloat64(tokenRefusals.WithLabelValues("unknown", "refresh_token", "unknown_client"))
	for _, ep := range []struct {
		name string
		h    http.HandlerFunc
		body string
	}{
		{"token", tokenEndpoint, "grant_type=refresh_token&refresh_token=abc"},
		{"revoke", revokeEndpoint, "token=abc"},
	} {
		for name, rec := range map[string]*httptest.ResponseRecorder{
			"no credentials":      postForm(ep.h, ep.body, "", ""),
			"malformed client id": postForm(ep.h, ep.body, "not-a-uuid", "secret"),
		} {
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s, %s: status %d, want 401", ep.name, name, rec.Code)
			}
			if rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s, %s: headers %v", ep.name, name, rec.Header())
			}
			var body map[string]string
			json.Unmarshal(rec.Body.Bytes(), &body)
			if body["error"] != "invalid_client" {
				t.Errorf("%s, %s: error = %q", ep.name, name, body["error"])
			}
		}
	}
	if got := promtest.ToFloat64(tokenRefusals.WithLabelValues("unknown", "refresh_token", "unknown_client")); got != before+2 {
		t.Errorf("refused counter went %v -> %v, want +2", before, got)
	}
	// whatever a client sends as grant_type, the metric keeps a fixed set of labels
	if grantLabel("../../etc") != "other" || grantLabel("refresh_token") != "refresh_token" {
		t.Error("grantLabel lets arbitrary values through")
	}
}

func TestTokenAndRevokeRejectOversizedBodies(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{"token": tokenEndpoint, "revoke": revokeEndpoint} {
		if rec := postForm(h, "token="+strings.Repeat("a", 100_000), "", ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
}

func TestUserinfoRequiresBearerToken(t *testing.T) {
	for name, header := range map[string]string{"missing": "", "basic": "Basic dXNlcjpwYXNz", "bare": "Bearer"} {
		r := httptest.NewRequest("GET", "/userinfo", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		rec := call(userinfo, r)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
			t.Errorf("%s: status %d, WWW-Authenticate %q", name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
}
