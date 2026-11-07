package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	db "guardian/database"
)

const someUUID = "11111111-1111-1111-1111-111111111111"

func jsonReq(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func call(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

func TestDiscoveryDocument(t *testing.T) {
	oldIssuer, oldURL := Issuer, IntrospectionURL
	Issuer, IntrospectionURL = "https://auth.test", ""
	t.Cleanup(func() { Issuer, IntrospectionURL = oldIssuer, oldURL })

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
	} {
		if m[key] != want {
			t.Errorf("%s = %v, want %s", key, m[key], want)
		}
	}
	if _, present := m["introspection_endpoint"]; present {
		t.Error("introspection_endpoint must not be advertised unless configured")
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
	if got := asStrings("grant_types_supported"); strings.Join(got, ",") != "authorization_code,refresh_token" {
		t.Errorf("grant types = %v", got)
	}
	if got := asStrings("id_token_signing_alg_values_supported"); len(got) != 1 || got[0] != "RS256" {
		t.Errorf("signing algs = %v", got)
	}
	if m["backchannel_logout_supported"] != true || m["backchannel_logout_session_supported"] != true {
		t.Error("back-channel logout must be advertised")
	}

	IntrospectionURL = "http://guardian-internal.guardian.svc:3002/introspect"
	if got := fetch()["introspection_endpoint"]; got != IntrospectionURL {
		t.Errorf("introspection_endpoint = %v", got)
	}
}

func TestInternalRouterBasics(t *testing.T) {
	h := GetInternalRouter()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("/healthz = %d", rec.Code)
	}

	// introspection must not be reachable with GET, and the public API must not exist on this listener
	for _, c := range []struct{ method, path string }{{"GET", "/introspect"}, {"GET", "/authorize"}, {"POST", "/token"}, {"GET", "/login"}} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s on the internal listener = %d, want 404/405", c.method, c.path, rec.Code)
		}
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "guardian_") {
		t.Errorf("/metrics = %d, body lacks guardian_ metrics", rec.Code)
	}
}

func TestIntrospectRejectsUnauthenticatedCallers(t *testing.T) {
	h := GetInternalRouter()
	before := promtest.ToFloat64(introspections.WithLabelValues("unauthorized"))

	post := func(basicUser, basicPass string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/introspect", strings.NewReader("token=abc"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basicUser != "" {
			r.SetBasicAuth(basicUser, basicPass)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"no credentials":       post("", ""),
		"malformed client id":  post("not-a-uuid", "secret"),
	} {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: missing WWW-Authenticate", name)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: introspection responses must be no-store", name)
		}
		var body map[string]string
		json.Unmarshal(rec.Body.Bytes(), &body)
		if body["error"] != "invalid_client" {
			t.Errorf("%s: error = %q", name, body["error"])
		}
		if strings.Contains(rec.Body.String(), `"active"`) {
			t.Errorf("%s: an unauthenticated caller must learn nothing about the token", name)
		}
	}
	if got := promtest.ToFloat64(introspections.WithLabelValues("unauthorized")); got != before+2 {
		t.Errorf("unauthorized counter went %v -> %v, want +2", before, got)
	}
}

func TestIntrospectRejectsOversizedBodies(t *testing.T) {
	r := httptest.NewRequest("POST", "/introspect", strings.NewReader("token="+strings.Repeat("a", 100_000)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	GetInternalRouter().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
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

func TestRegisterValidation(t *testing.T) {
	cases := map[string]string{
		"invalid json":         `{"username":`,
		"empty body":           ``,
		"username too short":   `{"username":"ab","password":"long-enough-password"}`,
		"username with space":  `{"username":"a b c","password":"long-enough-password"}`,
		"username with symbol": `{"username":"alice@home","password":"long-enough-password"}`,
		"username too long":    `{"username":"` + strings.Repeat("a", 65) + `","password":"long-enough-password"}`,
		"password too short":   `{"username":"alice","password":"123456789"}`,
		"password too long":    `{"username":"alice","password":"` + strings.Repeat("x", 1025) + `"}`,
		"body over 1 MiB":      `{"username":"alice","password":"` + strings.Repeat("x", 1<<20) + `"}`,
	}
	for name, body := range cases {
		rec := call(register, jsonReq("POST", "/register", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (and no database access)", name, rec.Code)
		}
	}
}

func TestUpdateUsernameValidation(t *testing.T) {
	for _, body := range []string{`{"username":"x"}`, `{"username":"has space"}`, `{}`, `nope`} {
		if rec := call(updateUsername, jsonReq("POST", "/update/username", body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
	}
}

func TestAddAppValidation(t *testing.T) {
	valid := map[string]any{"name": "billing", "pretty_name": "Billing", "redirect_uris": []string{"https://billing.test/cb"}}
	with := func(key string, value any) string {
		m := map[string]any{}
		for k, v := range valid {
			m[k] = v
		}
		if value == nil {
			delete(m, key)
		} else {
			m[key] = value
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	cases := map[string]string{
		"invalid json":              `{`,
		"unknown client type":       with("client_type", "weird"),
		"uppercase name":            with("name", "Billing"),
		"name with space":           with("name", "my app"),
		"name too short":            with("name", "a"),
		"missing pretty name":       with("pretty_name", ""),
		"no redirect uris":          with("redirect_uris", []string{}),
		"http redirect off-localhost": with("redirect_uris", []string{"http://billing.test/cb"}),
		"redirect with fragment":    with("redirect_uris", []string{"https://billing.test/cb#x"}),
		"bad post-logout uri":       with("post_logout_redirect_uris", []string{"ftp://x/y"}),
		"bad back-channel uri":      with("backchannel_logout_uri", "http://billing.test/bcl"),
		"ttl too small":             with("access_token_ttl_seconds", 59),
		"ttl too large":             with("access_token_ttl_seconds", 86401),
	}
	for name, body := range cases {
		if rec := call(addApp, jsonReq("POST", "/add", body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (rejected before touching the database)", name, rec.Code)
		}
	}
}

func TestAccessEndpointsValidateIDsAndAttributes(t *testing.T) {
	type tc struct {
		name    string
		handler http.HandlerFunc
		body    string
	}
	cases := []tc{
		{"grant-role bad ids", grantRole, `{"account_id":"x","role_id":"y"}`},
		{"grant-role missing role", grantRole, `{"account_id":"` + someUUID + `"}`},
		{"revoke-role bad ids", revokeRole, `{"account_id":"x","role_id":"` + someUUID + `"}`},
		{"grant-permission bad ids", grantPermission, `{"account_id":"x","permission_id":"y"}`},
		{"grant-permission attributes not an object", grantPermission,
			`{"account_id":"` + someUUID + `","permission_id":"` + someUUID + `","attributes":[1,2]}`},
		{"grant-permission attributes string", grantPermission,
			`{"account_id":"` + someUUID + `","permission_id":"` + someUUID + `","attributes":"x"}`},
		{"revoke-permission bad ids", revokePermission, `{"account_id":"x","permission_id":"y"}`},
		{"create role bad name", createRole, `{"name":"Bad Name","pretty_name":"x"}`},
		{"create role bad permission id", createRole, `{"name":"ok-name","pretty_name":"x","permission_ids":["nope"]}`},
		{"delete role bad id", deleteRole, `{"role_id":"nope"}`},
		{"set role permissions bad id", setRolePermissions, `{"role_id":"nope","permission_ids":[]}`},
		{"create permission bad app", createPermission, `{"app_id":"nope","name":"x","pretty_name":"x"}`},
		{"create permission empty name", createPermission, `{"app_id":"` + someUUID + `","name":"","pretty_name":"x"}`},
		{"invalid json", grantRole, `{`},
	}
	for _, c := range cases {
		if rec := call(c.handler, jsonReq("POST", "/", c.body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", c.name, rec.Code)
		}
	}
}

func TestAccessFailMapsErrors(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{&pq.Error{Code: "23505"}, http.StatusConflict},
		{db.ErrSystemRole, http.StatusForbidden},
		{errors.New("boom: connection details that must not leak"), http.StatusBadRequest},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		accessFail(rec, c.err)
		if rec.Code != c.want {
			t.Errorf("%v: status %d, want %d", c.err, rec.Code, c.want)
		}
		if strings.Contains(rec.Body.String(), "connection details") {
			t.Errorf("internal error text leaked to the client: %s", rec.Body.String())
		}
	}
}

func TestMetricsMiddlewareRecordsRoutePatternAndStatus(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Metrics("unit"))
	r.Get("/things/{id}", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }) // implicit 200
	r.Get("/boom", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusInternalServerError) })

	for _, path := range []string{"/things/1", "/things/2", "/things/3", "/boom"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	if got := promtest.ToFloat64(httpRequests.WithLabelValues("unit", "/things/{id}", "GET", "200")); got != 3 {
		t.Errorf("/things/{id} 200 count = %v, want 3 (one series for all ids: bounded label cardinality)", got)
	}
	if got := promtest.ToFloat64(httpRequests.WithLabelValues("unit", "/boom", "GET", "500")); got != 1 {
		t.Errorf("/boom 500 count = %v, want 1", got)
	}
}
