package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	db "guardian/internal/store"
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
		"invalid json":                `{`,
		"unknown client type":         with("client_type", "weird"),
		"uppercase name":              with("name", "Billing"),
		"name with space":             with("name", "my app"),
		"name too short":              with("name", "a"),
		"missing pretty name":         with("pretty_name", ""),
		"no redirect uris":            with("redirect_uris", []string{}),
		"http redirect off-localhost": with("redirect_uris", []string{"http://billing.test/cb"}),
		"redirect with fragment":      with("redirect_uris", []string{"https://billing.test/cb#x"}),
		"bad post-logout uri":         with("post_logout_redirect_uris", []string{"ftp://x/y"}),
		"bad back-channel uri":        with("backchannel_logout_uri", "http://billing.test/bcl"),
		"ttl too small":               with("access_token_ttl_seconds", 14),
		"unknown access rule":         with("access_rule", "everyone"),
		"group id is not an id":       with("group_ids", []string{"nope"}),
		"ttl too large":               with("access_token_ttl_seconds", 86401),
	}
	for name, body := range cases {
		if rec := call(addApp, jsonReq("POST", "/add", body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (rejected before touching the database)", name, rec.Code)
		}
	}
}

func TestGroupAndAppAccessEndpointsValidateInput(t *testing.T) {
	type tc struct {
		name    string
		handler http.HandlerFunc
		body    string
	}
	long := strings.Repeat("x", 129)
	cases := []tc{
		{"create group: upper case key", createGroup, `{"key":"Finance","display_name":"x"}`},
		{"create group: key with a space", createGroup, `{"key":"fin ance","display_name":"x"}`},
		{"create group: key too short", createGroup, `{"key":"f","display_name":"x"}`},
		{"create group: key starts with a dash", createGroup, `{"key":"-finance","display_name":"x"}`},
		{"create group: no display name", createGroup, `{"key":"finance"}`},
		{"create group: display name too long", createGroup, `{"key":"finance","display_name":"` + long + `"}`},
		{"create group: owner is not an id", createGroup, `{"key":"finance","display_name":"x","owner_group_id":"nope"}`},
		{"create group: invalid json", createGroup, `{`},
		{"update group: key cannot change", updateGroup, `{"key":"other"}`},
		{"update group: empty display name", updateGroup, `{"display_name":""}`},
		{"update group: owner is not an id", updateGroup, `{"owner_group_id":"nope"}`},
		{"app access: app is not an id", setAppAccess, `{"id":"nope","access_rule":"anyone"}`},
		{"app access: unknown rule", setAppAccess, `{"id":"` + someUUID + `","access_rule":"everyone"}`},
		{"app access: missing rule", setAppAccess, `{"id":"` + someUUID + `"}`},
		{"app access: group is not an id", setAppAccess, `{"id":"` + someUUID + `","access_rule":"groups","group_ids":["nope"]}`},
	}
	for _, c := range cases {
		if rec := call(c.handler, jsonReq("POST", "/", c.body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (rejected before touching the database)", c.name, rec.Code)
		}
	}
}

func TestGroupFailMapsErrors(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{db.ErrGroupNotFound, http.StatusNotFound},
		{db.ErrSystemGroup, http.StatusForbidden},
		{db.ErrLastAdmin, http.StatusConflict},
		{db.ErrInvalidOwner, http.StatusBadRequest},
		{&pgconn.PgError{Code: "23505"}, http.StatusConflict},
		{errors.New("boom: connection details that must not leak"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		groupFail(rec, c.err)
		if rec.Code != c.want {
			t.Errorf("%v: status %d, want %d", c.err, rec.Code, c.want)
		}
		if strings.Contains(rec.Body.String(), "connection details") {
			t.Errorf("internal error text leaked to the client: %s", rec.Body.String())
		}
	}
}
