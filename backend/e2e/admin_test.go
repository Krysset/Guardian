package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// items returns the "items" of a list answer.
func items(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	raw, ok := m["items"].([]any)
	if !ok {
		t.Fatalf("not a list answer: %v", m)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(map[string]any))
	}
	return out
}

func usernames(list []map[string]any) string {
	var out []string
	for _, a := range list {
		out = append(out, str(a["username"]))
	}
	return strings.Join(out, ",")
}

// Covers: A1, A3, A4
func TestE2EAdminsListCreateAndEditAccounts(t *testing.T) {
	testutil.Reset(t)
	root := testutil.AdminAccount(t, "root")
	for _, u := range []string{"amy", "ben", "cat"} {
		testutil.CreateAccount(t, u)
	}
	admin := newBrowser(t)
	admin.mustLogin("root")

	// paging: every account exactly once, in order
	first := admin.call("GET", "/api/v1/accounts?limit=2", nil, 200)
	second := admin.call("GET", "/api/v1/accounts?limit=2&cursor="+str(first["next_cursor"]), nil, 200)
	third := admin.call("GET", "/api/v1/accounts?limit=2&cursor="+str(second["next_cursor"]), nil, 200)
	if got := usernames(items(t, first)) + "|" + usernames(items(t, second)) + "|" + usernames(items(t, third)); got != "admin,amy|ben,cat|root" {
		t.Errorf("pages = %s", got)
	}
	if third["next_cursor"] != nil {
		t.Errorf("the last page must have no next_cursor, got %v", third["next_cursor"])
	}
	if got := usernames(items(t, admin.call("GET", "/api/v1/accounts?q=BE", nil, 200))); got != "ben" {
		t.Errorf("search = %s", got)
	}

	// an account made by an administrator, with an email that counts as verified
	made := admin.call("POST", "/api/v1/accounts", map[string]any{"username": "dan", "password": testutil.DefaultPassword, "email": "dan@example.com"}, 201)
	if made["email"] != "dan@example.com" || made["email_verified"] != true || made["must_change_password"] != true {
		t.Errorf("created = %v", made)
	}
	admin.call("POST", "/api/v1/accounts", map[string]any{"username": "DAN", "password": testutil.DefaultPassword}, 409)
	dan := str(made["id"])
	newBrowser(t).mustLogin("dan")

	// one account, with its groups
	team := testutil.Group(t, "team", "")
	testutil.AddMember(t, team, dan)
	one := admin.call("GET", "/api/v1/accounts/"+dan, nil, 200)
	if groups, _ := one["groups"].([]any); len(groups) != 1 || groups[0].(map[string]any)["key"] != "team" {
		t.Errorf("groups = %v", one["groups"])
	}
	admin.call("GET", "/api/v1/accounts/00000000-0000-0000-0000-000000000000", nil, 404)

	// editing
	edited := admin.call("PATCH", "/api/v1/accounts/"+dan, map[string]any{"display_name": "Dan D", "email": "dd@example.com"}, 200)
	if edited["display_name"] != "Dan D" || edited["email"] != "dd@example.com" || edited["email_verified"] != true {
		t.Errorf("edited = %v", edited)
	}
	admin.call("PATCH", "/api/v1/accounts/"+dan, map[string]any{"username": "amy"}, 409)

	// the administrator's own view of itself
	if me := admin.call("GET", "/api/v1/me", nil, 200); me["is_admin"] != true || me["id"] != root.ID {
		t.Errorf("me = %v", me)
	}
}

// Covers: A5
func TestE2EDisablingAnAccountLocksItOutAndEnablingLetsItBackIn(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	user := testutil.CreateAccount(t, "erin")
	endpoint, logouts := startReceiver(t)
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true, BackchannelURI: endpoint})
	ub := newBrowser(t)
	tok := ub.signIn(app, secret, "erin", "openid")
	admin := newBrowser(t)
	admin.mustLogin("root")

	if got := admin.call("PATCH", "/api/v1/accounts/"+user.ID, map[string]any{"status": "disabled"}, 200); got["status"] != "disabled" {
		t.Fatalf("status = %v", got["status"])
	}
	if lt := parseJWT(t, waitToken(t, logouts), jwt.WithAudience(app.ClientID)); lt.Claims.(jwt.MapClaims)["sub"] != user.ID {
		t.Errorf("the app was told about the wrong user: %v", lt.Claims)
	}
	refreshRefused(t, app, secret, tok.Refresh)
	me := ub.get("/api/v1/me")
	wantStatus(t, me, http.StatusUnauthorized)
	drain(me)
	r := newBrowser(t).login("erin", testutil.DefaultPassword, "")
	wantStatus(t, r, http.StatusUnauthorized)
	drain(r)

	admin.call("PATCH", "/api/v1/accounts/"+user.ID, map[string]any{"status": "active"}, 200)
	newBrowser(t).mustLogin("erin")
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'account.updated' AND metadata->>'target' = $1`, user.ID); n != 2 {
		t.Errorf("%d audit entries, want 2", n)
	}
}

// Covers: U3, A6
func TestE2EAnAdminSetPasswordEndsSessionsAndMustBeChanged(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	user := testutil.CreateAccount(t, "fay")
	ub := newBrowser(t)
	ub.mustLogin("fay")
	admin := newBrowser(t)
	admin.mustLogin("root")

	admin.call("PUT", "/api/v1/accounts/"+user.ID+"/password", map[string]any{"new_password": "temporary-password-1"}, 204)
	me := ub.get("/api/v1/me")
	wantStatus(t, me, http.StatusUnauthorized)
	drain(me)
	fresh := newBrowser(t)
	fresh.mustLoginWith("fay", "temporary-password-1")
	if got := fresh.call("GET", "/api/v1/me", nil, 200); got["must_change_password"] != true {
		t.Errorf("must_change_password = %v", got["must_change_password"])
	}
	fresh.call("PUT", "/api/v1/me/password", map[string]any{"new_password": "my-own-password-1"}, 204)
	if got := fresh.call("GET", "/api/v1/me", nil, 200); got["must_change_password"] != false {
		t.Errorf("after the user's own change: must_change_password = %v", got["must_change_password"])
	}
}

// Covers: A15, A17, A19
func TestE2EAdminsEditAppsAndRotateSecrets(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	testutil.CreateAccount(t, "gil")
	app, oldSecret := testutil.CreateApp(t, "notes", testutil.AppOptions{FirstParty: true})
	admin := newBrowser(t)
	admin.mustLogin("root")
	path := "/api/v1/apps/" + app.ID

	edited := admin.call("PATCH", path, map[string]any{"pretty_name": "Notes", "access_token_ttl_seconds": 120,
		"redirect_uris": []string{"https://notes.test/cb2"}}, 200)
	if edited["pretty_name"] != "Notes" || edited["access_token_ttl_seconds"] != float64(120) || fmt.Sprint(edited["redirect_uris"]) != "[https://notes.test/cb2]" {
		t.Errorf("edited = %v", edited)
	}
	admin.call("PATCH", path, map[string]any{"client_type": "public"}, 400)
	admin.call("PATCH", "/api/v1/apps/00000000-0000-0000-0000-000000000000", map[string]any{"pretty_name": "x"}, 404)

	// a rotated secret with a grace period: both work for now
	rotated := str(admin.call("POST", path+"/secret", map[string]any{"grace_seconds": 3600}, 201)["client_secret"])
	if len(rotated) != 43 {
		t.Fatalf("secret = %q", rotated)
	}
	for _, s := range []string{oldSecret, rotated} {
		if status, body := refreshRequest(t, app, s, "garbage"); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("secret %.6s… during the grace period: %d %v", s, status, body)
		}
	}
	// rotating again without grace: only the newest works
	newest := str(admin.call("POST", path+"/secret", nil, 201)["client_secret"])
	if status, _ := refreshRequest(t, app, rotated, "garbage"); status != http.StatusUnauthorized {
		t.Errorf("an old secret still works after rotation without grace: %d", status)
	}
	if status, _ := refreshRequest(t, app, newest, "garbage"); status != http.StatusBadRequest {
		t.Errorf("the newest secret does not work: %d", status)
	}

	// a disabled app cannot get tokens
	admin.call("PATCH", path, map[string]any{"enabled": false}, 200)
	if status, _ := refreshRequest(t, app, newest, "garbage"); status != http.StatusUnauthorized {
		t.Errorf("a disabled app authenticated: %d", status)
	}
	spa, _ := testutil.CreateApp(t, "spa", testutil.AppOptions{Public: true})
	admin.call("POST", "/api/v1/apps/"+spa.ID+"/secret", nil, 400)
}

// Covers: A22
func TestE2EAuditLogAPI(t *testing.T) {
	testutil.Reset(t)
	root := testutil.AdminAccount(t, "root")
	admin := newBrowser(t)
	admin.mustLogin("root")
	for i := 0; i < 3; i++ {
		r := newBrowser(t).login("root", "wrong-password-123", "")
		drain(r)
	}
	admin.call("POST", "/api/v1/groups", map[string]any{"key": "team", "display_name": "Team"}, 201)

	all := items(t, admin.call("GET", "/api/v1/audit", nil, 200))
	if len(all) < 5 || all[0]["event_type"] != "group.created" {
		t.Fatalf("newest entry = %v (of %d)", all[0], len(all))
	}
	failures := admin.call("GET", "/api/v1/audit?event=login.failure&limit=2", nil, 200)
	page := items(t, failures)
	if len(page) != 2 || failures["next_cursor"] == nil {
		t.Fatalf("first page = %v", failures)
	}
	rest := items(t, admin.call("GET", "/api/v1/audit?event=login.failure&limit=2&cursor="+str(failures["next_cursor"]), nil, 200))
	if len(rest) != 1 {
		t.Errorf("second page has %d entries, want 1", len(rest))
	}
	mine := items(t, admin.call("GET", "/api/v1/audit?account="+root.ID+"&event=group.created", nil, 200))
	if len(mine) != 1 || mine[0]["metadata"].(map[string]any)["key"] != "team" {
		t.Errorf("filtered = %v", mine)
	}
}

func TestE2EAPIErrorsAndUnknownRoutes(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	admin := newBrowser(t)
	admin.mustLogin("root")

	got := admin.call("GET", "/api/v1/nothing-here", nil, 404)
	if got["error"] != "not_found" || got["message"] == "" {
		t.Errorf("unknown route: %v", got)
	}
	if got := admin.call("POST", "/api/v1/me", map[string]any{}, 405); got["error"] != "method_not_allowed" {
		t.Errorf("wrong method: %v", got)
	}
	if got := admin.call("POST", "/api/v1/groups", map[string]any{"key": "x1", "display_name": "x", "colour": "red"}, 400); !strings.Contains(str(got["message"]), "colour") {
		t.Errorf("unknown field: %v", got)
	}
	seeded, _, _ := db.GetAccountByUsername("admin")
	admin.call("DELETE", "/api/v1/accounts/"+seeded.ID, nil, 204)
	root, _, _ := db.GetAccountByUsername("root")
	if got := admin.call("DELETE", "/api/v1/accounts/"+root.ID, nil, 409); got["error"] != "last_admin" {
		t.Errorf("last admin: %v", got)
	}
}

// Covers: A27
func TestE2ESingleAppGroupsThroughTheAPI(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	grafana, _ := testutil.CreateApp(t, "grafana", testutil.AppOptions{})
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})
	admin := newBrowser(t)
	admin.mustLogin("root")

	g := admin.call("POST", "/api/v1/groups", map[string]any{"key": "grafana-admins", "display_name": "Grafana admins",
		"bound_app_id": grafana.ID}, 201)
	if g["single_app"] != true || g["bound_app_id"] != grafana.ID {
		t.Fatalf("created group: %v", g)
	}
	if ids, _ := g["app_ids"].([]any); len(ids) != 1 || ids[0] != grafana.ID {
		t.Errorf("a bound group must be linked to its app: %v", g["app_ids"])
	}
	resp := admin.sendJSON("PUT", "/api/v1/apps/"+wiki.ID+"/access", map[string]any{"access_rule": "groups", "group_ids": []string{str(g["id"])}})
	wantStatus(t, resp, http.StatusConflict)
	if body := decodeMap(t, resp); body["error"] != "group_bound" {
		t.Errorf("linking a bound group elsewhere: %v", body)
	}

	plain := admin.call("POST", "/api/v1/groups", map[string]any{"key": "readers", "display_name": "Readers"}, 201)
	if plain["single_app"] != false {
		t.Errorf("a plain group: %v", plain)
	}
	admin.call("PUT", "/api/v1/apps/"+wiki.ID+"/access", map[string]any{"access_rule": "groups", "group_ids": []string{str(plain["id"])}}, 200)
	resp = admin.sendJSON("POST", "/api/v1/groups/"+str(plain["id"])+"/bind", map[string]any{"app_id": grafana.ID})
	wantStatus(t, resp, http.StatusConflict)
	if body := decodeMap(t, resp); body["error"] != "linked_elsewhere" {
		t.Errorf("binding a group linked elsewhere: %v", body)
	}
	bound := admin.call("POST", "/api/v1/groups/"+str(plain["id"])+"/bind", map[string]any{"app_id": wiki.ID}, 200)
	if bound["bound_app_id"] != wiki.ID {
		t.Errorf("bound group: %v", bound)
	}
	resp = admin.sendJSON("POST", "/api/v1/groups/"+str(plain["id"])+"/bind", map[string]any{"app_id": grafana.ID})
	wantStatus(t, resp, http.StatusConflict)
	if body := decodeMap(t, resp); body["error"] != "already_bound" {
		t.Errorf("binding again: %v", body)
	}

	// group owners cannot bind; deleting the app leaves the group bound to nothing
	user := newBrowser(t)
	testutil.CreateAccount(t, "plainuser")
	user.mustLogin("plainuser")
	resp = user.sendJSON("POST", "/api/v1/groups/"+str(g["id"])+"/bind", map[string]any{"app_id": wiki.ID})
	wantStatus(t, resp, http.StatusForbidden)
	drain(resp)
	admin.call("DELETE", "/api/v1/apps/"+grafana.ID, nil, 204)
	after := admin.call("GET", "/api/v1/groups/"+str(g["id"]), nil, 200)
	if after["single_app"] != true || after["bound_app_id"] != nil || after["bound_app_deleted_at"] == nil {
		t.Errorf("after deleting its app: %v", after)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'group.bound'`); n != 1 {
		t.Errorf("%d bindings audited, want 1", n)
	}
}

// Deleting an app removes its secrets, tokens, consents, scopes and group links, and its users and
// sessions forget it; its single-app groups stay, marked as bound to a deleted app (A27).
//
// Covers: A25
func TestE2EDeletingAnAppRemovesEverythingItHeld(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "rauru")
	testutil.CreateAccount(t, "tulin")
	app, secret := testutil.CreateApp(t, "wiki", testutil.AppOptions{FirstParty: true})
	user := newBrowser(t)
	user.mustLogin("tulin")
	tokens := user.signIn(app, secret, "tulin", "openid profile")
	testutil.Exec(t, `INSERT INTO account_consent (account_id, app_id, scopes) SELECT id, $1, ARRAY['openid'] FROM account WHERE username = 'tulin'
		ON CONFLICT DO NOTHING`, app.ID)

	tables := []string{"app_secret", "app_scope", "account_consent", "app_group", "authorization_code", "refresh_token", "app_user", "session_app"}
	held := func() map[string]int {
		out := map[string]int{}
		for _, table := range tables {
			out[table] = testutil.Count(t, `SELECT count(*) FROM `+table+` WHERE app_id = $1`, app.ID)
		}
		return out
	}
	if h := held(); h["app_secret"] == 0 || h["refresh_token"] == 0 || h["account_consent"] == 0 {
		t.Fatalf("before deleting, the app should hold a secret, a refresh token and a consent: %v", h)
	}
	admin := newBrowser(t)
	admin.mustLogin("rauru")
	admin.call("DELETE", "/api/v1/apps/"+app.ID, nil, 204)
	for table, n := range held() {
		if n != 0 {
			t.Errorf("%d rows of %s remain after deleting the app", n, table)
		}
	}
	if status, body := refreshRequest(t, app, secret, tokens.Refresh); status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Errorf("a deleted app's refresh: %d %v", status, body)
	}
	admin.call("GET", "/api/v1/apps/"+app.ID, nil, 404)
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'app.removed'`); n != 1 {
		t.Errorf("%d app removals audited", n)
	}
}
