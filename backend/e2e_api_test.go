package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	db "guardian/database"
	"guardian/internal/testutil"
)

// The core requirement: permission changes are visible to the very next introspection.
func TestE2EPermissionChangesByAnAdminAreImmediate(t *testing.T) {
	testutil.Reset(t)
	svc, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	approve := testutil.Permission(t, svc.ID, "invoices.approve")
	read := testutil.Permission(t, svc.ID, "invoices.read")
	role := testutil.Role(t, "approvers", false, approve)
	testutil.AdminAccount(t, "root")
	user := testutil.CreateAccount(t, "dave")

	admin := newBrowser(t)
	admin.mustLogin("root")
	ub := newBrowser(t)
	tok := ub.signIn(svc, secret, "dave", "openid")

	perms := func() []string { return permList(mustActive(t, svc, secret, tok.Access)) }
	api := func(path string, body map[string]any) {
		t.Helper()
		resp := admin.postJSON("/api/access/"+path, body)
		wantStatus(t, resp, 200)
		drain(resp)
	}
	if len(perms()) != 0 {
		t.Fatalf("a new user must hold nothing: %v", perms())
	}

	api("grant-role", map[string]any{"account_id": user.ID, "role_id": role})
	if got := perms(); len(got) != 1 || got[0] != "invoices.approve" {
		t.Fatalf("after granting the role: %v", got)
	}
	api("revoke-role", map[string]any{"account_id": user.ID, "role_id": role})
	if len(perms()) != 0 {
		t.Fatalf("after revoking the role the permission must be gone at once: %v", perms())
	}

	// direct grant with app-defined attributes
	api("grant-permission", map[string]any{"account_id": user.ID, "permission_id": read, "attributes": map[string]any{"limit": 5000}})
	m := mustActive(t, svc, secret, tok.Access)
	attrs, _ := m["attributes"].(map[string]any)
	if got := permList(m); len(got) != 1 || got[0] != "invoices.read" {
		t.Fatalf("direct grant: %v", got)
	}
	if one, _ := attrs["invoices.read"].(map[string]any); one["limit"] != float64(5000) {
		t.Errorf("attributes = %v", m["attributes"])
	}

	// changing a role's permission set applies to its holders immediately; direct and role grants combine
	api("grant-role", map[string]any{"account_id": user.ID, "role_id": role})
	api("roles/permissions", map[string]any{"role_id": role, "permission_ids": []string{read}})
	if got := perms(); len(got) != 1 || got[0] != "invoices.read" {
		t.Fatalf("after replacing the role's permissions: %v", got)
	}
	api("revoke-permission", map[string]any{"account_id": user.ID, "permission_id": read})
	if got := perms(); len(got) != 1 {
		t.Fatalf("the role must still provide the permission: %v", got)
	}
	api("revoke-role", map[string]any{"account_id": user.ID, "role_id": role})
	if len(perms()) != 0 {
		t.Fatalf("everything revoked: %v", perms())
	}

	// expired grants are inert; deleting a role removes it from holders
	resp := admin.postJSON("/api/access/grant-role", map[string]any{"account_id": user.ID, "role_id": role, "expires_at": "2000-01-01T00:00:00Z"})
	wantStatus(t, resp, 200)
	drain(resp)
	if len(perms()) != 0 {
		t.Error("an already-expired role grant is effective")
	}
	api("grant-role", map[string]any{"account_id": user.ID, "role_id": role})
	api("roles/delete", map[string]any{"role_id": role})
	if len(perms()) != 0 {
		t.Error("a deleted role still grants permissions")
	}

	// every change was audited
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type IN ('role.granted','role.revoked','permission.granted','permission.revoked','role.permissions_set','role.deleted')`); n < 8 {
		t.Errorf("only %d audit entries for the permission changes", n)
	}
}

func TestE2EAccessAPIRequiresThePermissionsManagePermission(t *testing.T) {
	testutil.Reset(t)
	plainAcct := testutil.CreateAccount(t, "plain")
	testutil.AdminAccount(t, "root")
	adminRole := testutil.RoleID(t, "admin")

	anon := newBrowser(t)
	plain := newBrowser(t)
	plain.mustLogin("plain")
	admin := newBrowser(t)
	admin.mustLogin("root")

	for _, path := range []string{"/api/access/roles", "/api/access/permissions"} {
		r := anon.get(path)
		wantStatus(t, r, http.StatusUnauthorized)
		drain(r)
		r = plain.get(path)
		wantStatus(t, r, http.StatusForbidden)
		drain(r)
		r = admin.get(path)
		wantStatus(t, r, 200)
		drain(r)
	}
	for _, c := range []struct {
		b    *browser
		want int
	}{{anon, 401}, {plain, 403}} {
		r := c.b.postJSON("/api/access/grant-role", map[string]any{"account_id": adminRole, "role_id": adminRole})
		wantStatus(t, r, c.want)
		drain(r)
	}

	// the built-in admin role cannot be deleted or edited, even by an admin
	r := admin.postJSON("/api/access/roles/delete", map[string]any{"role_id": adminRole})
	wantStatus(t, r, http.StatusForbidden)
	drain(r)
	r = admin.postJSON("/api/access/roles/permissions", map[string]any{"role_id": adminRole, "permission_ids": []string{}})
	wantStatus(t, r, http.StatusForbidden)
	drain(r)

	resp := admin.get("/api/access/roles")
	if body := readBody(t, resp); !strings.Contains(body, `"name":"admin"`) {
		t.Errorf("roles listing lacks admin: %.200s", body)
	}

	// permissions are checked individually: holding permissions.manage opens the access API (at once, on the
	// same session) but not app management, which needs apps.manage
	perms, err := db.ListAppPermissions()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range perms {
		if p.AppName == "guardian" && p.Name == "permissions.manage" {
			if err := db.GrantPermission(plainAcct.ID, p.ID, "", "", nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	r = plain.get("/api/access/roles")
	wantStatus(t, r, 200)
	drain(r)
	r = plain.postJSON("/api/service/add", map[string]any{"name": "x1", "pretty_name": "x", "redirect_uris": []string{"https://x1.test/cb"}})
	wantStatus(t, r, http.StatusForbidden)
	drain(r)
}

func mustGuardianID(t *testing.T) string {
	t.Helper()
	apps, err := db.GetApps()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps {
		if a.Name == "guardian" {
			return a.ID
		}
	}
	t.Fatal("guardian app not seeded")
	return ""
}

func TestE2EIntrospectionAuthenticationAndBoundaries(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	a, secA := testutil.CreateApp(t, "appa", testutil.AppOptions{FirstParty: true})
	bApp, secB := testutil.CreateApp(t, "appb", testutil.AppOptions{FirstParty: true})
	pa := testutil.Permission(t, a.ID, "a.perm")
	pb := testutil.Permission(t, bApp.ID, "b.perm")
	user, _, _ := db.GetAccountByUsername("alice")
	for _, p := range []string{pa, pb} {
		if err := db.GrantPermission(user.ID, p, "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	br := newBrowser(t)
	tok := br.signIn(a, secA, "alice", "openid profile")

	// the answer reveals only what a service needs, nothing about the user's profile
	m := mustActive(t, a, secA, tok.Access)
	for _, k := range []string{"sub", "client_id", "scope", "token_type", "iat", "exp", "permissions", "sid"} {
		if m[k] == nil {
			t.Errorf("introspection response lacks %q: %v", k, m)
		}
	}
	for _, leaked := range []string{"email", "name", "username", "preferred_username"} {
		if _, ok := m[leaked]; ok {
			t.Errorf("introspection leaked %q", leaked)
		}
	}

	// another service gets ITS permissions for the same user, and learns which app the token belongs to
	other := mustActive(t, bApp, secB, tok.Access)
	if got := permList(other); len(got) != 1 || got[0] != "b.perm" || other["client_id"] != a.ClientID {
		t.Errorf("app B sees %v / client_id %v", got, other["client_id"])
	}
	if got := permList(m); len(got) != 1 || got[0] != "a.perm" {
		t.Errorf("app A sees %v", got)
	}

	// caller authentication
	if status, _ := introspectToken(t, a, "wrong-secret", tok.Access); status != http.StatusUnauthorized {
		t.Errorf("wrong secret: %d", status)
	}
	if status, _ := introspectToken(t, a, "", tok.Access); status != http.StatusUnauthorized {
		t.Errorf("no credentials: %d", status)
	}
	if status, _ := introspectToken(t, a, secB, tok.Access); status != http.StatusUnauthorized {
		t.Errorf("another app's secret: %d", status)
	}
	mustInactive(t, a, secA, "garbage-token")
	for _, blank := range []string{"", " "} {
		if status, m := introspectToken(t, a, secA, blank); status != http.StatusBadRequest {
			t.Errorf("blank token %q: %d %v, want 400", blank, status, m)
		}
	}

	// introspection exists only on the internal listener
	for _, path := range []string{"/introspect", "/metrics", "/healthz", "/readyz"} {
		r := br.get(path)
		if r.StatusCode != http.StatusNotFound && r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("public listener answers %s with %d", path, r.StatusCode)
		}
		drain(r)
	}
	req, _ := http.NewRequest("POST", pubSrv.URL+"/introspect", strings.NewReader("token="+tok.Access))
	req.SetBasicAuth(a.ClientID, secA)
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusNotFound {
		t.Errorf("POST /introspect on the public listener must be 404")
	}

	// token client authentication at /token
	status, body := tokenRequest(t, a, "wrong", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Errorf("/token with a wrong secret: %d %v", status, body)
	}
}

func TestE2EDisablingAnAppKillsItsTokensAndLogins(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	a, secA := testutil.CreateApp(t, "appa", testutil.AppOptions{FirstParty: true})
	b2, secB := testutil.CreateApp(t, "appb", testutil.AppOptions{FirstParty: true})
	br := newBrowser(t)
	tokA := br.signIn(a, secA, "alice", "openid offline_access")
	tokB := br.signIn(b2, secB, "alice", "openid")

	testutil.Exec(t, `UPDATE app SET enabled = FALSE WHERE id = $1`, a.ID)
	mustInactive(t, b2, secB, tokA.Access) // tokens of a disabled app are dead
	mustActive(t, b2, secB, tokB.Access)   // other apps are unaffected
	if status, _ := introspectToken(t, a, secA, tokB.Access); status != http.StatusUnauthorized {
		t.Errorf("a disabled app must not authenticate, got %d", status)
	}
	if status, _ := userinfoStatus(t, tokA.Access); status != http.StatusUnauthorized {
		t.Errorf("userinfo for a disabled app's token = %d", status)
	}
	if status, _ := refreshRequest(t, a, secA, tokA.Refresh); status != http.StatusUnauthorized {
		t.Errorf("a disabled app refreshed tokens: %d", status)
	}
	resp := br.get("/authorize?" + authParams{app: a, state: "s", challenge: strings.Repeat("a", 43)}.values().Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("authorize for a disabled app = %d", resp.StatusCode)
	}
	drain(resp)
}

func TestE2ESignUpIsOpenButRateLimited(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	admin := newBrowser(t)
	admin.mustLogin("root")
	anon := newBrowser(t)
	register := func(name string) *http.Response {
		return anon.postJSON("/api/account/register", map[string]any{"username": name, "password": testutil.DefaultPassword})
	}

	for i := 1; i <= 10; i++ {
		resp := register(fmt.Sprintf("user%02d", i))
		wantStatus(t, resp, http.StatusCreated)
		drain(resp)
	}
	resp := register("user11")
	wantStatus(t, resp, http.StatusTooManyRequests)
	if resp.Header.Get("Retry-After") != "3600" {
		t.Errorf("Retry-After = %q", resp.Header.Get("Retry-After"))
	}
	drain(resp)
	if testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'user11'`) != 0 {
		t.Error("a rate-limited sign-up must not create the account")
	}
	if n := testutil.Count(t, `SELECT hits FROM rate_limit WHERE key LIKE 'register:ip:%'`); n < 11 {
		t.Errorf("counter = %d", n)
	}

	// administrators can still add accounts
	ar := admin.postJSON("/api/account/add", map[string]any{"username": "added-by-admin", "password": testutil.DefaultPassword})
	wantStatus(t, ar, http.StatusCreated)
	drain(ar)

	// the throttling is visible in the metrics
	m := readBody(t, mustGet(t, intSrv.URL+"/metrics"))
	if !strings.Contains(m, `guardian_rate_limited_total{endpoint="register"}`) {
		t.Error("rate_limited_total{endpoint=register} missing from /metrics")
	}
}

func TestE2ESignUpValidation(t *testing.T) {
	testutil.Reset(t)
	anon := newBrowser(t)
	post := func(user, pw string) *http.Response {
		return anon.postJSON("/api/account/register", map[string]any{"username": user, "password": pw})
	}
	ok := post("Alice", testutil.DefaultPassword)
	wantStatus(t, ok, http.StatusCreated)
	acct := decodeMap(t, ok)
	if acct["username"] != "Alice" || acct["status"] != "active" {
		t.Errorf("created account = %v", acct)
	}
	if _, leaked := acct["password"]; leaked {
		t.Error("the response must never contain password material")
	}
	if strings.Contains(fmt.Sprint(acct), "argon2") {
		t.Error("password hash leaked in the response")
	}
	for name, resp := range map[string]*http.Response{
		"duplicate, other case": post("ALICE", testutil.DefaultPassword),
		"short password":        post("bob", "short"),
		"bad username":          post("b b", testutil.DefaultPassword),
	} {
		want := http.StatusBadRequest
		if strings.HasPrefix(name, "duplicate") {
			want = http.StatusConflict
		}
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", name, resp.StatusCode, want)
		}
		drain(resp)
	}
	// the new account can log in with the password it signed up with
	br := newBrowser(t)
	br.mustLogin("alice")
}

func TestE2ELoginThrottlingAndNoUserEnumeration(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "carol")
	testutil.CreateAccount(t, "dave")
	br := newBrowser(t)
	failures := func(user string) string {
		resp := br.login(user, "wrong-password-123", "")
		wantStatus(t, resp, http.StatusUnauthorized)
		return readBody(t, resp)
	}

	// unknown user and wrong password are indistinguishable
	known, unknown := failures("carol"), failures("no-such-user")
	if !strings.Contains(known, "Invalid username or password.") || !strings.Contains(unknown, "Invalid username or password.") {
		t.Error("login failure message missing")
	}
	for i := 0; i < 8; i++ { // carol now has 9 failures
		failures("carol")
	}
	failures("carol") // the 10th

	// from now on even the correct password is refused for that username
	resp := br.login("carol", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusTooManyRequests)
	drain(resp)
	if testutil.Count(t, `SELECT hits FROM rate_limit WHERE key = 'login:user:carol'`) != 10 {
		t.Error("failed attempts were not counted per username")
	}
	// other users are unaffected (the IP budget is larger)
	br2 := newBrowser(t)
	br2.mustLogin("dave")

	// a successful login clears that user's failure counter
	testutil.CreateAccount(t, "erin")
	failures("erin")
	failures("erin")
	br3 := newBrowser(t)
	br3.mustLogin("erin")
	if testutil.Count(t, `SELECT count(*) FROM rate_limit WHERE key = 'login:user:erin'`) != 0 {
		t.Error("a successful login must reset the failure counter")
	}
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'login.failure'`) < 12 {
		t.Error("failed logins must be audited")
	}
}

func TestE2ECSRFProtections(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	br := newBrowser(t)

	// HTML forms need the double-submit token
	noToken := br.postForm("/login", url.Values{"username": {"alice"}, "password": {testutil.DefaultPassword}})
	wantStatus(t, noToken, http.StatusForbidden)
	drain(noToken)
	br.csrf() // gets the cookie
	wrong := br.postForm("/login", url.Values{"csrf": {strings.Repeat("z", 43)}, "username": {"alice"}, "password": {testutil.DefaultPassword}})
	wantStatus(t, wrong, http.StatusForbidden)
	drain(wrong)
	if br.cookie("guardian_session") != "" {
		t.Fatal("a rejected login created a session")
	}

	br.mustLogin("alice")
	noLogoutToken := br.postForm("/logout", url.Values{})
	wantStatus(t, noLogoutToken, http.StatusForbidden)
	drain(noLogoutToken)
	if r := br.get("/api/account/me"); r.StatusCode != 200 {
		t.Error("a CSRF-rejected logout must not end the session")
	} else {
		drain(r)
	}

	// JSON API: cross-site browser requests are blocked, same-origin and non-browser requests work
	body := map[string]any{"display_name": "Alice"}
	evil := br.postJSON("/api/account/update", body, "Origin", "https://evil.example")
	wantStatus(t, evil, http.StatusForbidden)
	drain(evil)
	for _, origin := range []string{testIssuer, ""} {
		var resp *http.Response
		if origin == "" {
			resp = br.postJSON("/api/account/update", body)
		} else {
			resp = br.postJSON("/api/account/update", body, "Origin", origin)
		}
		wantStatus(t, resp, 200)
		drain(resp)
	}
}

func TestE2ELoginRedirectsCannotLeaveGuardian(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	for _, returnTo := range []string{"https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)", "/login"} {
		br := newBrowser(t)
		resp := br.login("alice", testutil.DefaultPassword, returnTo)
		wantStatus(t, resp, http.StatusSeeOther)
		if loc := resp.Header.Get("Location"); loc != "/login" {
			t.Errorf("return_to %q redirected to %q", returnTo, loc)
		}
		drain(resp)
	}
}

func TestE2EAccountSelfServiceAPI(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	anon := newBrowser(t)
	for _, p := range []string{"/api/account/me", "/api/service/list"} {
		r := anon.get(p)
		wantStatus(t, r, http.StatusUnauthorized)
		drain(r)
	}
	for _, p := range []string{"/api/account/update", "/api/account/update/username", "/api/account/update/password"} {
		r := anon.postJSON(p, map[string]any{})
		wantStatus(t, r, http.StatusUnauthorized)
		drain(r)
	}

	br := newBrowser(t)
	br.mustLogin("alice")
	update := func(body map[string]any) (int, map[string]any) {
		resp := br.postJSON("/api/account/update", body)
		return resp.StatusCode, decodeMap(t, resp)
	}
	status, got := update(map[string]any{"display_name": "Alice A", "email": "alice@example.com", "locale": "sv-SE"})
	if status != 200 || got["display_name"] != "Alice A" || got["email"] != "alice@example.com" || got["email_verified"] != false {
		t.Fatalf("update: %d %v", status, got)
	}
	if _, got = update(map[string]any{"locale": "en-US"}); got["display_name"] != "Alice A" || got["locale"] != "en-US" {
		t.Errorf("a partial update must leave other fields alone: %v", got)
	}
	if status, _ = update(map[string]any{"picture_url": "http://insecure.example/a.png"}); status != http.StatusBadRequest {
		t.Errorf("non-https picture accepted: %d", status)
	}
	_, got = update(map[string]any{"username": "hacked", "status": "disabled", "id": "x"})
	if got["username"] != "alice" || got["status"] != "active" {
		t.Errorf("mass assignment: protected fields were changed: %v", got)
	}

	// username
	testutil.CreateAccount(t, "taken")
	for body, want := range map[string]int{`taken`: 409, `TAKEN`: 409, `x`: 400, `with space`: 400, `alice2`: 200} {
		resp := br.postJSON("/api/account/update/username", map[string]any{"username": body})
		if resp.StatusCode != want {
			t.Errorf("rename to %q: %d, want %d", body, resp.StatusCode, want)
		}
		drain(resp)
	}

	// password: needs the current one, enforces the length, takes effect immediately
	for _, c := range []struct {
		cur, next string
		want      int
	}{{"wrong-current", "brand-new-password", 403}, {testutil.DefaultPassword, "short", 400}, {testutil.DefaultPassword, "brand-new-password", 200}} {
		resp := br.postJSON("/api/account/update/password", map[string]any{"currentPassword": c.cur, "newPassword": c.next})
		if resp.StatusCode != c.want {
			t.Errorf("password change %+v: %d", c, resp.StatusCode)
		}
		drain(resp)
	}
	fresh := newBrowser(t)
	if r := fresh.login("alice2", testutil.DefaultPassword, ""); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old password still works: %d", r.StatusCode)
	} else {
		drain(r)
	}
	ok := fresh.login("alice2", "brand-new-password", "")
	wantStatus(t, ok, http.StatusSeeOther)
	drain(ok)
}

func TestE2EAdminDeletionLocksTheUserOutImmediately(t *testing.T) {
	testutil.Reset(t)
	victim := testutil.CreateAccount(t, "victim")
	testutil.CreateAccount(t, "bystander")
	testutil.AdminAccount(t, "root")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})

	vb := newBrowser(t)
	tok := vb.signIn(app, secret, "victim", "openid offline_access")
	bb := newBrowser(t)
	bb.mustLogin("bystander")
	admin := newBrowser(t)
	admin.mustLogin("root")

	// not for ordinary users, and not with bad input
	r := bb.postJSON("/api/account/delete", map[string]any{"id": victim.ID})
	wantStatus(t, r, http.StatusForbidden)
	drain(r)
	r = admin.postJSON("/api/account/delete", map[string]any{"id": "not-a-uuid"})
	wantStatus(t, r, http.StatusBadRequest)
	drain(r)
	mustActive(t, app, secret, tok.Access)

	r = admin.postJSON("/api/account/delete", map[string]any{"id": victim.ID})
	wantStatus(t, r, 200)
	drain(r)

	me := vb.get("/api/account/me")
	wantStatus(t, me, http.StatusUnauthorized)
	drain(me)
	mustInactive(t, app, secret, tok.Access)
	if status, _ := refreshRequest(t, app, secret, tok.Refresh); status != 400 {
		t.Errorf("refresh after deletion: %d", status)
	}
	login := newBrowser(t).login("victim", testutil.DefaultPassword, "")
	wantStatus(t, login, http.StatusUnauthorized)
	drain(login)
	// others are untouched
	ok := bb.get("/api/account/me")
	wantStatus(t, ok, 200)
	drain(ok)
}

func TestE2EAppRegistrationAPI(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "plain")
	testutil.AdminAccount(t, "root")
	admin := newBrowser(t)
	admin.mustLogin("root")
	plain := newBrowser(t)
	plain.mustLogin("plain")

	valid := map[string]any{
		"name": "newsvc", "pretty_name": "New service", "description": "d",
		"redirect_uris": []string{"https://newsvc.test/cb"}, "scopes": []string{"openid", "email"},
		"access_token_ttl_seconds": 3600,
	}
	r := plain.postJSON("/api/service/add", valid)
	wantStatus(t, r, http.StatusForbidden)
	drain(r)

	resp := admin.postJSON("/api/service/add", valid)
	wantStatus(t, resp, http.StatusCreated)
	created := decodeMap(t, resp)
	secret := str(created["client_secret"])
	app, _ := created["app"].(map[string]any)
	if len(secret) != 43 || app["client_id"] == nil || app["access_token_ttl_seconds"] != float64(3600) {
		t.Fatalf("created = %v", created)
	}
	if scopes, _ := app["scopes"].([]any); len(scopes) != 2 {
		t.Errorf("scopes = %v", app["scopes"])
	}
	if strings.Contains(fmt.Sprint(app), secret) || testutil.Count(t, `SELECT count(*) FROM app_secret WHERE secret_hash = $1`, secret) != 0 {
		t.Error("the secret must be shown once and stored only as a hash")
	}
	// the returned credentials really work against the internal listener
	registered := db.App{ClientID: str(app["client_id"])}
	mustInactive(t, registered, secret, "garbage")

	// validation and conflicts
	dup := admin.postJSON("/api/service/add", valid)
	wantStatus(t, dup, http.StatusConflict)
	drain(dup)
	bad := map[string]any{"name": "evilsvc", "pretty_name": "x", "redirect_uris": []string{"http://evil.example/cb"}}
	rb := admin.postJSON("/api/service/add", bad)
	wantStatus(t, rb, http.StatusBadRequest)
	drain(rb)
	pub := admin.postJSON("/api/service/add", map[string]any{"name": "spa", "pretty_name": "SPA", "client_type": "public",
		"redirect_uris": []string{"https://spa.test/cb"}})
	wantStatus(t, pub, http.StatusCreated)
	if pc := decodeMap(t, pub); pc["client_secret"] != nil {
		t.Error("a public client must not get a secret")
	}

	// listing: any signed-in user, never any secret material
	list := plain.get("/api/service/list")
	wantStatus(t, list, 200)
	body := readBody(t, list)
	if !strings.Contains(body, "newsvc") || strings.Contains(body, `"client_secret":`) || strings.Contains(body, "secret_hash") {
		t.Errorf("list leaks or lacks data: %.300s", body)
	}
	one := plain.get("/api/service/not-a-uuid")
	wantStatus(t, one, http.StatusNotFound)
	drain(one)

	// removal: the guardian app is protected; removing an app kills its credentials at once
	guardianID := mustGuardianID(t)
	rg := admin.sendJSON("DELETE", "/api/service/remove", map[string]any{"id": guardianID})
	wantStatus(t, rg, http.StatusBadRequest)
	drain(rg)
	rp := plain.sendJSON("DELETE", "/api/service/remove", map[string]any{"id": app["id"]})
	wantStatus(t, rp, http.StatusForbidden)
	drain(rp)
	rm := admin.sendJSON("DELETE", "/api/service/remove", map[string]any{"id": app["id"]})
	wantStatus(t, rm, 200)
	drain(rm)
	if status, _ := introspectToken(t, registered, secret, "garbage"); status != http.StatusUnauthorized {
		t.Errorf("a removed app still authenticates: %d", status)
	}
}

func TestE2EInternalListenerProbesAndMetrics(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	br := newBrowser(t)
	tok := br.signIn(app, secret, "alice", "openid")
	mustActive(t, app, secret, tok.Access)
	mustInactive(t, app, secret, "nope")

	for _, p := range []string{"/healthz", "/readyz"} {
		r := mustGet(t, intSrv.URL+p)
		wantStatus(t, r, 200)
		drain(r)
	}
	m := readBody(t, mustGet(t, intSrv.URL+"/metrics"))
	for _, want := range []string{
		`guardian_introspections_total{result="active"}`, `guardian_introspections_total{result="inactive"}`,
		`guardian_logins_total{result="success"}`, `guardian_http_request_duration_seconds_bucket`,
		`listener="public"`, `listener="internal"`, `route="/introspect"`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("/metrics lacks %s", want)
		}
	}
	// route labels use patterns, so ids never explode the label cardinality
	r := br.get("/api/service/11111111-1111-1111-1111-111111111111")
	drain(r)
	m = readBody(t, mustGet(t, intSrv.URL+"/metrics"))
	if strings.Contains(m, "11111111-1111-1111-1111-111111111111") {
		t.Error("a raw id leaked into a metric label")
	}
}

func mustGet(t *testing.T, u string) *http.Response {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestNewServerSetsTimeouts(t *testing.T) {
	s := newServer(":0", http.NotFoundHandler())
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 {
		t.Errorf("timeouts missing (slowloris protection): %+v", s)
	}
	t.Setenv("SOME_ADDR", "")
	if env("SOME_ADDR", ":1234") != ":1234" {
		t.Error("env default")
	}
	t.Setenv("SOME_ADDR", ":9")
	if env("SOME_ADDR", ":1234") != ":9" {
		t.Error("env override")
	}
}
