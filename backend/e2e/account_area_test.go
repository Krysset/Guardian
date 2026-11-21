package e2e

import (
	"net/http"
	"testing"

	"guardian/internal/testutil"
)

// The routes behind Home and the account area (0.4 part 2): Home's apps, connected apps, sessions, the
// email address, and groups with their owners' page.

func names(list []any, field string) []string {
	var out []string
	for _, v := range list {
		out = append(out, str(v.(map[string]any)[field]))
	}
	return out
}

// Covers: U13, U20
func TestE2EHomeAndConnectedApps(t *testing.T) {
	newTestEnv(t)
	notes, notesSecret := testutil.CreateApp(t, "notes", testutil.AppOptions{})
	testutil.CreateApp(t, "wiki", testutil.AppOptions{FirstParty: true})
	testutil.CreateApp(t, "hidden", testutil.AppOptions{}) // no homepage: not on Home
	testutil.Exec(t, `UPDATE app SET homepage_url = 'https://' || name || '.test/' WHERE name IN ('notes', 'wiki')`)
	acct := testutil.CreateAccount(t, "sidon")
	br := newBrowser(t)
	br.mustLogin("sidon")

	home := br.call("GET", "/api/v1/me/home", nil, 200)
	if str(home["site_name"]) == "" || len(home["connected"].([]any)) != 0 ||
		!equal(names(home["available"].([]any), "display_name"), []string{"App notes", "App wiki"}) {
		t.Fatalf("home before any sign-in: %v", home)
	}

	// The user agreed to these scopes on the consent page earlier.
	testutil.Exec(t, `INSERT INTO account_consent (account_id, app_id, scopes) VALUES ($1, $2, '{openid,profile,offline_access}')`, acct.ID, notes.ID)
	tokens := br.signIn(notes, notesSecret, "sidon", "openid profile offline_access")
	home = br.call("GET", "/api/v1/me/home", nil, 200)
	if !equal(names(home["connected"].([]any), "display_name"), []string{"App notes"}) ||
		!equal(names(home["available"].([]any), "display_name"), []string{"App wiki"}) {
		t.Fatalf("home after signing in to notes: %v", home)
	}

	apps := items(t, br.call("GET", "/api/v1/me/apps", nil, 200))
	if len(apps) != 1 || apps[0]["name"] != "notes" || apps[0]["first_used_at"] == nil {
		t.Fatalf("connected apps: %v", apps)
	}
	if sees := apps[0]["sees"].([]any); len(sees) != 3 || str(sees[0]) != "Who you are: your account id" {
		t.Errorf("what the app sees: %v", sees)
	}

	// Removing access is a protected change.
	ageSessions(t, acct.ID)
	if m := br.call("DELETE", "/api/v1/me/apps/"+notes.ID, nil, 403); m["error"] != "reauth_required" {
		t.Fatalf("remove without a recent sign-in: %v", m)
	}
	br.call("POST", "/api/v1/me/reauth", map[string]any{"password": testutil.DefaultPassword}, 200)
	br.call("DELETE", "/api/v1/me/apps/"+notes.ID, nil, 204)
	refreshRefused(t, notes, notesSecret, tokens.Refresh)
	if testutil.Count(t, `SELECT count(*) FROM account_consent WHERE account_id = $1`, acct.ID) != 0 ||
		testutil.Count(t, `SELECT count(*) FROM app_user WHERE account_id = $1`, acct.ID) != 0 {
		t.Error("the consent or the app's right to look the user up survived")
	}
	if len(items(t, br.call("GET", "/api/v1/me/apps", nil, 200))) != 0 {
		t.Error("the app is still listed")
	}
	br.call("DELETE", "/api/v1/me/apps/"+notes.ID, nil, 404)
	br.call("DELETE", "/api/v1/me/apps/not-a-uuid", nil, 404)
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'app.access_removed'`) != 1 {
		t.Error("removing access is not audited")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Covers: U12
func TestE2EMySessions(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "riju")
	testutil.CreateAccount(t, "buliara")
	laptop, phone, tablet := newBrowser(t), newBrowser(t), newBrowser(t)
	for _, b := range []*browser{laptop, phone, tablet} {
		b.mustLogin("riju")
	}
	other := newBrowser(t)
	other.mustLogin("buliara")

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
	resp := laptop.sendJSON("GET", "/api/v1/me/sessions", nil, "User-Agent", ua)
	wantStatus(t, resp, 200)
	sessions := items(t, decodeMap(t, resp))
	if len(sessions) != 3 {
		t.Fatalf("sessions: %v", sessions)
	}
	var current, phoneID string
	for _, s := range sessions {
		if s["current"] == true {
			current = str(s["id"])
		}
		if s["ip_address"] == "" || s["browser"] == "" || s["created_at"] == nil {
			t.Errorf("session without details: %v", s)
		}
	}
	if current == "" {
		t.Fatal("no session is marked as the current one")
	}
	// Find the phone's session: the one that is neither current nor the tablet's.
	tabletID := str(items(t, tablet.call("GET", "/api/v1/me/sessions", nil, 200))[0]["id"])
	for _, s := range items(t, tablet.call("GET", "/api/v1/me/sessions", nil, 200)) {
		if s["current"] == true {
			tabletID = str(s["id"])
		}
	}
	for _, s := range sessions {
		if id := str(s["id"]); id != current && id != tabletID {
			phoneID = id
		}
	}

	// Another account's session is not found, and ending sessions is a protected change.
	otherID := ""
	for _, s := range items(t, other.call("GET", "/api/v1/me/sessions", nil, 200)) {
		otherID = str(s["id"])
	}
	laptop.call("DELETE", "/api/v1/me/sessions/"+otherID, nil, 404)
	other.call("GET", "/api/v1/me", nil, 200)
	ageSessions(t, acct.ID)
	if m := laptop.call("DELETE", "/api/v1/me/sessions/"+phoneID, nil, 403); m["error"] != "reauth_required" {
		t.Fatalf("ending a session without a recent sign-in: %v", m)
	}
	laptop.call("POST", "/api/v1/me/reauth", map[string]any{"password": testutil.DefaultPassword}, 200)

	laptop.call("DELETE", "/api/v1/me/sessions/"+phoneID, nil, 204)
	phone.call("GET", "/api/v1/me", nil, 401)
	tablet.call("GET", "/api/v1/me", nil, 200)

	laptop.call("DELETE", "/api/v1/me/sessions", nil, 204)
	tablet.call("GET", "/api/v1/me", nil, 401)
	if n := len(items(t, laptop.call("GET", "/api/v1/me/sessions", nil, 200))); n != 1 {
		t.Errorf("after signing out everywhere else: %d sessions", n)
	}

	// Ending the current session signs out.
	laptop.call("DELETE", "/api/v1/me/sessions/"+current, nil, 204)
	laptop.call("GET", "/api/v1/me", nil, 401)
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type IN ('session.revoked', 'session.revoked_others')`) != 3 {
		t.Error("ending sessions is not audited")
	}
}

// Covers: U9
func TestE2EMyEmailAddress(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "kass")
	setEmail(t, "kass", "kass@rito.example")
	br := newBrowser(t)
	br.mustLogin("kass")

	me := br.call("GET", "/api/v1/me", nil, 200)
	settings := me["email_settings"].(map[string]any)
	if settings["enabled"] != true || settings["required"] != false || settings["pending"] != nil {
		t.Fatalf("email settings: %v", settings)
	}

	br.call("PUT", "/api/v1/me/email", map[string]any{"email": "kass@tabantha.example"}, 202)
	settings = br.call("GET", "/api/v1/me", nil, 200)["email_settings"].(map[string]any)
	if settings["pending"] != "kass@tabantha.example" || settings["pending_until"] == nil {
		t.Fatalf("the new address is not pending: %v", settings)
	}
	link := linkIn(t, "kass@tabantha.example", "Confirm")

	br.call("DELETE", "/api/v1/me/email/pending", nil, 204)
	br.call("DELETE", "/api/v1/me/email/pending", nil, 404)
	if settings = br.call("GET", "/api/v1/me", nil, 200)["email_settings"].(map[string]any); settings["pending"] != nil {
		t.Errorf("still pending after cancelling: %v", settings)
	}
	// The cancelled link no longer changes the address.
	drain(br.get(link))
	if m := br.call("GET", "/api/v1/me", nil, 200); m["email"] != "kass@rito.example" {
		t.Errorf("a cancelled link changed the address: %v", m["email"])
	}

	ageSessions(t, acct.ID)
	if m := br.call("DELETE", "/api/v1/me/email", nil, 403); m["error"] != "reauth_required" {
		t.Fatalf("removing the address without a recent sign-in: %v", m)
	}
	br.call("POST", "/api/v1/me/reauth", map[string]any{"password": testutil.DefaultPassword}, 200)
	br.call("DELETE", "/api/v1/me/email", nil, 204)
	if m := br.call("GET", "/api/v1/me", nil, 200); m["email"] != nil || m["email_verified"] != false {
		t.Errorf("after removing the address: %v %v", m["email"], m["email_verified"])
	}
}

// Covers: U18, O1, O2, O3, O5
func TestE2EMyGroupsAndAddingMembersByLogin(t *testing.T) {
	newTestEnv(t)
	app, _ := testutil.CreateApp(t, "notes", testutil.AppOptions{})
	owner := testutil.CreateAccount(t, "yunobo")
	testutil.CreateAccount(t, "teba")
	setEmail(t, "teba", "teba@rito.example")
	testutil.CreateAccount(t, "outsider")
	owners := testutil.Group(t, "goron-leads", "")
	team := testutil.Group(t, "goron-team", owners)
	testutil.AddMember(t, owners, owner.ID)
	testutil.Exec(t, `INSERT INTO app_group (app_id, group_id) VALUES ($1, $2)`, app.ID, team)
	testutil.Exec(t, `UPDATE user_group SET display_name = 'Goron team' WHERE id = $1`, team)

	br := newBrowser(t)
	br.mustLogin("yunobo") // group owners set up two-factor at sign-in
	mine := br.call("GET", "/api/v1/me/groups", nil, 200)
	if !equal(names(mine["member_of"].([]any), "id"), []string{owners}) {
		t.Errorf("member of: %v", mine["member_of"])
	}
	manages := mine["manages"].([]any)
	if len(manages) != 1 {
		t.Fatalf("manages: %v", manages)
	}
	if g := manages[0].(map[string]any); g["display_name"] != "Goron team" || g["member_count"] != 0.0 ||
		len(g["apps"].([]any)) != 1 || g["apps"].([]any)[0] != "App notes" {
		t.Errorf("managed group: %v", g)
	}

	path := "/api/v1/groups/" + team + "/members"
	if m := br.call("POST", path, map[string]any{"login": "nobody"}, 404); m["message"] != "No user found" {
		t.Errorf("unknown login: %v", m)
	}
	br.call("POST", path, map[string]any{"login": "TEBA@rito.example"}, 200)
	added := br.call("POST", path, map[string]any{"login": "outsider", "expires_at": "2099-01-01T00:00:00Z"}, 200)
	if added["username"] != "outsider" {
		t.Errorf("added: %v", added)
	}
	members := items(t, br.call("GET", path, nil, 200))
	if len(members) != 2 {
		t.Fatalf("members: %v", members)
	}
	br.call("POST", path, map[string]any{"login": "teba", "expires_at": "2000-01-01T00:00:00Z"}, 400)

	// Someone who does not own the group may not add to it.
	stranger := newBrowser(t)
	stranger.mustLogin("teba")
	stranger.call("POST", path, map[string]any{"login": "outsider"}, 403)
	if g := stranger.call("GET", "/api/v1/me/groups", nil, 200); len(g["manages"].([]any)) != 0 ||
		!equal(names(g["member_of"].([]any), "id"), []string{team}) {
		t.Errorf("a member's own groups: %v", g)
	}
}

// A user changes their username: they sign in with the new one, the old one is free again, a taken or
// malformed name is refused, and the change is audited. Apps keep knowing the account by its id.
//
// Covers: U8
func TestE2EChangingYourUsername(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "kass")
	testutil.CreateAccount(t, "teba")
	app, secret := testutil.CreateApp(t, "notes", testutil.AppOptions{FirstParty: true})
	br := newBrowser(t)
	br.mustLogin("kass")
	before := verifyAccessToken(t, app, br.signIn(app, secret, "kass", "openid profile").Access)

	if got := br.call("PATCH", "/api/v1/me", map[string]any{"username": "Teba"}, 409); got["error"] != "username_taken" {
		t.Errorf("a taken username (in other letter case): %v", got)
	}
	br.call("PATCH", "/api/v1/me", map[string]any{"username": "no spaces allowed"}, 400)
	if got := br.call("PATCH", "/api/v1/me", map[string]any{"username": "kass-the-bard"}, 200); got["username"] != "kass-the-bard" {
		t.Fatalf("after changing the username: %v", got)
	}

	other := newBrowser(t)
	resp := other.login("kass", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)
	other.mustLogin("kass-the-bard")
	after := verifyAccessToken(t, app, other.signIn(app, secret, "kass-the-bard", "openid profile").Access)
	if before["sub"] != after["sub"] || after["sub"] != acct.ID {
		t.Errorf("the account's id changed with its name: %v, %v", before["sub"], after["sub"])
	}
	testutil.CreateAccount(t, "kass") // the old name is free again
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'account.username_changed' AND metadata->>'username' = 'kass-the-bard'`); n != 1 {
		t.Errorf("%d username changes audited", n)
	}
}
