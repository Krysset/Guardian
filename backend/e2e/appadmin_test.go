package e2e

import (
	"net/http"
	"testing"

	"guardian/internal/testutil"
)

// An app's admins are the members of its owner group, which only Guardian admins choose. They must use
// two-factor. They see and edit only their apps: settings, enabling, the secret, the access rule, links to
// groups they own (never to or from groups they do not own), and the app's audit entries without IP
// addresses. Creating and deleting apps, choosing an app's admins and the machine API stay with Guardian
// admins.
//
// Covers: A15, A17, A18, A19, A20, A22, A32
func TestE2EAppAdminsManageTheirOwnApps(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	alice := testutil.CreateAccount(t, "alice")
	testutil.CreateAccount(t, "bob")
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{AccessRule: "groups"})
	other, _ := testutil.CreateApp(t, "other", testutil.AppOptions{})
	team := testutil.Group(t, "wiki-team", "")
	editors := testutil.Group(t, "editors", team) // owned by the team
	strangers := testutil.Group(t, "strangers", "")
	testutil.AddMember(t, team, alice.ID)

	root := newBrowser(t)
	root.mustLogin("root")
	root.call("PUT", "/api/v1/apps/"+wiki.ID+"/access", map[string]any{"access_rule": "groups", "group_ids": []string{strangers}}, 200)

	// Before the app has admins, alice is no one's app admin.
	br := newBrowser(t)
	br.mustLogin("alice") // a group owner already, so two-factor is set up here
	if me := br.call("GET", "/api/v1/me", nil, 200); me["app_admin"] != false {
		t.Errorf("app_admin before = %v", me["app_admin"])
	}
	br.call("GET", "/api/v1/apps/"+wiki.ID, nil, 403)

	// Only Guardian admins choose an app's admins.
	root.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"owner_group_id": team}, 200)
	if me := br.call("GET", "/api/v1/me", nil, 200); me["app_admin"] != true {
		t.Errorf("app_admin after = %v", me["app_admin"])
	}
	list := br.call("GET", "/api/v1/apps", nil, 200)
	if apps := items(t, list); len(apps) != 1 || apps[0]["id"] != wiki.ID {
		t.Fatalf("an app admin's apps = %v", apps)
	}
	got := br.call("GET", "/api/v1/apps/"+wiki.ID, nil, 200)
	if linked, _ := got["linked_groups"].([]any); len(linked) != 1 || linked[0].(map[string]any)["key"] != "strangers" {
		t.Errorf("linked_groups = %v", got["linked_groups"])
	}
	br.call("GET", "/api/v1/apps/"+other.ID, nil, 403)
	br.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"owner_group_id": ""}, 403)

	// Settings, enabling and the secret.
	if a := br.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"pretty_name": "Team wiki", "signing_alg": "ES256"}, 200); a["pretty_name"] != "Team wiki" {
		t.Errorf("edit: %v", a)
	}
	// Skipping consent and the scopes are promises to the people signing in: Guardian admins keep them.
	br.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"is_first_party": true}, 403)
	br.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"scopes": []string{"openid"}}, 403)
	current := br.call("GET", "/api/v1/apps/"+wiki.ID, nil, 200)
	br.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"is_first_party": current["is_first_party"], "scopes": current["scopes"]}, 200)
	br.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"enabled": false}, 200)
	br.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"enabled": true}, 200)
	br.call("POST", "/api/v1/apps/"+wiki.ID+"/secret", map[string]any{"grace_seconds": 3600}, 201)

	// Links: their own groups only, and the others stay as they are.
	access := func(rule string, groups []string, want int) map[string]any {
		t.Helper()
		return br.call("PUT", "/api/v1/apps/"+wiki.ID+"/access", map[string]any{"access_rule": rule, "group_ids": groups}, want)
	}
	if body := access("groups", []string{strangers, editors}, 200); len(body["group_ids"].([]any)) != 2 {
		t.Errorf("linking their own group: %v", body)
	}
	resp := br.sendJSON("PUT", "/api/v1/apps/"+wiki.ID+"/access", map[string]any{"access_rule": "groups", "group_ids": []string{editors}})
	wantStatus(t, resp, http.StatusForbidden)
	if body := decodeMap(t, resp); body["error"] != "not_group_owner" {
		t.Errorf("unlinking a group they do not own: %v", body)
	}
	access("groups", []string{strangers, editors, team}, 403) // the owner group itself is not theirs to link
	access("groups", []string{strangers}, 200)                // unlinking their own
	access("anyone", []string{strangers}, 200)                // the rule is theirs to set
	br.call("PUT", "/api/v1/apps/"+wiki.ID+"/access", map[string]any{"access_rule": "groups", "group_ids": []string{strangers}, "machine_api": true}, 403)

	// The audit entries of their app, without addresses.
	entries := items(t, br.call("GET", "/api/v1/audit?app="+wiki.ID, nil, 200))
	if len(entries) == 0 {
		t.Fatal("no audit entries for the app")
	}
	for _, e := range entries {
		if e["ip_address"] != nil {
			t.Errorf("an app admin sees an IP address: %v", e)
		}
	}
	if v := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'app.access_changed' AND metadata->>'via' = 'owner:wiki-team'`); v < 2 {
		t.Errorf("changes by the app admin are audited with how they were allowed: %d", v)
	}
	br.call("GET", "/api/v1/audit", nil, 403)
	br.call("GET", "/api/v1/audit?app="+other.ID, nil, 403)

	// What stays with Guardian admins.
	br.call("DELETE", "/api/v1/apps/"+wiki.ID, nil, 403)
	br.call("POST", "/api/v1/apps", map[string]any{"name": "mine", "pretty_name": "Mine", "redirect_uris": []string{"https://mine.test/cb"}}, 403)

	// Someone else sees no apps at all.
	bob := newBrowser(t)
	bob.mustLogin("bob")
	if apps := items(t, bob.call("GET", "/api/v1/apps", nil, 200)); len(apps) != 0 {
		t.Errorf("bob's apps = %v", apps)
	}
	bob.call("GET", "/api/v1/apps/"+wiki.ID, nil, 403)

	// Removing the owner group from the app takes the rights away at once.
	root.call("PATCH", "/api/v1/apps/"+wiki.ID, map[string]any{"owner_group_id": ""}, 200)
	br.call("GET", "/api/v1/apps/"+wiki.ID, nil, 403)
}

// An app admin must use two-factor, like a group owner.
//
// Covers: A24
func TestE2EAppAdminsMustUseTwoFactor(t *testing.T) {
	newTestEnv(t)
	app, _ := testutil.CreateApp(t, "notes", testutil.AppOptions{})
	team := testutil.Group(t, "notes-team", "")
	testutil.Exec(t, `UPDATE app SET owner_group_id = $1 WHERE id = $2`, team, app.ID)
	acct := testutil.CreateAccount(t, "kass")
	testutil.AddMember(t, team, acct.ID)
	br := newBrowser(t)
	resp := br.login("kass", testutil.DefaultPassword, "")
	drain(resp)
	if resp.Header.Get("Location") != "/mfa/setup" {
		t.Fatalf("an app admin without two-factor: %q", resp.Header.Get("Location"))
	}
	setUpOnPage(t, br, "App admins must use two-factor.")
	br.call("GET", "/api/v1/apps/"+app.ID, nil, 200)
}
