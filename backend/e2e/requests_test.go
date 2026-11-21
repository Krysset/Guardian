package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"guardian/internal/testutil"
)

// A hidden group is left out of its members' own group list, but its owners still manage it and apps still
// get it. It cannot also be open to requests.
//
// Covers: A26
func TestE2EHiddenGroups(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "root")
	alice := testutil.CreateAccount(t, "alice")
	leads := testutil.Group(t, "leads", "")
	secret := testutil.Group(t, "secret-project", leads)
	testutil.AddMember(t, secret, alice.ID)
	testutil.AddMember(t, leads, alice.ID)
	app, appSecret := testutil.CreateApp(t, "tracker", testutil.AppOptions{FirstParty: true, GroupIDs: []string{secret}})

	root := newBrowser(t)
	root.mustLogin("root")
	if g := root.call("PATCH", "/api/v1/groups/"+secret, map[string]any{"hidden": true}, 200); g["hidden"] != true {
		t.Fatalf("hide: %v", g)
	}
	resp := root.sendJSON("PATCH", "/api/v1/groups/"+secret, map[string]any{"requestable": true})
	wantStatus(t, resp, http.StatusBadRequest)
	if body := decodeMap(t, resp); body["error"] != "hidden_requestable" {
		t.Errorf("hidden and requestable: %v", body)
	}

	br := newBrowser(t)
	br.mustLogin("alice")
	mine := br.call("GET", "/api/v1/me/groups", nil, 200)
	for _, g := range mine["member_of"].([]any) {
		if g.(map[string]any)["id"] == secret {
			t.Error("a hidden group is in its member's own list")
		}
	}
	found := false
	for _, g := range mine["manages"].([]any) {
		found = found || g.(map[string]any)["id"] == secret
	}
	if !found {
		t.Error("its owner no longer sees the hidden group")
	}
	tok := newBrowser(t).signIn(app, appSecret, "alice", "openid groups")
	if !contains(groupList(map[string]any(verifyAccessToken(t, app, tok.Access))), "secret-project") {
		t.Error("the app no longer gets the hidden group")
	}
}

// Every new account, made by sign-up or by an administrator, joins the groups marked join_by_default.
//
// Covers: A34
func TestE2EDefaultGroups(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "root")
	everyone := testutil.Group(t, "everyone", "")
	testutil.Group(t, "others", "")
	root := newBrowser(t)
	root.mustLogin("root")
	root.call("PATCH", "/api/v1/groups/"+everyone, map[string]any{"join_by_default": true}, 200)

	created := root.call("POST", "/api/v1/accounts", map[string]any{"username": "made", "password": testutil.DefaultPassword}, 201)
	newBrowser(t).call("POST", "/api/v1/signup", map[string]any{"username": "self", "password": "long-enough-pw-1"}, 201)
	resp := signupForm(newBrowser(t), "byform", "", "")
	drain(resp)
	for _, who := range []string{str(created["id"]), testutil.AccountID(t, "self"), testutil.AccountID(t, "byform")} {
		if n := testutil.Count(t, `SELECT count(*) FROM group_member m JOIN user_group g ON g.id = m.group_id
			WHERE m.account_id = $1 AND g.key IN ('everyone', 'others')`, who); n != 1 {
			t.Errorf("account %s is in %d of the groups, want only the default one", who, n)
		}
	}
	// Existing accounts are not added afterwards.
	if n := testutil.Count(t, `SELECT count(*) FROM group_member WHERE group_id = $1 AND account_id = $2`, everyone, testutil.AccountID(t, "root")); n != 0 {
		t.Error("an existing account joined a default group")
	}
}

// Asking to join a group: only requestable groups; one open request at a time; the owners (or Guardian
// admins, for a group without owners) are emailed and decide; an approval adds the membership; the
// requester is emailed and can withdraw while it is open. The no-access page offers the app's requestable
// groups.
//
// Covers: A33
func TestE2EAskingToJoinAGroup(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "root")
	setEmail(t, "root", "root@hyrule.example")
	alice := testutil.CreateAccount(t, "alice")
	setEmail(t, "alice", "alice@hyrule.example")
	owner := testutil.CreateAccount(t, "owner")
	setEmail(t, "owner", "owner@hyrule.example")
	stewards := testutil.Group(t, "stewards", "")
	testutil.AddMember(t, stewards, owner.ID)
	wiki := testutil.Group(t, "wiki-users", stewards)
	closed := testutil.Group(t, "closed", "")
	orphans := testutil.Group(t, "orphans", "") // no owner group: Guardian admins decide
	app, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{FirstParty: true, AccessRule: "groups", GroupIDs: []string{wiki}})
	testutil.Exec(t, `UPDATE user_group SET requestable = TRUE WHERE id IN ($1, $2)`, wiki, orphans)

	br := newBrowser(t)
	br.mustLogin("alice")
	listing := br.call("GET", "/api/v1/me/group-requests", nil, 200)
	if n := len(listing["requestable"].([]any)); n != 2 {
		t.Fatalf("requestable groups = %v", listing["requestable"])
	}
	resp := br.postJSON("/api/v1/me/group-requests", map[string]any{"group_id": closed})
	wantStatus(t, resp, http.StatusBadRequest)
	drain(resp)

	q := br.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": wiki, "message": "I write docs"}, 201)
	br.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": wiki}, 409)
	if m, ok := mailbox.WaitFor("owner@hyrule.example", "alice asks to join"); !ok || !strings.Contains(m.Text, "I write docs") ||
		!strings.Contains(m.Text, "/account/groups/"+wiki) {
		t.Errorf("the owner's email: %v %s", ok, m.Text)
	}
	if _, ok := mailbox.WaitFor("root@hyrule.example", "alice asks to join wiki"); ok {
		t.Error("a Guardian admin was emailed about a group that has owners")
	}

	// The owner sees and approves it, with an expiry; someone else cannot.
	ob := newBrowser(t)
	ob.mustLogin("owner")
	open := items(t, ob.call("GET", "/api/v1/groups/"+wiki+"/requests", nil, 200))
	if len(open) != 1 || open[0]["username"] != "alice" || open[0]["message"] != "I write docs" {
		t.Fatalf("open requests: %v", open)
	}
	br.call("POST", "/api/v1/groups/"+wiki+"/requests/"+str(q["id"]), map[string]any{"approve": true}, 403)
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	decided := ob.call("POST", "/api/v1/groups/"+wiki+"/requests/"+str(q["id"]), map[string]any{"approve": true, "expires_at": until}, 200)
	if decided["decision"] != "approved" {
		t.Errorf("decided: %v", decided)
	}
	ob.call("POST", "/api/v1/groups/"+wiki+"/requests/"+str(q["id"]), map[string]any{"approve": false}, 409)
	if n := testutil.Count(t, `SELECT count(*) FROM group_member WHERE group_id = $1 AND account_id = $2 AND expires_at IS NOT NULL`, wiki, alice.ID); n != 1 {
		t.Error("the approval did not add the membership with its expiry")
	}
	if _, ok := mailbox.WaitFor("alice@hyrule.example", "You were added to"); !ok {
		t.Error("the requester was not told")
	}

	// A group without owners: Guardian admins are emailed and decide; denied, and withdrawing works.
	q2 := br.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": orphans}, 201)
	if _, ok := mailbox.WaitFor("root@hyrule.example", "alice asks to join"); !ok {
		t.Error("the admin was not emailed for a group without owners")
	}
	br.call("DELETE", "/api/v1/me/group-requests/"+str(q2["id"]), nil, 204)
	br.call("DELETE", "/api/v1/me/group-requests/"+str(q2["id"]), nil, 404)
	q3 := br.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": orphans}, 201)
	root := newBrowser(t)
	root.mustLogin("root")
	root.call("POST", "/api/v1/groups/"+orphans+"/requests/"+str(q3["id"]), map[string]any{"approve": false}, 200)
	if _, ok := mailbox.WaitFor("alice@hyrule.example", "was denied"); !ok {
		t.Error("no denial email")
	}

	// Closing a group to requests withdraws its open ones.
	bob := testutil.CreateAccount(t, "bob")
	bb := newBrowser(t)
	bb.mustLogin("bob")
	bq := bb.call("POST", "/api/v1/me/group-requests", map[string]any{"group_id": orphans}, 201)
	root.call("PATCH", "/api/v1/groups/"+orphans, map[string]any{"requestable": false}, 200)
	if n := testutil.Count(t, `SELECT count(*) FROM group_request WHERE id = $1 AND decision = 'withdrawn'`, bq["id"]); n != 1 {
		t.Error("closing the group left its request open")
	}

	// The no-access page offers the app's requestable groups, and asking from it works.
	_, challenge := newPKCE(t)
	authorize := "/authorize?" + authParams{app: app, scope: "openid", state: "s", challenge: challenge}.values().Encode()
	page := readBody(t, bb.get(authorize))
	if !strings.Contains(page, "Ask to join") || !strings.Contains(page, "wiki-users") && !strings.Contains(page, "App wiki") {
		t.Fatalf("the no-access page offers nothing: %.600s", page)
	}
	resp = bb.postForm("/request-access", url.Values{"csrf": {bb.csrf()}, "group": {wiki}, "message": {"please"}, "return_to": {authorize}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	next := readBody(t, bb.get(resp.Header.Get("Location")))
	if !strings.Contains(next, "Your request was sent") || !strings.Contains(next, "Waiting for a decision") {
		t.Errorf("after asking from the no-access page: %.800s", next)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM group_request WHERE account_id = $1 AND group_id = $2 AND decision IS NULL`, bob.ID, wiki); n != 1 {
		t.Error("the request from the no-access page was not recorded")
	}
}
