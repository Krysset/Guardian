package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// call sends a JSON request as this browser, checks the status and returns the answer when it is a JSON
// object (nil otherwise, for example for a list).
func (b *browser) call(method, path string, body any, want int) map[string]any {
	b.t.Helper()
	resp := b.sendJSON(method, path, body)
	raw := readBody(b.t, resp)
	if resp.StatusCode != want {
		b.t.Fatalf("%s %s: status %d, want %d (%.300s)", method, path, resp.StatusCode, want, raw)
	}
	var m map[string]any
	json.Unmarshal([]byte(raw), &m)
	return m
}

func members(group, account string) string { return "/api/groups/" + group + "/members/" + account }

// Group changes made through the API reach the app at its next refresh. The app's refresh token stays
// the same; what it returns is decided at refresh time.
func TestE2EGroupChangesReachTheAppAtItsNextRefresh(t *testing.T) {
	testutil.Reset(t)
	svc, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	testutil.AdminAccount(t, "root")
	user := testutil.CreateAccount(t, "dave")

	admin := newBrowser(t)
	admin.mustLogin("root")
	ub := newBrowser(t)
	tok := ub.signIn(svc, secret, "dave", "openid groups")
	groups := func() []string {
		fresh := refreshed(t, svc, secret, tok.Refresh)
		inAccess := groupList(verifyAccessToken(t, svc, fresh.Access))
		inID := groupList(parseJWT(t, fresh.ID).Claims.(jwt.MapClaims))
		if fmt.Sprint(inAccess) != fmt.Sprint(inID) {
			t.Fatalf("access token says %v, ID token says %v", inAccess, inID)
		}
		return inAccess
	}
	if len(groups()) != 0 {
		t.Fatalf("a new user must be in no group: %v", groups())
	}

	// create two groups and link only one of them to the app
	approvers := str(admin.call("POST", "/api/groups", map[string]any{"key": "approvers", "display_name": "Approvers"}, 201)["id"])
	hr := str(admin.call("POST", "/api/groups", map[string]any{"key": "hr-sensitive", "display_name": "HR"}, 201)["id"])
	admin.call("PUT", members(approvers, user.ID), nil, 200)
	admin.call("PUT", members(hr, user.ID), nil, 200)
	if got := groups(); len(got) != 0 {
		t.Fatalf("groups that are not linked to the app must not be shown to it: %v", got)
	}
	linked := admin.call("POST", "/api/service/access", map[string]any{"id": svc.ID, "access_rule": "anyone", "group_ids": []string{approvers}}, 200)
	if linked["access_rule"] != "anyone" || fmt.Sprint(linked["group_ids"]) != "["+approvers+"]" {
		t.Errorf("app after linking: rule %v, groups %v", linked["access_rule"], linked["group_ids"])
	}
	if got := groups(); len(got) != 1 || got[0] != "approvers" {
		t.Fatalf("after linking the group: %v, want [approvers] and never hr-sensitive", got)
	}

	// userinfo always answers with the groups as they are now
	if _, info := userinfoStatus(t, tok.Access); fmt.Sprint(groupList(info)) != "[approvers]" {
		t.Errorf("userinfo groups = %v", info["groups"])
	}

	// removing the member reaches the next refresh, and userinfo at once
	admin.call("DELETE", members(approvers, user.ID), nil, 200)
	if len(groups()) != 0 {
		t.Fatalf("after removing the member the next refresh must not carry the group: %v", groups())
	}
	if _, info := userinfoStatus(t, tok.Access); len(groupList(info)) != 0 {
		t.Errorf("userinfo still shows %v after the removal", info["groups"])
	}

	// memberships can expire; an expiry in the past is refused
	admin.call("PUT", members(approvers, user.ID), map[string]any{"expires_at": "2000-01-01T00:00:00Z"}, 400)
	if len(groups()) != 0 {
		t.Error("a refused membership took effect")
	}
	admin.call("PUT", members(approvers, user.ID), map[string]any{"expires_at": "2999-01-01T00:00:00Z"}, 200)
	if got := groups(); len(got) != 1 {
		t.Fatalf("a membership that expires in the future must count: %v", got)
	}
	listed := admin.get("/api/groups/" + approvers + "/members")
	if body := readBody(t, listed); !strings.Contains(body, `"username":"dave"`) || !strings.Contains(body, `"expires_at":"2999-01-01T00:00:00Z"`) {
		t.Errorf("member listing: %.300s", body)
	}

	// renaming keeps the key, which is what the app sees
	admin.call("PATCH", "/api/groups/"+approvers, map[string]any{"display_name": "Invoice approvers"}, 200)
	admin.call("PATCH", "/api/groups/"+approvers, map[string]any{"key": "renamed"}, 400)
	if got := groups(); len(got) != 1 || got[0] != "approvers" {
		t.Fatalf("after renaming, the app must still see the same key: %v", got)
	}

	// unknown accounts and unknown groups
	admin.call("PUT", members(approvers, "00000000-0000-0000-0000-000000000000"), nil, 404)
	admin.call("PUT", members("00000000-0000-0000-0000-000000000000", user.ID), nil, 404)
	admin.call("POST", "/api/groups", map[string]any{"key": "approvers", "display_name": "Again"}, 409)
	admin.call("POST", "/api/service/access", map[string]any{"id": svc.ID, "access_rule": "groups", "group_ids": []string{"00000000-0000-0000-0000-000000000000"}}, 400)

	// deleting the group removes it from its members
	admin.call("DELETE", "/api/groups/"+approvers, nil, 200)
	if len(groups()) != 0 {
		t.Error("a deleted group is still reported")
	}

	// every change was audited
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type IN
		('group.created','group.updated','group.deleted','group.member_added','group.member_removed','app.access_changed')`); n != 9 {
		t.Errorf("%d audit entries for the group changes, want 9", n)
	}
}

func TestE2EGroupAndAppAPIsAreForAdministrators(t *testing.T) {
	testutil.Reset(t)
	plainAcct := testutil.CreateAccount(t, "plain")
	testutil.AdminAccount(t, "root")
	adminGroup := testutil.GroupID(t, db.AdminGroupKey)
	team := testutil.Group(t, "team", "")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})

	anon := newBrowser(t)
	plain := newBrowser(t)
	plain.mustLogin("plain")
	admin := newBrowser(t)
	admin.mustLogin("root")

	type req struct {
		method, path string
		body         any
	}
	adminOnly := []req{
		{"POST", "/api/groups", map[string]any{"key": "new-group", "display_name": "New"}},
		{"GET", "/api/groups/" + team, nil},
		{"PATCH", "/api/groups/" + team, map[string]any{"description": "changed"}},
		{"GET", "/api/groups/" + team + "/members", nil},
		{"PUT", members(team, plainAcct.ID), nil},
		{"PUT", members(adminGroup, plainAcct.ID), nil}, // nobody may make themselves an administrator
		{"DELETE", members(team, plainAcct.ID), nil},
		{"DELETE", "/api/groups/" + team, nil},
		{"GET", "/api/service/list", nil}, // app settings and redirect URIs are not for everyone
		{"GET", "/api/service/" + app.ID, nil},
		{"POST", "/api/service/add", map[string]any{"name": "x1", "pretty_name": "x", "redirect_uris": []string{"https://x1.test/cb"}}},
		{"POST", "/api/service/access", map[string]any{"id": app.ID, "access_rule": "anyone", "group_ids": []string{}}},
	}
	for _, r := range adminOnly {
		anon.call(r.method, r.path, r.body, http.StatusUnauthorized)
		plain.call(r.method, r.path, r.body, http.StatusForbidden)
	}
	if ok, _ := db.IsAdmin(plainAcct.ID); ok {
		t.Fatal("an ordinary account made itself an administrator")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM user_group WHERE key = 'new-group'`); n != 0 {
		t.Error("an ordinary account created a group")
	}

	// the group listing answers everyone who is signed in, but only with what they may manage
	anon.call("GET", "/api/groups", nil, http.StatusUnauthorized)
	if body := readBody(t, plain.get("/api/groups")); strings.TrimSpace(body) != "[]" {
		t.Errorf("an account that owns no group must get an empty list, got %.200s", body)
	}
	if body := readBody(t, admin.get("/api/groups")); !strings.Contains(body, `"key":"guardian-admins"`) || !strings.Contains(body, `"key":"team"`) {
		t.Errorf("the administrator's listing lacks groups: %.300s", body)
	}

	// the built-in group cannot be deleted or edited, even by an administrator
	admin.call("DELETE", "/api/groups/"+adminGroup, nil, http.StatusForbidden)
	admin.call("PATCH", "/api/groups/"+adminGroup, map[string]any{"display_name": "Renamed"}, http.StatusForbidden)
	admin.call("PATCH", "/api/groups/"+adminGroup, map[string]any{"owner_group_id": team}, http.StatusForbidden)

	// becoming an administrator opens the API at once, on the same session
	admin.call("PUT", members(adminGroup, plainAcct.ID), nil, 200)
	plain.call("GET", "/api/service/list", nil, 200)
	plain.call("POST", "/api/groups", map[string]any{"key": "new-group", "display_name": "New"}, 201)
	// ...and losing it closes it again
	admin.call("DELETE", members(adminGroup, plainAcct.ID), nil, 200)
	plain.call("GET", "/api/service/list", nil, http.StatusForbidden)
}

func TestE2EGroupOwnersManageOnlyTheMembersOfTheirGroups(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	leads := testutil.Group(t, "billing-leads", "")
	users := testutil.Group(t, "billing-users", leads)
	other := testutil.Group(t, "other", "")
	adminGroup := testutil.GroupID(t, db.AdminGroupKey)
	leadAcct := testutil.CreateAccount(t, "lead")
	newcomer := testutil.CreateAccount(t, "newcomer")
	testutil.AddMember(t, leads, leadAcct.ID)

	lead := newBrowser(t)
	lead.mustLogin("lead")

	// the owner sees exactly the group it owns
	body := readBody(t, lead.get("/api/groups"))
	if !strings.Contains(body, `"key":"billing-users"`) || strings.Contains(body, `"key":"other"`) ||
		strings.Contains(body, `"key":"billing-leads"`) || strings.Contains(body, `"key":"guardian-admins"`) {
		t.Errorf("an owner must see only the groups it owns, got %.400s", body)
	}
	lead.call("GET", "/api/groups/"+users, nil, 200)

	// it can add and remove members there
	lead.call("PUT", members(users, newcomer.ID), nil, 200)
	if ok, _ := db.AccountInGroup(newcomer.ID, "billing-users"); !ok {
		t.Fatal("the owner could not add a member")
	}
	if body := readBody(t, lead.get("/api/groups/"+users+"/members")); !strings.Contains(body, `"username":"newcomer"`) {
		t.Errorf("member listing for the owner: %.200s", body)
	}
	lead.call("DELETE", members(users, newcomer.ID), nil, 200)
	if ok, _ := db.AccountInGroup(newcomer.ID, "billing-users"); ok {
		t.Fatal("the owner could not remove a member")
	}

	// and nothing else: not its own owner group, not other groups, not the administrators, no group settings
	for _, group := range []string{leads, other, adminGroup} {
		lead.call("GET", "/api/groups/"+group, nil, http.StatusForbidden)
		lead.call("GET", "/api/groups/"+group+"/members", nil, http.StatusForbidden)
		lead.call("PUT", members(group, newcomer.ID), nil, http.StatusForbidden)
		lead.call("DELETE", members(group, leadAcct.ID), nil, http.StatusForbidden)
	}
	lead.call("PATCH", "/api/groups/"+users, map[string]any{"display_name": "Mine now"}, http.StatusForbidden)
	lead.call("PATCH", "/api/groups/"+users, map[string]any{"owner_group_id": ""}, http.StatusForbidden)
	lead.call("DELETE", "/api/groups/"+users, nil, http.StatusForbidden)
	lead.call("POST", "/api/groups", map[string]any{"key": "more", "display_name": "More"}, http.StatusForbidden)
	if n := testutil.Count(t, `SELECT count(*) FROM group_member WHERE account_id = $1`, newcomer.ID); n != 0 {
		t.Errorf("the owner changed %d memberships outside its group", n)
	}

	// the audit log records that the changes were made as an owner, and through which group
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type IN ('group.member_added','group.member_removed')
		AND metadata->>'via' = 'owner:billing-leads' AND actor_account_id = $1`, leadAcct.ID); n != 2 {
		t.Errorf("%d audit entries marked as made by the owner, want 2", n)
	}

	// ownership ends with membership of the owner group, at once and on the same session
	if err := db.RemoveGroupMember(leads, leadAcct.ID); err != nil {
		t.Fatal(err)
	}
	lead.call("PUT", members(users, newcomer.ID), nil, http.StatusForbidden)
}

func TestE2ETheLastAdministratorIsProtected(t *testing.T) {
	testutil.Reset(t)
	root := testutil.AdminAccount(t, "root")
	seeded, _, _ := db.GetAccountByUsername("admin")
	adminGroup := testutil.GroupID(t, db.AdminGroupKey)
	admin := newBrowser(t)
	admin.mustLogin("root")

	// two administrators: one can go
	admin.call("DELETE", members(adminGroup, seeded.ID), nil, 200)

	// now root is the last one, and cannot remove, expire or delete itself
	admin.call("DELETE", members(adminGroup, root.ID), nil, http.StatusConflict)
	admin.call("PUT", members(adminGroup, root.ID), map[string]any{"expires_at": "2999-01-01T00:00:00Z"}, http.StatusConflict)
	admin.call("POST", "/api/account/delete", map[string]any{"id": root.ID}, http.StatusConflict)
	if ok, _ := db.IsAdmin(root.ID); !ok {
		t.Fatal("the last administrator lost its rights")
	}
	admin.call("GET", "/api/groups", nil, 200) // and can still work

	// with a second administrator, the first can leave
	second := testutil.CreateAccount(t, "second")
	admin.call("PUT", members(adminGroup, second.ID), nil, 200)
	admin.call("DELETE", members(adminGroup, root.ID), nil, 200)
	admin.call("GET", "/api/groups/"+adminGroup, nil, http.StatusForbidden)
}

func TestE2EAppAccessRuleDecidesWhoMaySignIn(t *testing.T) {
	testutil.Reset(t)
	team := testutil.Group(t, "team", "")
	app, secret := testutil.CreateApp(t, "intranet", testutil.AppOptions{FirstParty: true, AccessRule: "groups", GroupIDs: []string{team}})
	member := testutil.CreateAccount(t, "member")
	outsider := testutil.CreateAccount(t, "outsider")
	testutil.AddMember(t, team, member.ID)

	// a member of the linked group signs in as usual
	mb := newBrowser(t)
	mb.signIn(app, secret, "member", "openid")

	// anyone else is stopped by Guardian with an explanation, and the app never gets a code
	ob := newBrowser(t)
	ob.mustLogin("outsider")
	_, challenge := newPKCE(t)
	params := authParams{app: app, scope: "openid", state: "st-1", challenge: challenge}.values()
	resp := ob.get("/authorize?" + params.Encode())
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Location") != "" {
		t.Fatalf("an account outside the linked groups: status %d, location %q; want 403 and no redirect", resp.StatusCode, resp.Header.Get("Location"))
	}
	if body := readBody(t, resp); !strings.Contains(body, "does not have access to App intranet") {
		t.Errorf("the refusal must say what happened, got %.300s", body)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM authorization_code WHERE account_id = $1`, outsider.ID); n != 0 {
		t.Errorf("%d authorization codes were issued to an account without access", n)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'authorize.denied' AND actor_account_id = $1`, outsider.ID); n != 1 {
		t.Errorf("%d audit entries for the refusal, want 1", n)
	}

	// an app that asked not to show any page gets a standard error back instead
	params.Set("prompt", "none")
	silent := ob.get("/authorize?" + params.Encode())
	loc, _ := url.Parse(silent.Header.Get("Location"))
	drain(silent)
	if silent.StatusCode != http.StatusFound || loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
		t.Errorf("prompt=none without access: status %d, redirect %q", silent.StatusCode, silent.Header.Get("Location"))
	}
	params.Del("prompt")

	// joining the group opens the door at once, on the same session
	testutil.AddMember(t, team, outsider.ID)
	cb := ob.authorizeCallback(params, "outsider")
	if cb.Query().Get("code") == "" {
		t.Fatalf("after joining the linked group sign-in must work, got %s", cb)
	}
	// leaving closes it again
	if err := db.RemoveGroupMember(team, outsider.ID); err != nil {
		t.Fatal(err)
	}
	again := ob.get("/authorize?" + params.Encode())
	drain(again)
	if again.StatusCode != http.StatusForbidden {
		t.Errorf("after leaving the group: status %d, want 403", again.StatusCode)
	}

	// with the "anyone" rule every account may sign in
	if err := db.SetAppAccess(app.ID, "anyone", []string{team}); err != nil {
		t.Fatal(err)
	}
	if cb := ob.authorizeCallback(params, "outsider"); cb.Query().Get("code") == "" {
		t.Errorf("with the anyone rule sign-in must work, got %s", cb)
	}
}

func TestE2EEachAppSeesOnlyItsOwnGroupsAndNoProfileInAccessTokens(t *testing.T) {
	testutil.Reset(t)
	user := testutil.CreateAccount(t, "alice")
	if _, err := db.UpdateProfile(db.Account{ID: user.ID, DisplayName: "Alice A", Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	a, secA := testutil.CreateApp(t, "appa", testutil.AppOptions{FirstParty: true})
	bApp, secB := testutil.CreateApp(t, "appb", testutil.AppOptions{FirstParty: true})
	ga := testutil.Group(t, "a-group", "")
	gb := testutil.Group(t, "b-group", "")
	unlinked := testutil.Group(t, "hr-sensitive", "")
	if err := db.SetAppAccess(a.ID, "anyone", []string{ga}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAppAccess(bApp.ID, "anyone", []string{gb}); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{ga, gb, unlinked} {
		testutil.AddMember(t, g, user.ID)
	}
	br := newBrowser(t)
	tokA := br.signIn(a, secA, "alice", "openid profile email groups")
	tokB := br.signIn(bApp, secB, "alice", "openid groups")

	claimsA := verifyAccessToken(t, a, tokA.Access)
	if got := groupList(claimsA); fmt.Sprint(got) != "[a-group]" {
		t.Errorf("app A's access token carries %v, want [a-group]", got)
	}
	if got := groupList(verifyAccessToken(t, bApp, tokB.Access)); fmt.Sprint(got) != "[b-group]" {
		t.Errorf("app B's access token carries %v, want [b-group]", got)
	}
	// an access token is lean: who, for which app, which scopes and groups; no profile data
	for _, k := range []string{"sub", "aud", "client_id", "scope", "sid", "amr", "jti", "iat", "exp"} {
		if claimsA[k] == nil {
			t.Errorf("access token lacks %q: %v", k, claimsA)
		}
	}
	for _, leaked := range []string{"email", "name", "preferred_username", "email_verified"} {
		if _, ok := claimsA[leaked]; ok {
			t.Errorf("access token carries profile data %q", leaked)
		}
	}
	// the ID token carries the profile data instead
	idA := parseJWT(t, tokA.ID).Claims.(jwt.MapClaims)
	if idA["email"] != "alice@example.com" || idA["name"] != "Alice A" || fmt.Sprint(groupList(idA)) != "[a-group]" {
		t.Errorf("ID token claims = %v", idA)
	}
	// an access token for one app is not valid for another
	if _, err := jwt.Parse(tokA.Access, testKeys.Keyfunc, jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(bApp.ClientID)); err == nil {
		t.Error("app A's access token passes app B's audience check")
	}
	// without the groups scope there is no groups claim at all
	plain := br.signIn(a, secA, "alice", "openid")
	if _, ok := verifyAccessToken(t, a, plain.Access)["groups"]; ok {
		t.Error("a token without the groups scope carries groups")
	}
	if _, ok := parseJWT(t, plain.ID).Claims.(jwt.MapClaims)["groups"]; ok {
		t.Error("an ID token without the groups scope carries groups")
	}

	// client authentication at /token
	status, body := tokenRequest(t, a, "wrong", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Errorf("/token with a wrong secret: %d %v", status, body)
	}
	if status, _ := refreshRequest(t, a, secB, tokA.Refresh); status != http.StatusUnauthorized {
		t.Errorf("another app's secret: %d", status)
	}

	// introspection is gone, and the internal endpoints are not on the public listener
	for _, path := range []string{"/introspect", "/metrics", "/healthz", "/readyz"} {
		r := br.get(path)
		if r.StatusCode != http.StatusNotFound && r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("public listener answers %s with %d", path, r.StatusCode)
		}
		drain(r)
	}
	for _, srv := range []string{pubSrv.URL, intSrv.URL} {
		resp, err := http.Post(srv+"/introspect", "application/x-www-form-urlencoded", strings.NewReader("token="+tokA.Access))
		if err != nil || resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST /introspect on %s must be 404", srv)
		}
		if resp != nil {
			drain(resp)
		}
	}
}

func TestE2EDisablingAnAppStopsItsRefreshesAndLogins(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	a, secA := testutil.CreateApp(t, "appa", testutil.AppOptions{FirstParty: true})
	b2, secB := testutil.CreateApp(t, "appb", testutil.AppOptions{FirstParty: true})
	br := newBrowser(t)
	tokA := br.signIn(a, secA, "alice", "openid")
	tokB := br.signIn(b2, secB, "alice", "openid")

	testutil.Exec(t, `UPDATE app SET enabled = FALSE WHERE id = $1`, a.ID)
	if status, _ := refreshRequest(t, a, secA, tokA.Refresh); status != http.StatusUnauthorized {
		t.Errorf("a disabled app refreshed tokens: %d", status)
	}
	if status, _ := userinfoStatus(t, tokA.Access); status != http.StatusUnauthorized {
		t.Errorf("userinfo for a disabled app's token = %d", status)
	}
	// other apps are unaffected
	refreshed(t, b2, secB, tokB.Refresh)
	if status, _ := userinfoStatus(t, tokB.Access); status != 200 {
		t.Errorf("userinfo for another app's token = %d", status)
	}
	resp := br.get("/authorize?" + authParams{app: a, state: "s", challenge: strings.Repeat("a", 43)}.values().Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("authorize for a disabled app = %d", resp.StatusCode)
	}
	drain(resp)
}

func TestE2ELeavingAGroupEndsAccessAndNotifiesTheApp(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	user := testutil.CreateAccount(t, "erin")
	team := testutil.Group(t, "team", "")
	endpoint, logouts := startReceiver(t)
	app, secret := testutil.CreateApp(t, "intranet", testutil.AppOptions{FirstParty: true, AccessRule: "groups",
		GroupIDs: []string{team}, BackchannelURI: endpoint})
	testutil.AddMember(t, team, user.ID)

	ub := newBrowser(t)
	tok := ub.signIn(app, secret, "erin", "openid groups")
	refreshed(t, app, secret, tok.Refresh)

	admin := newBrowser(t)
	admin.mustLogin("root")
	admin.call("DELETE", members(team, user.ID), nil, 200)

	// the app is told at once, for the user's session
	lt := parseJWT(t, waitToken(t, logouts), jwt.WithIssuer(testIssuer), jwt.WithAudience(app.ClientID))
	claims := lt.Claims.(jwt.MapClaims)
	if lt.Header["typ"] != "logout+jwt" || claims["sub"] != user.ID || claims["sid"] != verifyAccessToken(t, app, tok.Access)["sid"] {
		t.Errorf("logout token: typ %v, claims %v", lt.Header["typ"], claims)
	}
	// and an app that missed it finds out at its next refresh: the access rule is applied again
	refreshRefused(t, app, secret, tok.Refresh)
	// the user is still signed in to Guardian itself
	me := ub.get("/api/account/me")
	wantStatus(t, me, 200)
	drain(me)
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
	endpoint, logouts := startReceiver(t)
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true, BackchannelURI: endpoint})

	vb := newBrowser(t)
	tok := vb.signIn(app, secret, "victim", "openid")
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
	refreshed(t, app, secret, tok.Refresh)

	r = admin.postJSON("/api/account/delete", map[string]any{"id": victim.ID})
	wantStatus(t, r, 200)
	drain(r)

	me := vb.get("/api/account/me")
	wantStatus(t, me, http.StatusUnauthorized)
	drain(me)
	refreshRefused(t, app, secret, tok.Refresh)
	if status, _ := userinfoStatus(t, tok.Access); status != http.StatusUnauthorized {
		t.Errorf("userinfo after deletion: %d", status)
	}
	if lt := parseJWT(t, waitToken(t, logouts), jwt.WithAudience(app.ClientID)); lt.Claims.(jwt.MapClaims)["sub"] != victim.ID {
		t.Errorf("the app was told about the wrong user: %v", lt.Claims)
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
	// the returned credentials really authenticate the app (the bogus refresh token is then refused)
	registered := db.App{ClientID: str(app["client_id"])}
	if status, body := refreshRequest(t, registered, secret, "garbage"); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("the new credentials did not authenticate: %d %v", status, body)
	}

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

	// a new app is closed until it is opened on purpose
	if app["access_rule"] != "groups" || fmt.Sprint(app["group_ids"]) != "[]" {
		t.Errorf("a new app must default to the groups rule with no linked groups, got %v %v", app["access_rule"], app["group_ids"])
	}

	// listing: administrators only, never any secret material
	list := admin.get("/api/service/list")
	wantStatus(t, list, 200)
	body := readBody(t, list)
	if !strings.Contains(body, "newsvc") || strings.Contains(body, `"client_secret":`) || strings.Contains(body, "secret_hash") {
		t.Errorf("list leaks or lacks data: %.300s", body)
	}
	forbidden := plain.get("/api/service/list")
	wantStatus(t, forbidden, http.StatusForbidden)
	drain(forbidden)
	one := admin.get("/api/service/not-a-uuid")
	wantStatus(t, one, http.StatusNotFound)
	drain(one)

	// removal: administrators only; removing an app kills its credentials at once
	rp := plain.sendJSON("DELETE", "/api/service/remove", map[string]any{"id": app["id"]})
	wantStatus(t, rp, http.StatusForbidden)
	drain(rp)
	rm := admin.sendJSON("DELETE", "/api/service/remove", map[string]any{"id": app["id"]})
	wantStatus(t, rm, 200)
	drain(rm)
	if status, _ := refreshRequest(t, registered, secret, "garbage"); status != http.StatusUnauthorized {
		t.Errorf("a removed app still authenticates: %d", status)
	}
}

func TestE2EInternalListenerProbesAndMetrics(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	br := newBrowser(t)
	tok := br.signIn(app, secret, "alice", "openid")
	refreshed(t, app, secret, tok.Refresh)
	refreshRefused(t, app, secret, "nope")

	for _, p := range []string{"/healthz", "/readyz"} {
		r := mustGet(t, intSrv.URL+p)
		wantStatus(t, r, 200)
		drain(r)
	}
	m := readBody(t, mustGet(t, intSrv.URL+"/metrics"))
	for _, want := range []string{
		`guardian_token_requests_total{grant="authorization_code",result="issued"}`,
		`guardian_token_requests_total{grant="refresh_token",result="issued"}`,
		`guardian_token_requests_total{grant="refresh_token",result="refused"}`,
		`guardian_logins_total{result="success"}`, `guardian_http_request_duration_seconds_bucket`,
		`listener="public"`, `listener="internal"`, `route="/token"`,
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

// clientToken gets a token for the app itself with the client_credentials grant.
func clientToken(t *testing.T, app db.App, secret string) string {
	t.Helper()
	status, raw := tokenRequest(t, app, secret, url.Values{"grant_type": {"client_credentials"}})
	if status != http.StatusOK || raw["refresh_token"] != nil || raw["id_token"] != nil {
		t.Fatalf("client_credentials: %d %v", status, raw)
	}
	return str(raw["access_token"])
}

// machineGet calls the machine API with a Bearer token.
func machineGet(t *testing.T, token, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", pubSrv.URL+"/api/v1/apps/self"+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, readBody(t, resp)
}

func TestE2EMachineAPIShowsAnAppOnlyItsOwnGroupsAndUsers(t *testing.T) {
	testutil.Reset(t)
	testutil.AdminAccount(t, "root")
	staff := testutil.Group(t, "staff", "")
	hr := testutil.Group(t, "hr", "")
	app, secret := testutil.CreateApp(t, "intranet", testutil.AppOptions{FirstParty: true, GroupIDs: []string{staff},
		MachineAPI: true, Scopes: []string{"openid", "profile", "groups"}})
	other, otherSecret := testutil.CreateApp(t, "wiki", testutil.AppOptions{FirstParty: true, GroupIDs: []string{hr}})
	member := testutil.CreateAccount(t, "member")
	if _, err := db.UpdateProfile(db.Account{ID: member.ID, DisplayName: "Mem Ber", Email: "member@example.com"}); err != nil {
		t.Fatal(err)
	}
	visitor := testutil.CreateAccount(t, "visitor")
	stranger := testutil.CreateAccount(t, "stranger")
	testutil.AddMember(t, staff, member.ID)
	testutil.AddMember(t, hr, member.ID)

	tok := clientToken(t, app, secret)
	claims := parseJWT(t, tok, jwt.WithIssuer(testIssuer), jwt.WithAudience(testIssuer)).Claims.(jwt.MapClaims)
	if claims["sub"] != app.ClientID || claims["client_id"] != app.ClientID || claims["sid"] != nil {
		t.Errorf("client token claims = %v", claims)
	}

	// who am I
	if status, body := machineGet(t, tok, ""); status != 200 || !strings.Contains(body, `"name":"intranet"`) {
		t.Errorf("self: %d %.200s", status, body)
	}
	// only linked groups
	status, body := machineGet(t, tok, "/groups")
	if status != 200 || !strings.Contains(body, `"key":"staff"`) || strings.Contains(body, `"hr"`) || !strings.Contains(body, `"member_count":1`) {
		t.Errorf("groups: %d %.300s", status, body)
	}
	// members of a linked group, with the claims the app's scopes allow: profile and groups, but no email
	status, body = machineGet(t, tok, "/groups/staff/members")
	if status != 200 || !strings.Contains(body, `"preferred_username":"member"`) || !strings.Contains(body, `"name":"Mem Ber"`) ||
		!strings.Contains(body, `"groups":["staff"]`) || strings.Contains(body, "member@example.com") || strings.Contains(body, `"hr"`) {
		t.Errorf("members: %d %.400s", status, body)
	}
	if status, _ := machineGet(t, tok, "/groups/hr/members"); status != http.StatusNotFound {
		t.Errorf("a group not linked to the app: %d, want 404", status)
	}

	// users: group members and people who signed in to the app, nobody else, and the same 404 for both kinds of refusal
	if status, body := machineGet(t, tok, "/users/"+member.ID); status != 200 || !strings.Contains(body, `"sub":"`+member.ID+`"`) {
		t.Errorf("a member of a linked group: %d %.200s", status, body)
	}
	_, unknown := machineGet(t, tok, "/users/00000000-0000-0000-0000-000000000000")
	for _, id := range []string{visitor.ID, stranger.ID} {
		if status, body := machineGet(t, tok, "/users/"+id); status != http.StatusNotFound || body != unknown {
			t.Errorf("an account the app may not know: %d %.100s (must look like an unknown account)", status, body)
		}
	}
	vb := newBrowser(t)
	vb.signIn(app, secret, "visitor", "openid")
	if status, body := machineGet(t, tok, "/users/"+visitor.ID); status != 200 || !strings.Contains(body, `"groups":[]`) {
		t.Errorf("after signing in to the app, the visitor must be visible: %d %.200s", status, body)
	}
	if status, _ := machineGet(t, tok, "/users/"+stranger.ID); status != http.StatusNotFound {
		t.Error("the stranger became visible")
	}

	// tokens that are not this kind are refused
	userTok := vb.signIn(app, secret, "visitor", "openid").Access
	for name, bad := range map[string]string{"none": "", "garbage": "x.y.z", "a user's access token": userTok} {
		if status, _ := machineGet(t, bad, "/groups"); status != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, status)
		}
	}
	// an app without machine access cannot get such a token
	if status, raw := tokenRequest(t, other, otherSecret, url.Values{"grant_type": {"client_credentials"}}); status != http.StatusBadRequest ||
		raw["error"] != "unsupported_grant_type" {
		t.Errorf("client_credentials without machine access: %d %v", status, raw)
	}

	// turning machine access off, or disabling the app, stops tokens that were already issued
	admin := newBrowser(t)
	admin.mustLogin("root")
	admin.call("POST", "/api/service/access", map[string]any{"id": app.ID, "access_rule": "anyone", "group_ids": []string{staff}, "machine_api": false}, 200)
	if status, _ := machineGet(t, tok, "/groups"); status != http.StatusUnauthorized {
		t.Errorf("after turning machine access off: %d, want 401", status)
	}
	admin.call("POST", "/api/service/access", map[string]any{"id": app.ID, "access_rule": "anyone", "group_ids": []string{staff}, "machine_api": true}, 200)
	tok = clientToken(t, app, secret)
	testutil.Exec(t, `UPDATE app SET enabled = FALSE WHERE id = $1`, app.ID)
	if status, _ := machineGet(t, tok, "/groups"); status != http.StatusUnauthorized {
		t.Errorf("after disabling the app: %d, want 401", status)
	}
	// an app without a secret cannot be given machine access, and the refused request changes nothing
	spa, _ := testutil.CreateApp(t, "spa", testutil.AppOptions{Public: true, AccessRule: "groups"})
	admin.call("POST", "/api/service/access", map[string]any{"id": spa.ID, "access_rule": "anyone", "group_ids": []string{}, "machine_api": true}, 400)
	if fresh, _ := db.GetApp(spa.ID); fresh.AccessRule != "groups" {
		t.Error("a refused request changed the app's access rule")
	}
}
