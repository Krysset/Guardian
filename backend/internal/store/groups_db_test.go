package store_test

import (
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

func inGroup(t *testing.T, a db.Account, key string) bool {
	t.Helper()
	ok, err := db.AccountInGroup(a.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func appGroups(t *testing.T, a db.Account, app db.App) []string {
	t.Helper()
	keys, err := db.AccountAppGroups(a.ID, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func mayUse(t *testing.T, a db.Account, app db.App) bool {
	t.Helper()
	fresh, err := db.GetApp(app.ID) // the rule and the links may have changed since app was loaded
	if err != nil {
		t.Fatal(err)
	}
	ok, err := db.AccountMayUseApp(a.ID, fresh)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// expireMembership moves a membership's expiry into the past.
func expireMembership(t *testing.T, groupID, accountID string) {
	t.Helper()
	testutil.Exec(t, `UPDATE group_member SET expires_at = now() - interval '1 minute' WHERE group_id = $1 AND account_id = $2`, groupID, accountID)
}

// ---- Membership and app links -----------------------------------------------

// Covers: M1
func TestAnAppOnlySeesTheGroupsLinkedToIt(t *testing.T) {
	testutil.Reset(t)
	finance := testutil.Group(t, "finance", "")
	approvers := testutil.Group(t, "approvers", "")
	hr := testutil.Group(t, "hr-sensitive", "")
	billing, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{GroupIDs: []string{finance, approvers}})
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{GroupIDs: []string{finance}})
	alice := testutil.CreateAccount(t, "alice")
	bob := testutil.CreateAccount(t, "bob")
	for _, g := range []string{finance, approvers, hr} {
		testutil.AddMember(t, g, alice.ID)
	}

	if got := appGroups(t, alice, billing); !slices.Equal(got, []string{"approvers", "finance"}) {
		t.Errorf("billing sees %v, want [approvers finance] (sorted, without hr-sensitive)", got)
	}
	if got := appGroups(t, alice, wiki); !slices.Equal(got, []string{"finance"}) {
		t.Errorf("wiki sees %v, want [finance]", got)
	}
	if got := appGroups(t, bob, billing); len(got) != 0 {
		t.Errorf("bob is in no group but billing sees %v", got)
	}
	if !inGroup(t, alice, "hr-sensitive") || inGroup(t, bob, "finance") || inGroup(t, alice, "no-such-group") {
		t.Error("AccountInGroup gave a wrong answer")
	}

	// changes apply to the very next question
	if err := db.RemoveGroupMember(finance, alice.ID); err != nil {
		t.Fatal(err)
	}
	if got := appGroups(t, alice, wiki); len(got) != 0 {
		t.Errorf("after removal wiki still sees %v", got)
	}
	if err := db.SetAppAccess(wiki.ID, "anyone", []string{hr}); err != nil {
		t.Fatal(err)
	}
	if got := appGroups(t, alice, wiki); !slices.Equal(got, []string{"hr-sensitive"}) {
		t.Errorf("after relinking wiki sees %v, want [hr-sensitive]", got)
	}

	// the group reports its links and its member count
	g, err := db.GetGroup(hr)
	if err != nil || g.MemberCount != 1 || !slices.Equal(g.AppIDs, []string{wiki.ID}) {
		t.Errorf("group = %+v (%v), want 1 member and the wiki link", g, err)
	}
}

// Covers: A13, O2
func TestExpiredMembershipsDoNotCount(t *testing.T) {
	testutil.Reset(t)
	staff := testutil.Group(t, "staff", "")
	app, _ := testutil.CreateApp(t, "intranet", testutil.AppOptions{AccessRule: "groups", GroupIDs: []string{staff}})
	erin := testutil.CreateAccount(t, "erin")

	soon := time.Now().Add(time.Hour)
	if err := db.AddGroupMember(staff, erin.ID, "", &soon); err != nil {
		t.Fatal(err)
	}
	if !inGroup(t, erin, "staff") || !mayUse(t, erin, app) || len(appGroups(t, erin, app)) != 1 {
		t.Fatal("a membership that expires in the future must count")
	}
	members, _ := db.ListGroupMembers(staff)
	if len(members) != 1 || members[0].Username != "erin" || members[0].ExpiresAt == nil {
		t.Errorf("members = %+v, want erin with an expiry", members)
	}

	expireMembership(t, staff, erin.ID)
	if inGroup(t, erin, "staff") || mayUse(t, erin, app) || len(appGroups(t, erin, app)) != 0 {
		t.Error("an expired membership still counts")
	}
	if members, _ := db.ListGroupMembers(staff); len(members) != 0 {
		t.Errorf("expired members are still listed: %+v", members)
	}
	if g, _ := db.GetGroup(staff); g.MemberCount != 0 {
		t.Errorf("member count = %d, want 0", g.MemberCount)
	}

	// adding again renews the membership instead of failing on the old row
	if err := db.AddGroupMember(staff, erin.ID, "", nil); err != nil {
		t.Fatal(err)
	}
	if !inGroup(t, erin, "staff") {
		t.Error("renewing an expired membership did not work")
	}
}

func TestAppAccessRule(t *testing.T) {
	testutil.Reset(t)
	team := testutil.Group(t, "team", "")
	member := testutil.CreateAccount(t, "member")
	outsider := testutil.CreateAccount(t, "outsider")
	testutil.AddMember(t, team, member.ID)

	// an app created without saying anything is closed
	closed, err := db.AddApp(db.App{Name: "closed", PrettyName: "Closed", Description: "d", ClientType: "public",
		RedirectURIs: []string{"https://closed.test/cb"}}, []string{"openid"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if closed.AccessRule != "groups" || len(closed.GroupIDs) != 0 {
		t.Fatalf("a new app must default to the groups rule with no links, got %q %v", closed.AccessRule, closed.GroupIDs)
	}
	if mayUse(t, member, closed) || mayUse(t, outsider, closed) {
		t.Error("an app with the groups rule and no linked group must admit nobody")
	}

	if err := db.SetAppAccess(closed.ID, "groups", []string{team}); err != nil {
		t.Fatal(err)
	}
	if !mayUse(t, member, closed) || mayUse(t, outsider, closed) {
		t.Error("with the groups rule only members of a linked group may sign in")
	}

	if err := db.SetAppAccess(closed.ID, "anyone", []string{team}); err != nil {
		t.Fatal(err)
	}
	if !mayUse(t, member, closed) || !mayUse(t, outsider, closed) {
		t.Error("with the anyone rule every account may sign in")
	}

	// linking a group that does not exist is refused, and nothing changes
	unknown := "00000000-0000-0000-0000-000000000000"
	if err := db.SetAppAccess(closed.ID, "groups", []string{unknown}); !errors.Is(err, db.ErrGroupNotFound) {
		t.Errorf("unknown group: %v, want ErrGroupNotFound", err)
	}
	if fresh, _ := db.GetApp(closed.ID); fresh.AccessRule != "anyone" || !slices.Equal(fresh.GroupIDs, []string{team}) {
		t.Errorf("a failed change must leave the app untouched, got %q %v", fresh.AccessRule, fresh.GroupIDs)
	}
	if err := db.SetAppAccess(unknown, "anyone", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown app: %v, want sql.ErrNoRows", err)
	}
	if _, err := db.AddApp(db.App{Name: "typo", PrettyName: "Typo", Description: "d", ClientType: "public",
		RedirectURIs: []string{"https://typo.test/cb"}, GroupIDs: []string{unknown}}, []string{"openid"}, ""); !errors.Is(err, db.ErrGroupNotFound) {
		t.Errorf("creating an app with an unknown group: %v, want ErrGroupNotFound", err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM app WHERE name = 'typo'`); n != 0 {
		t.Error("the app with the unknown group was created anyway")
	}
}

// ---- Group rules ------------------------------------------------------------

// Covers: A12
func TestBuiltInGroupsAreProtected(t *testing.T) {
	testutil.Reset(t)
	admins := testutil.GroupID(t, db.AdminGroupKey)
	other := testutil.Group(t, "other", "")
	name := "Renamed"

	if err := db.DeleteGroup(admins); !errors.Is(err, db.ErrSystemGroup) {
		t.Errorf("deleting the administrators group: %v, want ErrSystemGroup", err)
	}
	if err := db.UpdateGroup(admins, db.GroupUpdate{DisplayName: &name}); !errors.Is(err, db.ErrSystemGroup) {
		t.Errorf("renaming the administrators group: %v, want ErrSystemGroup", err)
	}
	if err := db.UpdateGroup(admins, db.GroupUpdate{OwnerGroupID: &other}); !errors.Is(err, db.ErrSystemGroup) {
		t.Errorf("giving the administrators group an owner: %v, want ErrSystemGroup", err)
	}
	if g, _ := db.GetGroup(admins); g.DisplayName == name || g.OwnerGroupID != "" || !g.IsSystem {
		t.Errorf("the administrators group was changed: %+v", g)
	}
}

// Covers: A12, A14
func TestGroupKeysAreUniqueAndOwnersMustBeOtherGroups(t *testing.T) {
	testutil.Reset(t)
	a := testutil.Group(t, "alpha", "")
	if _, err := db.CreateGroup("alpha", "Again", "", "", ""); !db.IsUniqueViolation(err) {
		t.Errorf("duplicate key: %v, want a unique violation", err)
	}
	unknown := "00000000-0000-0000-0000-000000000000"
	if _, err := db.CreateGroup("beta", "Beta", "", unknown, ""); !errors.Is(err, db.ErrInvalidOwner) {
		t.Errorf("unknown owner at creation: %v, want ErrInvalidOwner", err)
	}
	if err := db.UpdateGroup(a, db.GroupUpdate{OwnerGroupID: &a}); !errors.Is(err, db.ErrInvalidOwner) {
		t.Errorf("a group owning itself: %v, want ErrInvalidOwner", err)
	}
	if err := db.UpdateGroup(a, db.GroupUpdate{OwnerGroupID: &unknown}); !errors.Is(err, db.ErrInvalidOwner) {
		t.Errorf("unknown owner on update: %v, want ErrInvalidOwner", err)
	}
	if err := db.UpdateGroup(unknown, db.GroupUpdate{}); !errors.Is(err, db.ErrGroupNotFound) {
		t.Errorf("updating an unknown group: %v, want ErrGroupNotFound", err)
	}
	if err := db.DeleteGroup(unknown); !errors.Is(err, db.ErrGroupNotFound) {
		t.Errorf("deleting an unknown group: %v, want ErrGroupNotFound", err)
	}

	// an update changes only what it names, and never the key
	name, desc := "Alpha team", "The first team"
	if err := db.UpdateGroup(a, db.GroupUpdate{DisplayName: &name}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateGroup(a, db.GroupUpdate{Description: &desc}); err != nil {
		t.Fatal(err)
	}
	g, _ := db.GetGroup(a)
	if g.Key != "alpha" || g.DisplayName != name || g.Description != desc {
		t.Errorf("group = %+v", g)
	}
}

// Covers: O1, A14
func TestGroupOwnersAreTheMembersOfTheOwnerGroup(t *testing.T) {
	testutil.Reset(t)
	leads := testutil.Group(t, "billing-leads", "")
	users := testutil.Group(t, "billing-users", leads)
	unowned := testutil.Group(t, "unowned", "")
	lead := testutil.CreateAccount(t, "lead")
	user := testutil.CreateAccount(t, "user")
	testutil.AddMember(t, leads, lead.ID)
	testutil.AddMember(t, users, user.ID)

	if key, ok, err := db.OwnsGroup(lead.ID, users); err != nil || !ok || key != "billing-leads" {
		t.Errorf("lead owns billing-users: key %q ok %v err %v", key, ok, err)
	}
	for name, c := range map[string]struct{ account, group string }{
		"a member of the group itself":       {user.ID, users},
		"an owner, for a group without one":  {lead.ID, unowned},
		"an owner, for its own owner group":  {lead.ID, leads},
		"an owner, for the administrators":   {lead.ID, testutil.GroupID(t, db.AdminGroupKey)},
		"an owner, for a group that is gone": {lead.ID, "00000000-0000-0000-0000-000000000000"},
	} {
		if _, ok, err := db.OwnsGroup(c.account, c.group); err != nil || ok {
			t.Errorf("%s must not count as an owner (ok %v, err %v)", name, ok, err)
		}
	}
	owned, err := db.ListGroupsOwnedBy(lead.ID)
	if err != nil || len(owned) != 1 || owned[0].Key != "billing-users" {
		t.Errorf("groups owned by lead = %+v (%v), want only billing-users", owned, err)
	}

	// ownership follows membership of the owner group, at once
	expireMembership(t, leads, lead.ID)
	if _, ok, _ := db.OwnsGroup(lead.ID, users); ok {
		t.Error("an expired membership of the owner group still gives ownership")
	}
	// deleting the owner group leaves the owned group without an owner, not deleted
	if err := db.DeleteGroup(leads); err != nil {
		t.Fatal(err)
	}
	if g, err := db.GetGroup(users); err != nil || g.OwnerGroupID != "" || g.MemberCount != 1 {
		t.Errorf("after deleting its owner group: %+v (%v)", g, err)
	}
}

// Covers: A12
func TestDeletingAGroupRemovesItsMembershipsAndAppLinks(t *testing.T) {
	testutil.Reset(t)
	g := testutil.Group(t, "temps", "")
	app, _ := testutil.CreateApp(t, "portal", testutil.AppOptions{AccessRule: "groups", GroupIDs: []string{g}})
	temp := testutil.CreateAccount(t, "temp")
	testutil.AddMember(t, g, temp.ID)
	if !mayUse(t, temp, app) {
		t.Fatal("setup: the member must have access")
	}
	if err := db.DeleteGroup(g); err != nil {
		t.Fatal(err)
	}
	if mayUse(t, temp, app) || inGroup(t, temp, "temps") {
		t.Error("a deleted group still gives access")
	}
	if n := testutil.Count(t, `SELECT (SELECT count(*) FROM group_member) + (SELECT count(*) FROM app_group)`); n != 1 {
		t.Errorf("leftover rows: %d, want 1 (only the seeded admin's membership)", n)
	}
}

// ---- There is always an administrator ---------------------------------------

func TestTheLastAdministratorCannotBeRemoved(t *testing.T) {
	testutil.Reset(t)
	admins := testutil.GroupID(t, db.AdminGroupKey)
	seeded, _, _ := db.GetAccountByUsername("admin")
	later := time.Now().Add(24 * time.Hour)

	// the seeded admin is the only one
	if err := db.RemoveGroupMember(admins, seeded.ID); !errors.Is(err, db.ErrLastAdmin) {
		t.Errorf("removing the only administrator: %v, want ErrLastAdmin", err)
	}
	if err := db.AddGroupMember(admins, seeded.ID, "", &later); !errors.Is(err, db.ErrLastAdmin) {
		t.Errorf("giving the only administrator an expiry: %v, want ErrLastAdmin", err)
	}
	if _, err := db.SoftDeleteAccount(seeded.ID, ""); !errors.Is(err, db.ErrLastAdmin) {
		t.Errorf("deleting the only administrator: %v, want ErrLastAdmin", err)
	}
	if ok, _ := db.IsAdmin(seeded.ID); !ok {
		t.Fatal("the refused changes must leave the administrator in place")
	}
	if got, _ := db.GetAccount(seeded.ID); got.ID == "" {
		t.Fatal("the administrator's account was deleted despite the refusal")
	}

	// an administrator whose membership expires does not make the first one removable
	temp := testutil.CreateAccount(t, "temp-admin")
	if err := db.AddGroupMember(admins, temp.ID, "", &later); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveGroupMember(admins, seeded.ID); !errors.Is(err, db.ErrLastAdmin) {
		t.Errorf("only a temporary administrator would remain: %v, want ErrLastAdmin", err)
	}

	// neither does a disabled one
	disabled := testutil.CreateAccount(t, "disabled-admin")
	testutil.AddMember(t, admins, disabled.ID)
	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, disabled.ID)
	if err := db.RemoveGroupMember(admins, seeded.ID); !errors.Is(err, db.ErrLastAdmin) {
		t.Errorf("only a disabled administrator would remain: %v, want ErrLastAdmin", err)
	}

	// a second permanent, active administrator does
	second := testutil.AdminAccount(t, "second-admin")
	if err := db.RemoveGroupMember(admins, seeded.ID); err != nil {
		t.Fatalf("with a second administrator the first must be removable: %v", err)
	}
	if ok, _ := db.IsAdmin(seeded.ID); ok {
		t.Error("the removed administrator is still an administrator")
	}
	// ...and now the second one is the last
	if _, err := db.SoftDeleteAccount(second.ID, ""); !errors.Is(err, db.ErrLastAdmin) {
		t.Errorf("deleting the administrator that is now the last: %v, want ErrLastAdmin", err)
	}
	// removing someone from another group is never affected by the rule
	other := testutil.Group(t, "other", "")
	testutil.AddMember(t, other, second.ID)
	if err := db.RemoveGroupMember(other, second.ID); err != nil {
		t.Errorf("removing the last administrator from an ordinary group: %v", err)
	}
}

func TestAdministratorsRemovingEachOtherAtTheSameTimeLeaveOne(t *testing.T) {
	testutil.Reset(t)
	admins := testutil.GroupID(t, db.AdminGroupKey)
	seeded, _, _ := db.GetAccountByUsername("admin")
	second := testutil.AdminAccount(t, "second-admin")

	for round := 0; round < 5; round++ {
		errs := make(chan error, 2)
		go func() { errs <- db.RemoveGroupMember(admins, seeded.ID) }()
		go func() { errs <- db.RemoveGroupMember(admins, second.ID) }()
		refused := 0
		for i := 0; i < 2; i++ {
			if err := <-errs; errors.Is(err, db.ErrLastAdmin) {
				refused++
			} else if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if refused != 1 {
			t.Fatalf("round %d: %d removals were refused, want exactly 1", round, refused)
		}
		if n := testutil.Count(t, `SELECT count(*) FROM group_member WHERE group_id = $1`, admins); n != 1 {
			t.Fatalf("round %d: %d administrators left, want 1", round, n)
		}
		// put both back for the next round
		testutil.AddMember(t, admins, seeded.ID)
		testutil.AddMember(t, admins, second.ID)
	}
}

func TestADeletedAccountLeavesItsGroups(t *testing.T) {
	testutil.Reset(t)
	g := testutil.Group(t, "crew", "")
	gone := testutil.AdminAccount(t, "gone")
	testutil.AddMember(t, g, gone.ID)
	if _, err := db.SoftDeleteAccount(gone.ID, ""); err != nil {
		t.Fatalf("deleting one of two administrators: %v", err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM group_member WHERE account_id = $1`, gone.ID); n != 0 {
		t.Errorf("a deleted account still has %d memberships", n)
	}
	if ok, _ := db.IsAdmin(gone.ID); ok {
		t.Error("a deleted account is still an administrator")
	}
}

// ---- Telling apps about group changes ----------------------------------------

func TestLeavingAGroupNotifiesOnlyTheAppsLinkedToIt(t *testing.T) {
	testutil.Reset(t)
	finance := testutil.Group(t, "finance", "")
	other := testutil.Group(t, "other", "")
	linked, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{BackchannelURI: "http://127.0.0.1:9/billing", GroupIDs: []string{finance}})
	unlinked, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{BackchannelURI: "http://127.0.0.1:9/wiki", GroupIDs: []string{other}})
	noHook, _ := testutil.CreateApp(t, "plain", testutil.AppOptions{GroupIDs: []string{finance}})
	user := testutil.CreateAccount(t, "carol")
	testutil.AddMember(t, finance, user.ID)

	live, _ := testutil.Session(t, user.ID)
	ended, _ := testutil.Session(t, user.ID)
	for _, s := range []string{live.ID, ended.ID} {
		for _, app := range []db.App{linked, unlinked, noHook} {
			db.TrackSessionApp(s, app.ID)
		}
	}
	if _, err := db.RevokeSession(ended.ID); err != nil {
		t.Fatal(err)
	}

	notices, err := db.GroupChangeLogoutNotices(user.ID, finance)
	if err != nil {
		t.Fatal(err)
	}
	if len(notices) != 1 || notices[0].ClientID != linked.ClientID || notices[0].SessionID != live.ID ||
		notices[0].AccountID != user.ID || notices[0].URI != "http://127.0.0.1:9/billing" {
		t.Fatalf("notices = %+v, want one for billing and the live session only", notices)
	}
	// someone who was never signed in to anything causes no notices
	if none, err := db.GroupChangeLogoutNotices(testutil.CreateAccount(t, "dave").ID, finance); err != nil || len(none) != 0 {
		t.Errorf("notices for an account without sessions: %+v, %v", none, err)
	}
}

// Covers: A27
func TestSingleAppGroupsAreBoundToOneAppForGood(t *testing.T) {
	testutil.Reset(t)
	grafana, _ := testutil.CreateApp(t, "grafana", testutil.AppOptions{})
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})

	// created bound: linked to its app, and to no other
	bound, err := db.CreateGroup("grafana-admins", "Grafana admins", "", "", grafana.ID)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := db.GetGroup(bound)
	if !g.SingleApp || g.BoundAppID != grafana.ID || g.BoundAt == nil || !slices.Equal(g.AppIDs, []string{grafana.ID}) {
		t.Fatalf("bound group = %+v", g)
	}
	if err := db.SetAppAccess(wiki.ID, "groups", []string{bound}); !errors.Is(err, db.ErrGroupBound) {
		t.Errorf("linking a bound group to another app: %v", err)
	}
	if _, err := db.AddApp(db.App{Name: "other", PrettyName: "Other", ClientType: "public", RedirectURIs: []string{"https://o.test/cb"},
		GroupIDs: []string{bound}}, nil, ""); !errors.Is(err, db.ErrGroupBound) {
		t.Errorf("a new app linked to a bound group: %v", err)
	}
	// its own app may unlink and link it again
	if err := db.SetAppAccess(grafana.ID, "groups", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAppAccess(grafana.ID, "groups", []string{bound}); err != nil {
		t.Errorf("linking a bound group to its own app: %v", err)
	}
	// a binding never moves
	if err := db.BindGroup(bound, wiki.ID); !errors.Is(err, db.ErrAlreadyBound) {
		t.Errorf("binding again: %v", err)
	}

	// an existing group can be bound only while it is linked to no other app
	plain := testutil.Group(t, "readers", "")
	if err := db.SetAppAccess(wiki.ID, "groups", []string{plain}); err != nil {
		t.Fatal(err)
	}
	if err := db.BindGroup(plain, grafana.ID); !errors.Is(err, db.ErrLinkedElsewhere) {
		t.Errorf("binding a group linked to another app: %v", err)
	}
	if err := db.BindGroup(plain, wiki.ID); err != nil {
		t.Errorf("binding a group to the app it is linked to: %v", err)
	}
	if err := db.BindGroup(testutil.GroupID(t, db.AdminGroupKey), grafana.ID); !errors.Is(err, db.ErrSystemGroup) {
		t.Errorf("binding a built-in group: %v", err)
	}
	if err := db.BindGroup(testutil.Group(t, "x", ""), "11111111-1111-1111-1111-111111111111"); !errors.Is(err, db.ErrAppNotFound) {
		t.Errorf("binding to an unknown app: %v", err)
	}
	if _, err := db.CreateGroup("y", "Y", "", "", "11111111-1111-1111-1111-111111111111"); !errors.Is(err, db.ErrAppNotFound) {
		t.Errorf("creating a group bound to an unknown app: %v", err)
	}
	if testutil.Count(t, `SELECT count(*) FROM user_group WHERE key = 'y'`) != 0 {
		t.Error("a refused bound group was created anyway")
	}

	// when the app is deleted the group stays, bound to nothing, and can never be linked again
	member := testutil.CreateAccount(t, "eve")
	testutil.AddMember(t, bound, member.ID)
	if err := db.RemoveApp(grafana.ID); err != nil {
		t.Fatal(err)
	}
	g, err = db.GetGroup(bound)
	if err != nil {
		t.Fatalf("the bound group went with its app: %v", err)
	}
	if !g.SingleApp || g.BoundAppID != "" || g.BoundAppDeletedAt == nil || g.MemberCount != 1 || len(g.AppIDs) != 0 {
		t.Errorf("after deleting its app: %+v", g)
	}
	if err := db.SetAppAccess(wiki.ID, "groups", []string{bound}); !errors.Is(err, db.ErrGroupBound) {
		t.Errorf("linking an orphaned single-app group: %v", err)
	}
	if err := db.BindGroup(bound, wiki.ID); !errors.Is(err, db.ErrAlreadyBound) {
		t.Errorf("binding an orphaned single-app group again: %v", err)
	}
}
