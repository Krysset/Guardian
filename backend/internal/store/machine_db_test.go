package store_test

import (
	"database/sql"
	"errors"
	"slices"
	"testing"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

func TestMachineAccessIsOnlyForAppsWithASecret(t *testing.T) {
	testutil.Reset(t)
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	spa, _ := testutil.CreateApp(t, "spa", testutil.AppOptions{Public: true})
	grants := func(id string) []string {
		a, err := db.GetApp(id)
		if err != nil {
			t.Fatal(err)
		}
		return a.GrantTypes
	}
	if slices.Contains(grants(app.ID), "client_credentials") {
		t.Fatal("machine access must be off until it is turned on")
	}
	for i := 0; i < 2; i++ { // turning it on twice leaves one entry
		if err := db.SetMachineAccess(app.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := grants(app.ID); len(got) != 3 || !slices.Contains(got, "client_credentials") {
		t.Errorf("grants after turning on = %v", got)
	}
	if err := db.SetMachineAccess(app.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := grants(app.ID); len(got) != 2 || slices.Contains(got, "client_credentials") {
		t.Errorf("grants after turning off = %v", got)
	}
	if err := db.SetMachineAccess(spa.ID, true); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("an app without a secret got machine access: %v", err)
	}
	if err := db.SetMachineAccess(spa.ID, false); err != nil {
		t.Errorf("turning machine access off must always work: %v", err)
	}
}

func TestAnAppSeesOnlyItsLinkedGroupsAndTheirActiveMembers(t *testing.T) {
	testutil.Reset(t)
	linked := testutil.Group(t, "billing-users", "")
	other := testutil.Group(t, "hr", "")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{GroupIDs: []string{linked}})
	alice := testutil.CreateAccount(t, "alice")
	bob := testutil.CreateAccount(t, "bob")
	gone := testutil.CreateAccount(t, "gone")
	expired := testutil.CreateAccount(t, "expired")
	for _, a := range []db.Account{alice, bob, gone, expired} {
		testutil.AddMember(t, linked, a.ID)
	}
	testutil.AddMember(t, other, alice.ID)
	expireMembership(t, linked, expired.ID)
	if _, err := db.SoftDeleteAccount(gone.ID, ""); err != nil {
		t.Fatal(err)
	}

	groups, err := db.ListAppGroups(app.ID)
	if err != nil || len(groups) != 1 || groups[0].Key != "billing-users" || groups[0].MemberCount != 2 {
		t.Fatalf("groups = %+v (%v), want billing-users with 2 active members", groups, err)
	}
	members, err := db.ListAppGroupMembers(app.ID, "billing-users")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range members {
		names = append(names, m.Username)
	}
	if !slices.Equal(names, []string{"alice", "bob"}) {
		t.Errorf("members = %v, want [alice bob] (no expired or deleted members)", names)
	}
	for _, key := range []string{"hr", "no-such-group"} {
		if _, err := db.ListAppGroupMembers(app.ID, key); !errors.Is(err, db.ErrGroupNotFound) {
			t.Errorf("group %q: %v, want ErrGroupNotFound", key, err)
		}
	}
}

func TestAnAppMayKnowItsGroupMembersAndItsUsersOnly(t *testing.T) {
	testutil.Reset(t)
	linked := testutil.Group(t, "staff", "")
	app, _ := testutil.CreateApp(t, "intranet", testutil.AppOptions{GroupIDs: []string{linked}})
	otherApp, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})
	member := testutil.CreateAccount(t, "member")
	user := testutil.CreateAccount(t, "user")
	stranger := testutil.CreateAccount(t, "stranger")
	testutil.AddMember(t, linked, member.ID)

	mayKnow := func(appID, accountID string) bool {
		ok, err := db.AppMayKnowAccount(appID, accountID)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !mayKnow(app.ID, member.ID) || mayKnow(app.ID, user.ID) || mayKnow(app.ID, stranger.ID) {
		t.Error("before any sign-in only members of linked groups are visible")
	}
	// signing in makes the account known to that app, and only that app
	if err := db.RecordAppUser(app.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAppUser(app.ID, user.ID); err != nil { // a second sign-in is fine
		t.Fatal(err)
	}
	if !mayKnow(app.ID, user.ID) || mayKnow(otherApp.ID, user.ID) {
		t.Error("a sign-in must make the account known to that app only")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM app_user WHERE app_id = $1`, app.ID); n != 1 {
		t.Errorf("%d app_user rows after two sign-ins, want 1", n)
	}
	// a membership that expired no longer counts
	expireMembership(t, linked, member.ID)
	if mayKnow(app.ID, member.ID) {
		t.Error("an expired membership still makes the account visible")
	}
	if mayKnow(app.ID, "not-a-uuid") || mayKnow(app.ID, "00000000-0000-0000-0000-000000000000") {
		t.Error("malformed or unknown ids must not be visible")
	}
}
