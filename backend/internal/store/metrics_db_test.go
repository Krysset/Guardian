package store_test

import (
	"testing"
	"time"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// The counts behind /metrics: accounts by status and second factor, administrators without one, live
// sessions in total and per app (a session in two apps is one session and two app sessions; ended ones
// count nowhere), apps, groups, and the signing key.
//
// Covers: P6
func TestCountsForMetrics(t *testing.T) {
	testutil.Reset(t)
	const idle = time.Hour
	base, err := db.CountForMetrics(idle)
	if err != nil {
		t.Fatal(err)
	}

	alice := testutil.CreateAccount(t, "alice")
	testutil.EnableTOTP(t, alice.ID)
	bob := testutil.CreateAccount(t, "bob")
	testutil.AddMember(t, testutil.GroupID(t, db.AdminGroupKey), bob.ID) // an administrator without two-factor
	carol := testutil.CreateAccount(t, "carol")
	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, carol.ID)
	if _, err := db.CreatePendingAccount("dave", "x"); err != nil {
		t.Fatal(err)
	}
	erin := testutil.CreateAccount(t, "erin")
	testutil.Exec(t, `UPDATE account SET deleted_at = now() WHERE id = $1`, erin.ID)

	one, _ := testutil.CreateApp(t, "one", testutil.AppOptions{})
	two, _ := testutil.CreateApp(t, "two", testutil.AppOptions{})
	three, _ := testutil.CreateApp(t, "three", testutil.AppOptions{})
	testutil.Exec(t, `UPDATE app SET enabled = FALSE WHERE id = $1`, three.ID)
	testutil.Group(t, "shared-group", "")
	if _, err := db.CreateGroup("one-only", "One only", "", "", one.ID); err != nil {
		t.Fatal(err)
	}

	s1, _ := testutil.Session(t, alice.ID)
	s2, _ := testutil.Session(t, alice.ID)
	ended, _ := testutil.Session(t, bob.ID)
	idleOne, _ := testutil.Session(t, bob.ID)
	disabledOne, _ := testutil.Session(t, carol.ID)
	db.TrackSessionApp(s1.ID, one.ID)
	db.TrackSessionApp(s1.ID, two.ID)
	db.TrackSessionApp(s2.ID, one.ID)
	for _, s := range []db.Session{ended, idleOne, disabledOne} {
		db.TrackSessionApp(s.ID, one.ID)
	}
	if _, err := db.RevokeSession(ended.ID); err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, `UPDATE session SET last_seen_at = now() - interval '2 hours' WHERE id = $1`, idleOne.ID)

	c, err := db.CountForMetrics(idle)
	if err != nil {
		t.Fatal(err)
	}
	delta := func(name string, got, was, want int) {
		t.Helper()
		if got-was != want {
			t.Errorf("%s: went up by %d, want %d", name, got-was, want)
		}
	}
	delta("active accounts", c.Accounts["active"], base.Accounts["active"], 2)
	delta("disabled accounts", c.Accounts["disabled"], base.Accounts["disabled"], 1)
	delta("pending accounts", c.Accounts["pending"], base.Accounts["pending"], 1)
	delta("deleted accounts", c.Accounts["deleted"], base.Accounts["deleted"], 1)
	delta("accounts with an authenticator app", c.SecondFactor["authenticator_app"], base.SecondFactor["authenticator_app"], 1)
	delta("accounts without a second factor", c.SecondFactor["none"], base.SecondFactor["none"], 3) // bob, carol, dave
	delta("administrators without a second factor", c.AdminsWithoutSecondFactor, base.AdminsWithoutSecondFactor, 1)
	delta("live sessions", c.Sessions, base.Sessions, 2)
	if c.AppSessions["one"] != 2 || c.AppSessions["two"] != 1 {
		t.Errorf("app sessions = %v, want one: 2, two: 1", c.AppSessions)
	}
	if n, listed := c.AppSessions["three"]; !listed || n != 0 {
		t.Errorf("an app nobody uses must be listed with 0, got %v", c.AppSessions)
	}
	delta("enabled apps", c.Apps["enabled"], base.Apps["enabled"], 2)
	delta("disabled apps", c.Apps["disabled"], base.Apps["disabled"], 1)
	delta("shared groups", c.Groups["shared"], base.Groups["shared"], 1)
	delta("single-app groups", c.Groups["single_app"], base.Groups["single_app"], 1)
}
