package store_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// runbookSQL is the admin-recovery statement exactly as docs/INSTALL.md prints it, with the username put in.
func runbookSQL(t *testing.T, username string) string {
	t.Helper()
	b, err := os.ReadFile("../../../docs/INSTALL.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- runbook:admin-recovery[^>]*-->\\s*```sql\\n(.*?)```").FindSubmatch(b)
	if m == nil {
		t.Fatal("INSTALL.md lacks the admin-recovery SQL block")
	}
	return strings.ReplaceAll(string(m[1]), "NEW-ADMIN", username)
}

// The documented recovery for a locked-out sole administrator works as printed: it makes an active account
// an administrator for good, audits it, can be run twice, and leaves disabled or deleted accounts alone.
//
// Covers: P7
func TestTheRunbookRecoversALockedOutAdministrator(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "Sheikah")
	conn := db.GetDatabaseConnection()
	for i := 0; i < 2; i++ {
		if _, err := conn.Exec(runbookSQL(t, "sheikah")); err != nil {
			t.Fatalf("run %d of the runbook SQL: %v", i+1, err)
		}
	}
	if admin, err := db.IsAdmin(acct.ID); err != nil || !admin {
		t.Fatalf("after the runbook the account is an administrator: %v (%v)", admin, err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM group_member m JOIN user_group g ON g.id = m.group_id
		WHERE g.key = 'guardian-admins' AND m.account_id = $1 AND m.expires_at IS NULL`, acct.ID); n != 1 {
		t.Errorf("%d lasting admin memberships", n)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'account.admin_recovered' AND metadata->>'target' = $1`, acct.ID); n != 2 {
		t.Errorf("%d recoveries audited, want one per run", n)
	}

	disabled := testutil.CreateAccount(t, "yiga")
	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, disabled.ID)
	if _, err := conn.Exec(runbookSQL(t, "yiga")); err != nil {
		t.Fatal(err)
	}
	if admin, _ := db.IsAdmin(disabled.ID); admin {
		t.Error("the runbook made a disabled account an administrator")
	}
}
