package store_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"guardian/internal/auth"
	db "guardian/internal/store"
	"guardian/internal/testutil"
)

func strp(s string) *string { return &s }

func TestDisablingAnAccountEndsItsSessionsAndSparesTheLastAdmin(t *testing.T) {
	testutil.Reset(t)
	seeded, _, err := db.GetAccountByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	// the seeded admin is the only one: it cannot be disabled, and nothing changes
	if _, _, err := db.UpdateAccount(seeded.ID, db.AccountUpdate{DisplayName: strp("x"), Status: strp("disabled")}); !errors.Is(err, db.ErrLastAdmin) {
		t.Fatalf("disabling the last admin: %v, want ErrLastAdmin", err)
	}
	if a, _ := db.GetAccount(seeded.ID); a.Status != "active" || a.DisplayName != seeded.DisplayName {
		t.Errorf("a refused change was partly applied: %+v", a)
	}

	// with a second admin, either may be disabled
	other := testutil.AdminAccount(t, "second-admin")
	user := testutil.CreateAccount(t, "dora")
	hooked, _ := testutil.CreateApp(t, "hooked", testutil.AppOptions{BackchannelURI: "https://hooked.test/bcl"})
	sess, _ := testutil.Session(t, user.ID)
	db.TrackSessionApp(sess.ID, hooked.ID)
	testutil.Exec(t, `INSERT INTO refresh_token (token_hash, app_id, account_id, session_id, scopes)
		VALUES ('h1', $1, $2, $3, '{openid}')`, hooked.ID, user.ID, sess.ID)

	acct, notices, err := db.UpdateAccount(user.ID, db.AccountUpdate{Status: strp("disabled")})
	if err != nil || acct.Status != "disabled" {
		t.Fatalf("disable: %+v, %v", acct, err)
	}
	if len(notices) != 1 || notices[0].ClientID != hooked.ClientID || notices[0].SessionID != sess.ID {
		t.Errorf("notices = %+v, want one for the hooked app", notices)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE account_id = $1 AND revoked_at IS NULL`, user.ID); n != 0 {
		t.Errorf("%d sessions still live", n)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM refresh_token WHERE account_id = $1 AND revoked_at IS NULL`, user.ID); n != 0 {
		t.Errorf("%d refresh tokens still live", n)
	}
	if _, _, err := db.UpdateAccount(other.ID, db.AccountUpdate{Status: strp("disabled")}); err != nil {
		t.Errorf("disabling one of two admins: %v", err)
	}
	// re-enabling ends nothing and needs no lock dance
	if acct, notices, err := db.UpdateAccount(user.ID, db.AccountUpdate{Status: strp("active")}); err != nil || acct.Status != "active" || len(notices) != 0 {
		t.Errorf("re-enable: %+v, %v, %v", acct, notices, err)
	}
	if _, _, err := db.UpdateAccount("00000000-0000-0000-0000-000000000000", db.AccountUpdate{DisplayName: strp("x")}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("missing account: %v", err)
	}
}

func TestAccountUpdatesChangeOnlyWhatIsGiven(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "erin")
	testutil.CreateAccount(t, "taken")

	got, _, err := db.UpdateAccount(acct.ID, db.AccountUpdate{DisplayName: strp("Erin E"), Locale: strp("sv-SE")})
	if err != nil || got.DisplayName != "Erin E" || got.Locale != "sv-SE" || got.Username != "erin" {
		t.Fatalf("update: %+v, %v", got, err)
	}
	got, _, err = db.UpdateAccount(acct.ID, db.AccountUpdate{Locale: strp("")})
	if err != nil || got.Locale != "" || got.DisplayName != "Erin E" {
		t.Errorf("clearing one field: %+v, %v", got, err)
	}
	if _, _, err := db.UpdateAccount(acct.ID, db.AccountUpdate{Username: strp("TAKEN")}); !db.IsUniqueViolation(err) {
		t.Errorf("taken username (other case): %v, want a unique violation", err)
	}

	// an address set this way (by an administrator) counts as verified; removing it clears both
	got, _, err = db.UpdateAccount(acct.ID, db.AccountUpdate{Email: strp("erin@example.com")})
	if err != nil || got.Email != "erin@example.com" || !got.EmailVerified {
		t.Errorf("admin-set email: %+v, %v", got, err)
	}
	got, _, err = db.UpdateAccount(acct.ID, db.AccountUpdate{Email: strp("")})
	if err != nil || got.Email != "" || got.EmailVerified {
		t.Errorf("removed email: %+v, %v", got, err)
	}

	created, err := db.CreateAccountWithEmail("fred", "hash", "fred@example.com")
	if err != nil || !created.EmailVerified {
		t.Errorf("created with email: %+v, %v", created, err)
	}
	if created, err := db.CreateAccountWithEmail("gus", "hash", ""); err != nil || created.Email != "" || created.EmailVerified {
		t.Errorf("created without email: %+v, %v", created, err)
	}
}

func TestPasswordChangesEndTheRightSessions(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "hana")
	current, _ := testutil.Session(t, acct.ID)
	other, _ := testutil.Session(t, acct.ID)

	if _, err := db.RevokeOtherSessions(acct.ID, current.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetLiveSession(current.ID, idle); err != nil {
		t.Errorf("the session that changed the password must stay: %v", err)
	}
	if _, err := db.GetLiveSession(other.ID, idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("another session survived: %v", err)
	}

	if _, err := db.SetPasswordByAdmin(acct.ID, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetLiveSession(current.ID, idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("an admin-set password must end every session: %v", err)
	}
	if got, _ := db.GetAccount(acct.ID); !got.MustChangePassword {
		t.Error("an admin-set password must be changed at the next sign-in")
	}
	if hash, _ := db.GetPasswordHash(acct.ID); hash != "new-hash" {
		t.Errorf("hash = %q", hash)
	}
	if _, err := db.SetPasswordByAdmin("00000000-0000-0000-0000-000000000000", "x"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("missing account: %v", err)
	}
}

func TestListingAccountsSearchesAndPages(t *testing.T) {
	testutil.Reset(t)
	for _, u := range []string{"Anna", "bob", "carl", "dan_1", "dan21"} {
		testutil.CreateAccount(t, u)
	}
	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE username = 'carl'`)
	testutil.Exec(t, `UPDATE account SET email = 'robert@example.com' WHERE username = 'bob'`)
	gone := testutil.CreateAccount(t, "gone")
	if _, err := db.SoftDeleteAccount(gone.ID, ""); err != nil {
		t.Fatal(err)
	}
	names := func(f db.AccountFilter) string {
		t.Helper()
		if f.Limit == 0 {
			f.Limit = 50
		}
		accts, err := db.ListAccounts(f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range accts {
			out = append(out, a.Username)
		}
		return strings.Join(out, ",")
	}
	if got := names(db.AccountFilter{}); got != "admin,Anna,bob,carl,dan21,dan_1" {
		t.Errorf("all = %s (case-insensitive byte order, deleted accounts left out)", got)
	}
	if got := names(db.AccountFilter{Limit: 2}) + "|" + names(db.AccountFilter{After: "Anna", Limit: 2}); got != "admin,Anna|bob,carl" {
		t.Errorf("pages = %s", got)
	}
	if got := names(db.AccountFilter{Query: "ROBERT"}); got != "bob" {
		t.Errorf("search by email = %s", got)
	}
	if got := names(db.AccountFilter{Query: "dan_"}); got != "dan_1" {
		t.Errorf("an underscore in the search must match itself only, got %s", got)
	}
	if got := names(db.AccountFilter{Query: "%"}); got != "" {
		t.Errorf("a percent sign in the search must match itself only, got %s", got)
	}
	if got := names(db.AccountFilter{Status: "disabled"}); got != "carl" {
		t.Errorf("disabled = %s", got)
	}
}

func TestAccountGroupsListsActiveMemberships(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "ines")
	staff := testutil.Group(t, "staff", "")
	old := testutil.Group(t, "old", "")
	testutil.AddMember(t, staff, acct.ID)
	testutil.AddMember(t, old, acct.ID)
	testutil.Exec(t, `UPDATE group_member SET expires_at = now() - interval '1 minute' WHERE group_id = $1`, old)
	got, err := db.AccountGroups(acct.ID)
	if err != nil || len(got) != 1 || got[0].Key != "staff" || got[0].GroupID != staff {
		t.Errorf("groups = %+v, %v", got, err)
	}
}

func TestAppUpdatesAndSecretRotation(t *testing.T) {
	testutil.Reset(t)
	app, oldSecret := testutil.CreateApp(t, "notes", testutil.AppOptions{})

	got, err := db.UpdateApp(app.ID, db.AppUpdate{PrettyName: strp("Notes"), Scopes: &[]string{"openid", "email", "no-such-scope"}})
	if err != nil || got.PrettyName != "Notes" || strings.Join(got.Scopes, ",") != "email,openid" {
		t.Fatalf("update: %+v, %v", got, err)
	}
	if got.Name != "notes" || len(got.RedirectURIs) != 1 {
		t.Errorf("fields not given were changed: %+v", got)
	}
	off := false
	if got, err := db.UpdateApp(app.ID, db.AppUpdate{Enabled: &off}); err != nil || got.Enabled {
		t.Errorf("disable: %+v, %v", got, err)
	}
	if _, err := db.UpdateApp("00000000-0000-0000-0000-000000000000", db.AppUpdate{PrettyName: strp("x")}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("missing app: %v", err)
	}
	on := true
	db.UpdateApp(app.ID, db.AppUpdate{Enabled: &on})

	works := func(secret string) bool {
		_, err := db.GetAppByClientIDAndSecret(app.ClientID, auth.HashToken(secret))
		return err == nil
	}
	if err := db.RotateAppSecret(app.ID, auth.HashToken("second"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if !works(oldSecret) || !works("second") {
		t.Error("during the grace period both secrets must work")
	}
	if err := db.RotateAppSecret(app.ID, auth.HashToken("third"), 0); err != nil {
		t.Fatal(err)
	}
	if works(oldSecret) || works("second") || !works("third") {
		t.Error("without a grace period only the new secret may work")
	}
}

func TestAuditLogFiltersAndPages(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "jon")
	db.Audit("login.success", acct.ID, "", "203.0.113.9", map[string]any{"n": 1})
	db.Audit("login.failure", "", "", "", nil)
	db.Audit("login.success", acct.ID, "", "", map[string]any{"n": 2})

	all, err := db.ListAudit(db.AuditFilter{Limit: 50})
	if err != nil || len(all) < 3 || all[0].ID < all[1].ID {
		t.Fatalf("all: %+v, %v (newest first)", all, err)
	}
	mine, err := db.ListAudit(db.AuditFilter{AccountID: acct.ID, EventType: "login.success", Limit: 50})
	if err != nil || len(mine) != 2 || mine[0].Metadata["n"] != float64(2) {
		t.Fatalf("filtered: %+v, %v", mine, err)
	}
	if mine[1].IPAddress != "203.0.113.9" {
		t.Errorf("ip = %q", mine[1].IPAddress)
	}
	next, err := db.ListAudit(db.AuditFilter{AccountID: acct.ID, Before: mine[0].ID, Limit: 50})
	if err != nil || len(next) != 1 || next[0].ID != mine[1].ID {
		t.Errorf("page after the cursor: %+v, %v", next, err)
	}
}
