package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"guardian/internal/auth"
	db "guardian/internal/store"
	"guardian/internal/testutil"
)

var (
	testRing  = mustRing("k1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	otherRing = mustRing("k1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	testIssur = "https://auth.test"
)

func mustRing(spec string) *auth.Keyring {
	r, err := auth.ParseKeyring(spec)
	if err != nil {
		panic(err)
	}
	return r
}

func opts(execute bool) Options {
	return Options{Issuer: testIssur, Keyring: testRing, Execute: execute, Reason: "test"}
}

// fresh empties the database like a new installation: seed data only, no signing key.
func fresh(t *testing.T) {
	t.Helper()
	testutil.Reset(t)
	testutil.DeleteSigningKeys()
}

// contents returns every backed-up table as JSON, ordered, for comparing two databases.
func contents(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tb := range tables {
		var s string
		q := `SELECT COALESCE(json_agg(row_to_json(x) ORDER BY ` + tb.orderBy + `), '[]')::text FROM ` + tb.name + ` x`
		if tb.name == auditLog {
			q = `SELECT COALESCE(json_agg(row_to_json(x) ORDER BY id), '[]')::text FROM audit_log x WHERE event_type NOT LIKE 'backup.%'`
		}
		if err := db.GetDatabaseConnection().QueryRow(q).Scan(&s); err != nil {
			t.Fatal(err)
		}
		out[tb.name] = s
	}
	return out
}

// populate fills every backed-up table with rows that use every column type of the schema.
func populate(t *testing.T) {
	t.Helper()
	alice := testutil.CreateAccount(t, "alice")
	bob := testutil.CreateAccount(t, "bob")
	testutil.Exec(t, `UPDATE account SET email = 'alice@example.com', display_name = 'Alice Ö', last_login_at = now() WHERE id = $1`, alice.ID)
	owners := testutil.Group(t, "owners", "")
	staff := testutil.Group(t, "staff", owners)
	// An owner group that sorts after the group it owns, whatever the generated ids.
	testutil.Exec(t, `UPDATE user_group SET owner_group_id = $1 WHERE id = $2`, staff, owners)
	testutil.Exec(t, `UPDATE user_group SET owner_group_id = NULL WHERE id = $1`, staff)
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{GroupIDs: []string{staff}, Scopes: []string{"openid", "groups"}})
	if _, err := db.CreateGroup("billing-admins", "Billing admins", "", "", app.ID); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(48 * time.Hour)
	if err := db.AddGroupMember(staff, alice.ID, bob.ID, &exp); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveConsent(alice.ID, app.ID, []string{"openid", "groups"}); err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, `INSERT INTO scope (name, description, claims, app_id) VALUES ('billing:read', 'Your invoices', ARRAY['inv'], $1)`, app.ID)
	testutil.Exec(t, `INSERT INTO app_user (app_id, account_id) VALUES ($1, $2)`, app.ID, alice.ID)
	testutil.Exec(t, `INSERT INTO signing_key (kid, public_jwk, private_key_encrypted, status, retire_at)
		VALUES ('k1', '{"kty":"RSA","n":"abc"}', 'v1:k1:c2VhbGVk', 'retiring', now())`)
	testutil.Exec(t, `INSERT INTO account_mfa (account_id, type, name, credential_id, public_key, sign_count)
		VALUES ($1, 'webauthn', 'YubiKey', '\x00ff10'::bytea, '\xdead'::bytea, 7)`, alice.ID)
	testutil.Exec(t, `INSERT INTO audit_log (event_type, actor_account_id, ip_address, metadata)
		VALUES ('login.success', $1, '2001:db8::1', '{"k":[1,"two"]}')`, alice.ID)
	testutil.Exec(t, `INSERT INTO deletion_log (account_id, erased_at) VALUES (gen_random_uuid(), now() - interval '3 days')`)
	testutil.Exec(t, `INSERT INTO session (account_id, session_hash, expires_at, ip_address) VALUES ($1, 'h', now() + interval '1 day', '10.0.0.1')`, alice.ID)
}

func takeBackup(t *testing.T, withAudit bool) (file []byte, identity string) {
	t.Helper()
	recipient, identity := newKey(t)
	var out, report bytes.Buffer
	err := Backup(context.Background(), db.GetDatabaseConnection(),
		BackupOptions{Options: opts(true), Recipients: "# test key\n" + recipient, WithAudit: withAudit}, &out, &report)
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), identity
}

func TestBackupRestoresIntoAFreshInstallationExactly(t *testing.T) {
	testutil.RequireTestDB(t)
	ctx := context.Background()
	conn := db.GetDatabaseConnection()
	fresh(t)
	populate(t)
	before := contents(t)
	file, identity := takeBackup(t, true)
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'backup.created' AND metadata->>'reason' = 'test'`) != 1 {
		t.Error("the backup is not in the audit log")
	}
	if bytes.Contains(file, []byte("alice")) {
		t.Fatal("the backup file contains plaintext personal data")
	}

	var report bytes.Buffer
	m, err := Verify(bytes.NewReader(file), strings.NewReader(identity), &report)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n, _ := m.Rows("account"); n != 3 || !m.AuditLogIncluded || strings.Join(m.KeyringKeys, ",") != "k1:"+testRing.Fingerprints()["k1"] {
		t.Errorf("manifest = %+v", m)
	}

	restore := func(o RestoreOptions, f []byte) error {
		return Restore(ctx, conn, o, bytes.NewReader(f), &bytes.Buffer{})
	}
	withKey := func(execute bool) RestoreOptions {
		return RestoreOptions{Options: opts(execute), Confirm: "auth.test", Identities: strings.NewReader(identity)}
	}

	// The database in use is refused, even for a dry run.
	if err := restore(withKey(false), file); !errors.Is(err, ErrNotFresh) {
		t.Fatalf("restore into a database in use: %v", err)
	}

	fresh(t)
	if err := restore(withKey(false), file); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if testutil.Count(t, `SELECT count(*) FROM app`) != 0 {
		t.Fatal("the dry run changed the database")
	}

	refused := map[string]RestoreOptions{
		"no --confirm":    {Options: opts(true), Identities: strings.NewReader(identity)},
		"wrong --confirm": {Options: opts(true), Confirm: "other.test", Identities: strings.NewReader(identity)},
		"no --reason":     {Options: Options{Issuer: testIssur, Keyring: testRing, Execute: true}, Confirm: "auth.test"},
		"no identity":     {Options: opts(true), Confirm: "auth.test"},
		"other KEK":       {Options: Options{Issuer: testIssur, Keyring: otherRing, Execute: true, Reason: "x"}, Confirm: "auth.test"},
		"other issuer":    {Options: Options{Issuer: "https://new.test", Keyring: testRing, Execute: true, Reason: "x"}, Confirm: "new.test"},
		"wrong identity":  {Options: opts(true), Confirm: "auth.test", Identities: strings.NewReader(func() string { _, id := newKey(t); return id }())},
		"damaged file":    withKey(true),
	}
	for name, o := range refused {
		f := file
		if name == "damaged file" {
			f = file[:len(file)-200]
		}
		if err := restore(o, f); err == nil {
			t.Errorf("%s: restore went ahead", name)
		}
	}
	if testutil.Count(t, `SELECT count(*) FROM app`) != 0 {
		t.Fatal("a refused restore changed the database")
	}
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'backup.restore_failed'`) == 0 {
		t.Error("refused restores are not audited")
	}

	// Decrypt outside the cluster, restore the decrypted file without the key.
	var plain bytes.Buffer
	if err := DecryptFile(bytes.NewReader(file), strings.NewReader(identity), &plain); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bytes.NewReader(plain.Bytes()), nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify the decrypted file: %v", err)
	}
	if err := restore(RestoreOptions{Options: opts(true), Confirm: "auth.test"}, plain.Bytes()); err != nil {
		t.Fatalf("restore: %v", err)
	}

	after := contents(t)
	for _, tb := range tables {
		if before[tb.name] != after[tb.name] {
			t.Errorf("%s differs after the restore:\nbefore %s\nafter  %s", tb.name, before[tb.name], after[tb.name])
		}
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session`); n != 0 {
		t.Errorf("%d sessions restored; sign-in state is not backed up", n)
	}
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'backup.restored'`) != 1 {
		t.Error("the restore is not in the audit log")
	}
	// New audit entries continue after the restored ids.
	db.Audit("test.after_restore", "", "", "", nil)
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'test.after_restore'
		AND id > (SELECT max(id) FROM audit_log WHERE event_type <> 'test.after_restore')`) != 1 {
		t.Error("the audit log's identity was not moved past the restored rows")
	}
}

func TestBackupWithoutAuditLogAndDryRun(t *testing.T) {
	testutil.RequireTestDB(t)
	ctx := context.Background()
	conn := db.GetDatabaseConnection()
	fresh(t)
	populate(t)
	recipient, _ := newKey(t)

	var out, report bytes.Buffer
	if err := Backup(ctx, conn, BackupOptions{Options: opts(false), Recipients: recipient, WithAudit: true}, &out, &report); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || !strings.Contains(report.String(), "Dry run") || !strings.Contains(report.String(), "account") {
		t.Errorf("dry run wrote %d bytes, reported %q", out.Len(), report.String())
	}
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'backup.created'`) != 0 {
		t.Error("a dry run was audited as a backup")
	}
	for name, o := range map[string]BackupOptions{
		"no recipient":  {Options: opts(true)},
		"bad recipient": {Options: opts(true), Recipients: "age1notakey"},
		"no reason":     {Options: Options{Issuer: testIssur, Keyring: testRing, Execute: true}, Recipients: recipient},
	} {
		if err := Backup(ctx, conn, o, &out, &report); err == nil {
			t.Errorf("%s: backup went ahead", name)
		}
	}

	file, identity := takeBackup(t, false)
	m, err := Verify(bytes.NewReader(file), nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, listed := m.Rows(auditLog); listed || m.AuditLogIncluded {
		t.Error("the audit log is in a backup taken without it")
	}
	fresh(t)
	err = Restore(ctx, conn, RestoreOptions{Options: opts(true), Confirm: "auth.test", Identities: strings.NewReader(identity)},
		bytes.NewReader(file), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log`); n != 1 {
		t.Errorf("%d audit entries after restoring without the audit log, want only the restore itself", n)
	}
}

// A new table must be backed up or left out on purpose; this catches one that is neither.
func TestEveryTableIsBackedUpOrLeftOutOnPurpose(t *testing.T) {
	testutil.RequireTestDB(t)
	rows, err := db.GetDatabaseConnection().Query(`SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	known := slices.Concat(notBackedUp, schemaTables)
	for _, tb := range tables {
		known = append(known, tb.name)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(known, name) {
			t.Errorf("table %s is neither in the backup nor in notBackedUp (internal/backup/database.go)", name)
		}
	}
}

func TestRestoreAppliesANewerDeletionLog(t *testing.T) {
	testutil.RequireTestDB(t)
	ctx := context.Background()
	conn := db.GetDatabaseConnection()
	fresh(t)
	keep := testutil.CreateAccount(t, "keep")
	gone := testutil.CreateAccount(t, "gone")
	file, identity := takeBackup(t, true)

	// After the backup, "gone" is deleted and erased; the deletion log says so.
	if _, err := db.SoftDeleteAccount(gone.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.EraseAccount(gone.ID); err != nil {
		t.Fatal(err)
	}
	var exported bytes.Buffer
	if n, err := ExportDeletions(ctx, conn, &exported); err != nil || n != 1 {
		t.Fatalf("export: %d %v", n, err)
	}
	deletions, err := ReadDeletions(bytes.NewReader(exported.Bytes()))
	if err != nil || len(deletions) != 1 || deletions[0].AccountID != gone.ID {
		t.Fatalf("read back: %v %v", deletions, err)
	}

	fresh(t)
	var report bytes.Buffer
	err = Restore(ctx, conn, RestoreOptions{Options: opts(true), Confirm: "auth.test", Identities: strings.NewReader(identity),
		Deletions: deletions}, bytes.NewReader(file), &report)
	if err != nil {
		t.Fatal(err)
	}
	if testutil.Count(t, `SELECT count(*) FROM account WHERE id = $1`, gone.ID) != 0 {
		t.Error("the erased account came back with the backup")
	}
	if testutil.Count(t, `SELECT count(*) FROM account WHERE id = $1`, keep.ID) != 1 {
		t.Error("an account that was not erased is missing")
	}
	if testutil.Count(t, `SELECT count(*) FROM deletion_log WHERE account_id = $1`, gone.ID) != 1 {
		t.Error("the restored deletion log lacks the applied entry")
	}
	if !strings.Contains(report.String(), "1 accounts erased") {
		t.Errorf("report: %s", report.String())
	}
	for _, bad := range []string{"", "GUARDIAN-DELETIONS 1\nnot json\n", "GUARDIAN-DELETIONS 1\n{\"account_id\":\"x\"}\n"} {
		if _, err := ReadDeletions(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
