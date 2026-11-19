package backup

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"guardian/migrations"
)

// Options are what the backup and restore commands take from the running configuration and the command line.
type Options struct {
	Issuer           string // ISSUER_URL
	KeyEncryptionKey []byte // KEY_ENCRYPTION_KEY
	Execute          bool
	Reason           string
}

// BackupOptions configure `guardian backup`.
type BackupOptions struct {
	Options
	// Recipients are age public keys, one per line; blank lines and # comments are ignored.
	Recipients string
	WithAudit  bool
}

// RestoreOptions configure `guardian restore`.
type RestoreOptions struct {
	Options
	// Confirm is the issuer host, typed back.
	Confirm string
	// Identities holds age private keys, for a backup that is still encrypted. Nil for a decrypted one.
	Identities io.Reader
	// AllowOtherIssuer restores a backup taken under another issuer URL.
	AllowOtherIssuer bool
}

// RecipientList returns the recipients without blank lines and comments.
func RecipientList(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// Backup writes a backup to out and a summary to report. Without Execute it only counts the rows and
// checks the recipients: nothing is written to out and nothing is audited.
func Backup(ctx context.Context, db *sql.DB, opt BackupOptions, out, report io.Writer) error {
	recipients := RecipientList(opt.Recipients)
	if len(recipients) == 0 {
		return errors.New("no recipient: give the age public key to encrypt the backup to (--recipient or --recipients-file)")
	}
	// Encrypting nothing checks that every recipient is a valid public key, before any work is done.
	if w, err := Encrypt(io.Discard, opt.Recipients); err != nil {
		return err
	} else if err := w.Close(); err != nil {
		return err
	}
	if opt.Execute && strings.TrimSpace(opt.Reason) == "" {
		return errors.New("--reason is required with --execute: say why this backup is taken (it goes into the audit log)")
	}

	snap, err := OpenSnapshot(ctx, db, opt.WithAudit)
	if err != nil {
		return err
	}
	defer snap.Close()
	if !opt.Execute {
		fmt.Fprintln(report, "Dry run: nothing was written. A backup would contain:")
		printCounts(report, snap.Counts)
		fmt.Fprintf(report, "It would be encrypted to %d recipient(s). Run again with --execute and --reason to write it.\n", len(recipients))
		return nil
	}

	m := Manifest{
		SchemaRevision:     migrations.InitFingerprint,
		CreatedAt:          time.Now().UTC().Truncate(time.Second),
		Issuer:             opt.Issuer,
		KeyEncryptionKeyID: KeyID(opt.KeyEncryptionKey),
		Encryption:         EncryptionAge,
		Recipients:         recipients,
		AuditLogIncluded:   opt.WithAudit,
		Tables:             snap.Counts,
	}
	w, err := NewWriter(out, m)
	if err != nil {
		return err
	}
	enc, err := Encrypt(w, opt.Recipients)
	if err != nil {
		return err
	}
	if err := snap.Dump(ctx, enc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	snap.Close()

	size, sum := w.Sum()
	if err := audit(ctx, db, "backup.created", map[string]any{
		"reason": opt.Reason, "created_at": m.CreatedAt, "size": size, "sha256": sum, "recipients": recipients,
		"audit_log_included": opt.WithAudit, "tables": countMap(m.Tables),
	}); err != nil {
		return fmt.Errorf("the backup was written, but recording it in the audit log failed: %w", err)
	}
	fmt.Fprintf(report, "Backup written: %d bytes, sha256 %s, taken %s.\n", size, sum, m.CreatedAt.Format(time.RFC3339))
	printCounts(report, m.Tables)
	return nil
}

// Restore restores a backup read from in, and writes a summary to report. Without Execute it does the whole
// restore in a transaction and rolls it back, which proves the backup restores into this database.
func Restore(ctx context.Context, db *sql.DB, opt RestoreOptions, in io.Reader, report io.Writer) (err error) {
	if opt.Execute {
		host := IssuerHost(opt.Issuer)
		switch {
		case strings.TrimSpace(opt.Reason) == "":
			return errors.New("--reason is required with --execute: say why you restore (it goes into the audit log)")
		case opt.Confirm != host:
			return fmt.Errorf("--confirm must be this installation's issuer host, %q", host)
		}
		// A refused or failed restore is recorded too, outside the rolled-back transaction.
		defer func() {
			if err != nil {
				_ = audit(context.WithoutCancel(ctx), db, "backup.restore_failed", map[string]any{"reason": opt.Reason, "error": err.Error()})
			}
		}()
	}

	r, err := NewReader(in)
	if err != nil {
		return err
	}
	m := r.Manifest
	switch {
	case m.SchemaRevision != migrations.InitFingerprint:
		return fmt.Errorf("the backup is from another development version of Guardian (schema revision %s, this one has %s); "+
			"until 1.0 a backup only restores into the version that took it", m.SchemaRevision, migrations.InitFingerprint)
	case m.KeyEncryptionKeyID != KeyID(opt.KeyEncryptionKey):
		return fmt.Errorf("the backup's signing keys are encrypted with another KEY_ENCRYPTION_KEY (key id %s, this installation has %s); "+
			"set the key the backed-up installation used", m.KeyEncryptionKeyID, KeyID(opt.KeyEncryptionKey))
	case m.Issuer != opt.Issuer && !opt.AllowOtherIssuer:
		return fmt.Errorf("the backup was taken at %s, this installation is %s: apps would see a new issuer. "+
			"Add --allow-other-issuer if that is intended", m.Issuer, opt.Issuer)
	}
	if err := CheckFresh(ctx, db); err != nil {
		return err
	}

	payload := io.Reader(r)
	if m.Encryption == EncryptionAge {
		if opt.Identities == nil {
			return errors.New("the backup is encrypted: give the private key with --identity-file, or decrypt it first with `guardian backup decrypt`")
		}
		if payload, err = Decrypt(r, opt.Identities); err != nil {
			return err
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	counts, err := restoreRows(ctx, tx, payload, m)
	if err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, payload); err != nil {
		return fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	if err := r.Check(); err != nil {
		return err
	}

	if !opt.Execute {
		fmt.Fprintf(report, "Dry run: the backup taken %s at %s restores cleanly into this database; nothing was changed.\n",
			m.CreatedAt.Format(time.RFC3339), m.Issuer)
		printCounts(report, counts)
		fmt.Fprintf(report, "Run again with --execute, --reason and --confirm=%s to restore it.\n", IssuerHost(opt.Issuer))
		return nil
	}
	if err := audit(ctx, tx, "backup.restored", map[string]any{
		"reason": opt.Reason, "backup_created_at": m.CreatedAt, "backup_issuer": m.Issuer,
		"audit_log_included": m.AuditLogIncluded, "tables": countMap(counts),
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Fprintf(report, "Restored the backup taken %s at %s.\n", m.CreatedAt.Format(time.RFC3339), m.Issuer)
	printCounts(report, counts)
	fmt.Fprintln(report, "Restart Guardian now (kubectl rollout restart), so it loads the restored signing keys. "+
		"Then go through the post-restore checklist in docs/INSTALL.md.")
	return nil
}

// Verify checks a backup without touching any database: the manifest, and the payload against the trailer.
// With identities (or for a decrypted backup) it also decrypts the payload and counts the rows against the
// manifest, which proves the private key opens it.
func Verify(in io.Reader, identities io.Reader, report io.Writer) (Manifest, error) {
	r, err := NewReader(in)
	if err != nil {
		return Manifest{}, err
	}
	m := r.Manifest
	opened := m.Encryption == EncryptionNone || identities != nil
	if opened {
		payload := io.Reader(r)
		if m.Encryption == EncryptionAge {
			if payload, err = Decrypt(r, identities); err != nil {
				return m, err
			}
		}
		if err := countRows(payload, m); err != nil {
			return m, err
		}
		if _, err := io.Copy(io.Discard, payload); err != nil {
			return m, fmt.Errorf("%w: %v", ErrDamaged, err)
		}
	}
	if err := r.Check(); err != nil {
		return m, err
	}
	size, sum := r.Sum()
	fmt.Fprintf(report, "The backup is complete: taken %s at %s, format %d, schema revision %s.\n",
		m.CreatedAt.Format(time.RFC3339), m.Issuer, m.Format, m.SchemaRevision)
	fmt.Fprintf(report, "Payload: %d bytes, sha256 %s, encryption %s; signing keys need key id %s.\n",
		size, sum, m.Encryption, m.KeyEncryptionKeyID)
	printCounts(report, m.Tables)
	if opened {
		fmt.Fprintln(report, "The payload was opened and every row count matches the manifest.")
	} else {
		fmt.Fprintln(report, "The payload was not decrypted (give --identity-file to check the rows too).")
	}
	return m, nil
}

// DecryptFile turns an encrypted backup into a decrypted one, for a restore inside the cluster that must not
// see the private key. The output has no trailer if the input turns out to be damaged.
func DecryptFile(in io.Reader, identities io.Reader, out io.Writer) error {
	r, err := NewReader(in)
	if err != nil {
		return err
	}
	if r.Manifest.Encryption != EncryptionAge {
		return errors.New("the backup is not encrypted")
	}
	plain, err := Decrypt(r, identities)
	if err != nil {
		return err
	}
	m := r.Manifest
	m.Encryption, m.Recipients = EncryptionNone, nil
	w, err := NewWriter(out, m)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, plain); err != nil {
		return fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	if err := r.Check(); err != nil {
		return err
	}
	return w.Close()
}

// countRows reads the compressed rows and compares the count per table with the manifest.
func countRows(payload io.Reader, m Manifest) error {
	gz, err := gzip.NewReader(payload)
	if err != nil {
		return fmt.Errorf("%w: the payload is not compressed data: %v", ErrDamaged, err)
	}
	got := map[string]int64{}
	dec := json.NewDecoder(gz)
	for {
		var l line
		if err := dec.Decode(&l); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("%w: unreadable row: %v", ErrDamaged, err)
		}
		got[l.Table]++
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	for _, t := range m.Tables {
		if got[t.Name] != t.Rows {
			return fmt.Errorf("%w: %s has %d rows, the manifest says %d", ErrDamaged, t.Name, got[t.Name], t.Rows)
		}
		delete(got, t.Name)
	}
	for name := range got {
		return fmt.Errorf("%w: rows of %s, which the manifest does not list", ErrDamaged, name)
	}
	return nil
}

func printCounts(w io.Writer, counts []TableCount) {
	for _, c := range counts {
		fmt.Fprintf(w, "  %-16s %8d rows\n", c.Name, c.Rows)
	}
}

func countMap(counts []TableCount) map[string]int64 {
	out := map[string]int64{}
	for _, c := range counts {
		out[c.Name] = c.Rows
	}
	return out
}

// IssuerHost is the host part of the issuer URL, which a restore asks to have typed back.
func IssuerHost(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return issuer
	}
	return u.Host
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func audit(ctx context.Context, x execer, event string, meta map[string]any) error {
	meta["via"] = "cli"
	b, _ := json.Marshal(meta)
	_, err := x.ExecContext(ctx, `INSERT INTO audit_log (event_type, metadata) VALUES ($1, $2::jsonb)`, event, string(b))
	return err
}
