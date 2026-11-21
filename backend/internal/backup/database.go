package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// table is one table in a backup, in restore order: every table comes after the tables it refers to.
type table struct {
	name    string
	orderBy string
}

var tables = []table{
	{"account", "id"},
	{"app", "id"},
	{"app_secret", "id"},
	{"scope", "name"},
	{"app_scope", "app_id, scope_name"},
	{"account_consent", "account_id, app_id"},
	{"user_group", "id"},
	{"group_member", "group_id, account_id"},
	{"group_request", "id"},
	{"notification_setting", "account_id, kind"},
	{"notification_schedule", "account_id"},
	{"app_group", "app_id, group_id"},
	{"app_user", "app_id, account_id"},
	{"signing_key", "kid"},
	{"account_mfa", "id"},
	{"deletion_log", "account_id"},
	{auditLog, "id"}, // last: a backup without the audit log leaves out the last table
}

const auditLog = "audit_log"

// notBackedUp are the tables a backup leaves out: sign-in state that is worthless after a restore
// (everyone signs in again), one-time tokens, rate-limit counters and notifications waiting for a summary. A restore empties them. schema_revision and goose's own
// table belong to the schema, not to the data, and are neither backed up nor touched.
var notBackedUp = []string{"session", "authorization_code", "refresh_token", "session_app", "account_token", "rate_limit", "used_challenge", "notification_pending"}

var schemaTables = []string{"schema_revision", "goose_db_version"}

// Snapshot is one consistent view of the database, from which a backup is taken.
type Snapshot struct {
	tx        *sql.Tx
	withAudit bool
	// Counts are the rows each table contributes, from the same snapshot.
	Counts []TableCount
}

// OpenSnapshot starts a read-only, repeatable-read transaction and counts the rows to back up. Close it
// when done.
func OpenSnapshot(ctx context.Context, db *sql.DB, withAudit bool) (*Snapshot, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	s := &Snapshot{tx: tx, withAudit: withAudit}
	for _, t := range s.tables() {
		var n int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+t.name).Scan(&n); err != nil {
			tx.Rollback()
			return nil, err
		}
		s.Counts = append(s.Counts, TableCount{t.name, n})
	}
	return s, nil
}

// keyIDs returns the ids of the keyring keys the snapshot's encrypted values use.
func (s *Snapshot) keyIDs(ctx context.Context) ([]string, error) {
	rows, err := s.tx.QueryContext(ctx, `SELECT DISTINCT split_part(v, ':', 2) FROM (
		SELECT private_key_encrypted AS v FROM signing_key WHERE private_key_encrypted IS NOT NULL
		UNION ALL SELECT secret FROM account_mfa WHERE type = 'totp') x ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Snapshot) tables() []table {
	if s.withAudit {
		return tables
	}
	return tables[:len(tables)-1]
}

// Close ends the snapshot.
func (s *Snapshot) Close() { s.tx.Rollback() }

// line is one row in the payload.
type line struct {
	Table string          `json:"t"`
	Row   json.RawMessage `json:"r"`
}

// Dump writes every row of the snapshot, gzip-compressed, to w.
func (s *Snapshot) Dump(ctx context.Context, w io.Writer) error {
	gz := gzip.NewWriter(w)
	enc := json.NewEncoder(gz)
	for _, t := range s.tables() {
		if err := dumpTable(ctx, s.tx, enc, t); err != nil {
			return fmt.Errorf("back up %s: %w", t.name, err)
		}
	}
	return gz.Close()
}

func dumpTable(ctx context.Context, tx *sql.Tx, enc *json.Encoder, t table) error {
	rows, err := tx.QueryContext(ctx, `SELECT row_to_json(x)::text FROM `+t.name+` x ORDER BY `+t.orderBy)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			return err
		}
		if err := enc.Encode(line{t.name, json.RawMessage(row)}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ErrNotFresh means the target database already holds data that a restore would destroy.
var ErrNotFresh = errors.New("the database is in use: a restore only goes into a new installation " +
	"(no apps, no groups of its own, no account but the built-in admin, and nobody ever signed in)")

// CheckFresh refuses a database that holds anything a restore would destroy. A new installation qualifies:
// the seed data, and the built-in admin with its first password, as long as nobody has signed in yet.
func CheckFresh(ctx context.Context, db *sql.DB) error {
	var apps, groups, accounts, signedIn, sessions int64
	err := db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM app),
		(SELECT count(*) FROM user_group WHERE NOT is_system),
		(SELECT count(*) FROM account),
		(SELECT count(*) FROM account WHERE last_login_at IS NOT NULL),
		(SELECT count(*) FROM session)`).Scan(&apps, &groups, &accounts, &signedIn, &sessions)
	if err != nil {
		return err
	}
	if apps > 0 || groups > 0 || accounts > 1 || signedIn > 0 || sessions > 0 {
		return fmt.Errorf("%w; found %d apps, %d groups, %d accounts (%d have signed in) and %d sessions",
			ErrNotFresh, apps, groups, accounts, signedIn, sessions)
	}
	return nil
}

// restoreRows replaces the database's data with the rows read from payload (the decrypted, still
// compressed payload), inside tx. It empties every table it restores and the sign-in tables, inserts the rows, and
// checks the counts against the manifest. The caller commits or rolls back.
func restoreRows(ctx context.Context, tx *sql.Tx, payload io.Reader, m Manifest) ([]TableCount, error) {
	var names []string
	for _, t := range tables {
		names = append(names, t.name)
	}
	names = append(names, notBackedUp...)
	if _, err := tx.ExecContext(ctx, `TRUNCATE `+strings.Join(names, ", ")+` RESTART IDENTITY`); err != nil {
		return nil, fmt.Errorf("empty the tables: %w", err)
	}

	gz, err := gzip.NewReader(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: the payload is not compressed data: %v", ErrDamaged, err)
	}
	ins := &inserter{ctx: ctx, tx: tx, counts: map[string]int64{}}
	dec := json.NewDecoder(gz)
	for {
		var l line
		if err := dec.Decode(&l); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("%w: unreadable row: %v", ErrDamaged, err)
		}
		if err := ins.add(l); err != nil {
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	if err := ins.flush(); err != nil {
		return nil, err
	}
	if err := ins.finish(); err != nil {
		return nil, err
	}

	var out []TableCount
	for _, t := range tables {
		want, listed := m.Rows(t.name)
		got := ins.counts[t.name]
		if !listed && got == 0 {
			continue
		}
		if got != want {
			return nil, fmt.Errorf("%w: %s has %d rows, the manifest says %d", ErrDamaged, t.name, got, want)
		}
		out = append(out, TableCount{t.name, got})
	}
	return out, nil
}

// inserter collects rows of one table and inserts them in batches.
type inserter struct {
	ctx     context.Context
	tx      *sql.Tx
	counts  map[string]int64
	table   string
	batch   []json.RawMessage
	size    int
	owners  map[string]json.RawMessage // user_group id -> owner_group_id, set once every group exists
	reached int                        // index in tables of the latest table seen
}

const batchBytes = 1 << 20

func (in *inserter) add(l line) error {
	idx := -1
	for i, t := range tables {
		if t.name == l.Table {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("%w: unknown table %q", ErrDamaged, l.Table)
	}
	if idx < in.reached {
		return fmt.Errorf("%w: rows of %s come after rows of %s", ErrDamaged, l.Table, tables[in.reached].name)
	}
	in.reached = idx
	if l.Table != in.table {
		if err := in.flush(); err != nil {
			return err
		}
		in.table = l.Table
	}
	row := l.Row
	if l.Table == "user_group" {
		// A group may name an owner group that comes later; set owners after every group is in.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(row, &fields); err != nil {
			return fmt.Errorf("%w: unreadable group: %v", ErrDamaged, err)
		}
		if owner := fields["owner_group_id"]; len(owner) > 0 && string(owner) != "null" {
			if in.owners == nil {
				in.owners = map[string]json.RawMessage{}
			}
			in.owners[string(fields["id"])] = owner
			fields["owner_group_id"] = json.RawMessage("null")
			row, _ = json.Marshal(fields)
		}
	}
	in.batch = append(in.batch, row)
	in.size += len(row)
	in.counts[l.Table]++
	if in.size >= batchBytes {
		return in.flush()
	}
	return nil
}

func (in *inserter) flush() error {
	if len(in.batch) == 0 {
		return nil
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, r := range in.batch {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(r)
	}
	buf.WriteByte(']')
	overriding := ""
	if in.table == auditLog {
		overriding = " OVERRIDING SYSTEM VALUE"
	}
	q := `INSERT INTO ` + in.table + overriding + ` SELECT * FROM json_populate_recordset(NULL::` + in.table + `, $1::json)`
	if _, err := in.tx.ExecContext(in.ctx, q, buf.String()); err != nil {
		return fmt.Errorf("restore %s: %w", in.table, err)
	}
	in.batch, in.size = in.batch[:0], 0
	return nil
}

func (in *inserter) finish() error {
	for id, owner := range in.owners {
		if _, err := in.tx.ExecContext(in.ctx, `UPDATE user_group SET owner_group_id = ($1::json->>0)::uuid WHERE id = ($2::json->>0)::uuid`,
			"["+string(owner)+"]", "["+id+"]"); err != nil {
			return fmt.Errorf("restore group owners: %w", err)
		}
	}
	// The audit log's ids were restored as they were; new entries continue after the highest one.
	_, err := in.tx.ExecContext(in.ctx, `SELECT setval(pg_get_serial_sequence('audit_log', 'id'), COALESCE(max(id), 0) + 1, false) FROM audit_log`)
	return err
}
