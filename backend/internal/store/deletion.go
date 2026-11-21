package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Account deletion (GDPR): deleted accounts wait out the grace period, can be restored until then, and
// are then erased. Erasing deletes the account and everything that hangs off it, removes IP addresses and
// personal details from its audit entries, and writes its id (nothing else) to the deletion log.

// DeletedAccount is an account in its grace period.
type DeletedAccount struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	DeletedAt  time.Time `json:"deleted_at"`
	EraseAfter time.Time `json:"erase_after"`
	DeletedBy  string    `json:"deleted_by,omitempty"` // account id; the account itself when it deleted itself
	// DeletedByUsername is who deleted it, while that account exists.
	DeletedByUsername string `json:"deleted_by_username,omitempty"`
	ByItself          bool   `json:"deleted_by_itself"`
}

const deletedColumns = `id, username, deleted_at, erase_after, COALESCE(deleted_by::text, ''), deleted_by = id,
	COALESCE((SELECT b.username FROM account b WHERE b.id = account.deleted_by), '')`

func scanDeleted(s scanner) (DeletedAccount, error) {
	var d DeletedAccount
	var self sql.NullBool
	err := s.Scan(&d.ID, &d.Username, &d.DeletedAt, &d.EraseAfter, &d.DeletedBy, &self, &d.DeletedByUsername)
	d.ByItself = self.Bool
	return d, err
}

// ListDeletedAccounts returns the accounts waiting to be erased, the soonest first.
func ListDeletedAccounts() ([]DeletedAccount, error) {
	rows, err := GetDatabaseConnection().Query(`SELECT ` + deletedColumns + ` FROM account
		WHERE deleted_at IS NOT NULL ORDER BY erase_after, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeletedAccount{}
	for rows.Next() {
		d, err := scanDeleted(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDeletedAccount returns an account in its grace period, or sql.ErrNoRows.
func GetDeletedAccount(id string) (DeletedAccount, error) {
	if !IsUUID(id) {
		return DeletedAccount{}, sql.ErrNoRows
	}
	return scanDeleted(GetDatabaseConnection().QueryRow(
		`SELECT `+deletedColumns+` FROM account WHERE id = $1 AND deleted_at IS NOT NULL`, id))
}

// RestoreAccount brings a deleted account back during its grace period: it is active again and gets back
// the group memberships it had, except in groups deleted since and memberships that have expired since.
// Its sessions stay ended. It returns the groups it is a member of again.
func RestoreAccount(id string) (int, error) {
	if !IsUUID(id) {
		return 0, sql.ErrNoRows
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var held []byte
	if err := tx.QueryRow(`SELECT COALESCE(held_memberships, '[]') FROM account WHERE id = $1 AND deleted_at IS NOT NULL FOR UPDATE`,
		id).Scan(&held); err != nil {
		return 0, err
	}
	res, err := tx.Exec(`INSERT INTO group_member (group_id, account_id, added_by, added_at, expires_at)
		SELECT h.group_id, $1, a.id, h.added_at, h.expires_at
		FROM jsonb_to_recordset($2::jsonb) AS h(group_id uuid, added_by uuid, added_at timestamptz, expires_at timestamptz)
		JOIN user_group g ON g.id = h.group_id
		LEFT JOIN account a ON a.id = h.added_by
		WHERE h.expires_at IS NULL OR h.expires_at > now()
		ON CONFLICT DO NOTHING`, id, string(held))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec(`UPDATE account SET deleted_at = NULL, deleted_by = NULL, erase_after = NULL,
		held_memberships = NULL, status = 'active', updated_at = now() WHERE id = $1`, id); err != nil {
		return 0, err
	}
	return int(n), tx.Commit()
}

// ErrNotDeleted means the account is not waiting to be erased: delete it first.
var ErrNotDeleted = errors.New("the account is not deleted")

// personalKeys are the audit metadata keys that can hold personal details; erasing an account removes them
// from its entries.
var personalKeys = []string{"username", "email", "login", "name", "display_name", "given_name", "family_name",
	"picture_url", "pending_email", "user_agent"}

type execQuerier interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// EraseAccount erases a deleted account now. It refuses an account that is not deleted (ErrNotDeleted).
func EraseAccount(id string) error {
	if !IsUUID(id) {
		return sql.ErrNoRows
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deleted bool
	if err := tx.QueryRow(`SELECT deleted_at IS NOT NULL FROM account WHERE id = $1 FOR UPDATE`, id).Scan(&deleted); err != nil {
		return err
	}
	if !deleted {
		return ErrNotDeleted
	}
	if err := EraseAccountTx(tx, id); err != nil {
		return err
	}
	return tx.Commit()
}

// EraseAccountTx erases an account inside tx, whatever its state, and records it in the deletion log. An
// account that no longer exists is only recorded. The backup package uses it to apply a deletion log.
func EraseAccountTx(tx execQuerier, id string) error {
	stmts := []string{
		// Sessions, tokens, two-factor, consents, memberships and app records go with the account (CASCADE).
		`DELETE FROM account WHERE id = $1`,
		`UPDATE audit_log SET ip_address = NULL, metadata = metadata - $2::text[]
		 WHERE actor_account_id = $1 OR target_id = $1::text OR metadata->>'target' = $1::text OR metadata->>'account' = $1::text`,
		`INSERT INTO deletion_log (account_id) VALUES ($1) ON CONFLICT DO NOTHING`,
	}
	for i, q := range stmts {
		var err error
		if i == 1 {
			_, err = tx.Exec(q, id, strArray(personalKeys))
		} else {
			_, err = tx.Exec(q, id)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// EraseDueAccounts erases the accounts whose grace period has ended and returns their ids.
func EraseDueAccounts() ([]string, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT id FROM account WHERE deleted_at IS NOT NULL AND erase_after <= now() ORDER BY erase_after LIMIT 500`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	var erased []string
	for _, id := range ids {
		if err := EraseAccount(id); err != nil {
			return erased, err
		}
		erased = append(erased, id)
	}
	return erased, nil
}

// Deletion is one entry of the deletion log.
type Deletion struct {
	AccountID string    `json:"account_id"`
	ErasedAt  time.Time `json:"erased_at"`
}

// ListDeletions returns the deletion log, oldest first.
func ListDeletions(ctx context.Context, db *sql.DB) ([]Deletion, error) {
	rows, err := db.QueryContext(ctx, `SELECT account_id, erased_at FROM deletion_log ORDER BY erased_at, account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Deletion{}
	for rows.Next() {
		var d Deletion
		if err := rows.Scan(&d.AccountID, &d.ErasedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ExportAccountData is "download my data": everything Guardian holds about the account, except secrets
// (password hash, two-factor secrets, token hashes).
func ExportAccountData(id string) (map[string]any, error) {
	acct, err := GetAccount(id)
	if err != nil {
		return nil, err
	}
	mfa, err := GetMFAStatus(id)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"exported_at": time.Now().UTC(), "account": acct, "two_factor": mfa}
	queries := []struct{ key, q string }{
		{"groups", `SELECT g.key, g.display_name, m.added_at, m.expires_at FROM group_member m
			JOIN user_group g ON g.id = m.group_id WHERE m.account_id = $1 ORDER BY g.key`},
		{"group_requests", `SELECT g.display_name AS group, q.message, q.created_at, q.decision, q.decided_at FROM group_request q
			JOIN user_group g ON g.id = q.group_id WHERE q.account_id = $1 ORDER BY q.created_at DESC`},
		{"notification_settings", `SELECT kind, delivery FROM notification_setting WHERE account_id = $1 ORDER BY kind`},
		{"notifications_waiting", `SELECT kind, title, created_at FROM notification_pending WHERE account_id = $1 ORDER BY created_at`},
		{"consents", `SELECT a.pretty_name AS app, c.scopes, c.granted_at, c.revoked_at FROM account_consent c
			JOIN app a ON a.id = c.app_id WHERE c.account_id = $1 ORDER BY a.pretty_name`},
		{"apps_used", `SELECT a.pretty_name AS app, u.first_signed_in_at, u.last_signed_in_at FROM app_user u
			JOIN app a ON a.id = u.app_id WHERE u.account_id = $1 ORDER BY a.pretty_name`},
		{"sessions", `SELECT created_at, last_seen_at, expires_at, revoked_at, host(ip_address) AS ip_address, user_agent, amr
			FROM session WHERE account_id = $1 ORDER BY created_at DESC`},
		{"audit_log", `SELECT occurred_at, event_type, host(ip_address) AS ip_address, metadata FROM audit_log
			WHERE actor_account_id = $1 OR target_id = $1::text OR metadata->>'target' = $1::text OR metadata->>'account' = $1::text
			ORDER BY occurred_at DESC LIMIT 5000`},
	}
	for _, q := range queries {
		var raw []byte
		if err := GetDatabaseConnection().QueryRow(
			`SELECT COALESCE(json_agg(row_to_json(x)), '[]') FROM (`+q.q+`) x`, id).Scan(&raw); err != nil {
			return nil, err
		}
		out[q.key] = json.RawMessage(raw)
	}
	return out, nil
}
