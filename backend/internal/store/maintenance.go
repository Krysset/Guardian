package store

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"time"
)

// StartMaintenance deletes expired rows (tokens, codes, sessions, counters) every hour until ctx ends.
// Safe to run on every replica: the deletes are idempotent.
func StartMaintenance(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			cleanup()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func cleanup() {
	stmts := []string{
		`DELETE FROM authorization_code WHERE expires_at < now() - interval '1 day'`,
		// Refresh tokens of ended sessions go when their session row is deleted below (ON DELETE CASCADE).
		`DELETE FROM refresh_token WHERE revoked_at < now() - interval '7 days'`,
		`DELETE FROM account_token WHERE expires_at < now() - interval '7 days'`,
		`DELETE FROM session WHERE expires_at < now() - interval '30 days'`,
		`DELETE FROM rate_limit WHERE window_start < now() - interval '1 day'`,
		`DELETE FROM used_challenge WHERE expires_at < now()`,
		pruneGroupRequests,
		// Sign-ups whose email was never confirmed; their usernames become free again.
		`DELETE FROM account WHERE status = 'pending' AND last_login_at IS NULL
			AND created_at < now() - make_interval(secs => ` + strconv.Itoa(int(PendingSignupLifetime.Seconds())) + `)`,
	}
	for _, q := range stmts {
		if _, err := GetDatabaseConnection().Exec(q); err != nil {
			slog.Error("maintenance query failed", "error", err)
		}
	}
	pruned, err := PruneAudit()
	if err != nil {
		slog.Error("removing old audit entries failed", "error", err)
	} else if pruned > 0 {
		slog.Info("removed audit entries past the retention period", "count", pruned)
	}
	groups, err := RemoveOrphanedSingleAppGroups()
	for _, g := range groups {
		Audit("group.deleted", "", "", "", map[string]any{"group": g.ID, "key": g.Key, "by": "schedule"})
	}
	if err != nil {
		slog.Error("removing single-app groups of deleted apps failed", "error", err)
	}
	// Deleted accounts whose grace period has ended.
	erased, err := EraseDueAccounts()
	for _, id := range erased {
		Audit("account.erased", "", "", "", map[string]any{"target": id, "by": "schedule"})
	}
	if err != nil {
		slog.Error("erasing deleted accounts failed", "error", err)
	}
	if len(erased) > 0 {
		slog.Info("erased deleted accounts", "count", len(erased))
	}
}

// LastBackupTime returns when the last backup was written (the newest backup.created audit entry), or the
// zero time if there is none.
func LastBackupTime() (time.Time, error) {
	var t sql.NullTime
	err := GetDatabaseConnection().QueryRow(`SELECT max(occurred_at) FROM audit_log WHERE event_type = 'backup.created'`).Scan(&t)
	return t.Time, err
}

// AuditRetention is how long audit entries are kept (AUDIT_RETENTION, about six months by default).
var AuditRetention = 183 * 24 * time.Hour

// auditPruneBatch keeps each delete short, so a large first clean-up never holds locks for long.
const auditPruneBatch = 5000

// PruneAudit deletes audit entries older than AuditRetention, oldest first and in batches, and returns how
// many it deleted. The deletion log is separate and is never pruned: restores need it.
func PruneAudit() (int64, error) {
	var total int64
	for {
		res, err := GetDatabaseConnection().Exec(
			`DELETE FROM audit_log WHERE id IN (
				SELECT id FROM audit_log WHERE occurred_at < now() - make_interval(secs => $1) ORDER BY id LIMIT $2)`,
			AuditRetention.Seconds(), auditPruneBatch)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < auditPruneBatch {
			return total, nil
		}
	}
}

// RemovedGroup names a group the clean-up removed.
type RemovedGroup struct{ ID, Key string }

// RemoveOrphanedSingleAppGroups deletes single-app groups whose app was deleted longer ago than
// AuditRetention (A27): by then no audit entry refers to the group's history any more.
func RemoveOrphanedSingleAppGroups() ([]RemovedGroup, error) {
	rows, err := GetDatabaseConnection().Query(
		`DELETE FROM user_group WHERE bound_app_deleted_at < now() - make_interval(secs => $1) AND NOT is_system
		 RETURNING id, key`, AuditRetention.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RemovedGroup
	for rows.Next() {
		var g RemovedGroup
		if err := rows.Scan(&g.ID, &g.Key); err != nil {
			return out, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
