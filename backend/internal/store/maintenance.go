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
		// Sign-ups whose email was never confirmed; their usernames become free again.
		`DELETE FROM account WHERE status = 'pending' AND last_login_at IS NULL
			AND created_at < now() - make_interval(secs => ` + strconv.Itoa(int(PendingSignupLifetime.Seconds())) + `)`,
	}
	for _, q := range stmts {
		if _, err := GetDatabaseConnection().Exec(q); err != nil {
			slog.Error("maintenance query failed", "error", err)
		}
	}
}

// LastBackupTime returns when the last backup was written (the newest backup.created audit entry), or the
// zero time if there is none.
func LastBackupTime() (time.Time, error) {
	var t sql.NullTime
	err := GetDatabaseConnection().QueryRow(`SELECT max(occurred_at) FROM audit_log WHERE event_type = 'backup.created'`).Scan(&t)
	return t.Time, err
}
