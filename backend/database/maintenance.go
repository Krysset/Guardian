package database

import (
	"context"
	"log"
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
		`DELETE FROM access_token WHERE expires_at < now() - interval '1 day'`,
		`DELETE FROM authorization_code WHERE expires_at < now() - interval '1 day'`,
		`DELETE FROM refresh_token WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days'`,
		`DELETE FROM account_token WHERE expires_at < now() - interval '7 days'`,
		`DELETE FROM session WHERE expires_at < now() - interval '30 days'`,
		`DELETE FROM rate_limit WHERE window_start < now() - interval '1 day'`,
	}
	for _, q := range stmts {
		if _, err := GetDatabaseConnection().Exec(q); err != nil {
			log.Println("Maintenance query failed:", err)
		}
	}
}
