package store

import (
	"database/sql"
	"time"
)

// MetricCounts is the state of the installation that /metrics shows: totals only, never anything about one
// person. Every replica reads the same numbers from the same database.
type MetricCounts struct {
	// Accounts by status: active, pending (waiting for email confirmation), disabled, and deleted (in the
	// deletion grace period, whatever their status was).
	Accounts map[string]int
	// Accounts (not deleted) by second factor: none, authenticator_app, security_key, or both.
	SecondFactor map[string]int
	// AdminsWithoutSecondFactor are active, not deleted members of guardian-admins with neither an
	// authenticator app nor a security key. They must set one up at their next sign-in.
	AdminsWithoutSecondFactor int
	// Sessions are live sign-in sessions; AppSessions counts, per app (by its name), the live sessions that
	// have received tokens for it. A session signed in to three apps is one session and three app sessions.
	Sessions    int
	AppSessions map[string]int
	// Apps by enabled or disabled; groups by shared (may be linked to any app) or single_app.
	Apps   map[string]int
	Groups map[string]int
	// SigningKeyActivated is when the signing key in use started signing (zero if there is none).
	SigningKeyActivated time.Time
}

// CountForMetrics reads MetricCounts. idleTimeout is the session idle timeout: sessions unused for longer
// have ended even though they are not yet cleaned up.
func CountForMetrics(idleTimeout time.Duration) (MetricCounts, error) {
	c := MetricCounts{
		Accounts:     map[string]int{"active": 0, "pending": 0, "disabled": 0, "deleted": 0},
		SecondFactor: map[string]int{"none": 0, "authenticator_app": 0, "security_key": 0, "both": 0},
		AppSessions:  map[string]int{},
		Apps:         map[string]int{"enabled": 0, "disabled": 0},
		Groups:       map[string]int{"shared": 0, "single_app": 0},
	}
	conn := GetDatabaseConnection()
	add := func(m map[string]int, query string, args ...any) error {
		rows, err := conn.Query(query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				return err
			}
			m[k] += n
		}
		return rows.Err()
	}

	if err := add(c.Accounts, `SELECT CASE WHEN deleted_at IS NOT NULL THEN 'deleted' ELSE status END, count(*)
		FROM account GROUP BY 1`); err != nil {
		return c, err
	}
	if err := add(c.SecondFactor, `SELECT CASE WHEN totp AND key THEN 'both' WHEN totp THEN 'authenticator_app'
		       WHEN key THEN 'security_key' ELSE 'none' END, count(*)
		FROM (SELECT a.id,
		        EXISTS (SELECT 1 FROM account_mfa f WHERE f.account_id = a.id AND f.type = 'totp') AS totp,
		        EXISTS (SELECT 1 FROM account_mfa f WHERE f.account_id = a.id AND f.type = 'webauthn') AS key
		      FROM account a WHERE a.deleted_at IS NULL) x
		GROUP BY 1`); err != nil {
		return c, err
	}
	if err := conn.QueryRow(`SELECT count(DISTINCT a.id)
		FROM account a JOIN group_member m ON m.account_id = a.id JOIN user_group g ON g.id = m.group_id
		WHERE g.key = $1 AND `+activeMember+` AND a.status = 'active' AND a.deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM account_mfa f WHERE f.account_id = a.id AND f.type IN ('totp', 'webauthn'))`,
		AdminGroupKey).Scan(&c.AdminsWithoutSecondFactor); err != nil {
		return c, err
	}

	// The same rule as a session's own check (liveSession): not revoked, not past its end, not idle, and
	// its account active.
	const live = `s.revoked_at IS NULL AND s.expires_at > now() AND s.last_seen_at > now() - make_interval(secs => $1)
		AND a.status = 'active' AND a.deleted_at IS NULL`
	if err := conn.QueryRow(`SELECT count(*) FROM session s JOIN account a ON a.id = s.account_id WHERE `+live,
		idleTimeout.Seconds()).Scan(&c.Sessions); err != nil {
		return c, err
	}
	// Every app is listed, with 0 when nobody uses it, so a graph shows it rather than a gap.
	if err := add(c.AppSessions, `SELECT p.name, count(a.id)
		FROM app p
		LEFT JOIN session_app sa ON sa.app_id = p.id
		LEFT JOIN session s ON s.id = sa.session_id
		LEFT JOIN account a ON a.id = s.account_id AND `+live+`
		GROUP BY p.name`, idleTimeout.Seconds()); err != nil {
		return c, err
	}

	if err := add(c.Apps, `SELECT CASE WHEN enabled THEN 'enabled' ELSE 'disabled' END, count(*) FROM app GROUP BY 1`); err != nil {
		return c, err
	}
	if err := add(c.Groups, `SELECT CASE WHEN bound_at IS NOT NULL THEN 'single_app' ELSE 'shared' END, count(*)
		FROM user_group GROUP BY 1`); err != nil {
		return c, err
	}

	var activated sql.NullTime
	if err := conn.QueryRow(`SELECT max(activated_at) FROM signing_key WHERE status = 'active'`).Scan(&activated); err != nil {
		return c, err
	}
	c.SigningKeyActivated = activated.Time
	return c, nil
}
