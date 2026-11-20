package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// touchInterval limits last_seen_at writes: a session is written at most this often, so the hot
// read path is a pure SELECT.
const touchInterval = 5 * time.Minute

// CreateSession stores a new SSO session. sessionHash is the hash of the cookie value. The session ends
// maxLifetime from now at the latest, whatever the activity.
// amr says how the user signed in (RFC 8176): "pwd", and "otp" or "hwk" after two-factor; a passkey is
// {"hwk", "user"}. Without it, {"pwd"}.
func CreateSession(accountID, sessionHash, ip, userAgent string, maxLifetime time.Duration, amr ...string) (Session, error) {
	s := Session{AccountID: accountID}
	if len(amr) == 0 {
		amr = []string{"pwd"}
	}
	err := GetDatabaseConnection().QueryRow(
		`INSERT INTO session (session_hash, account_id, ip_address, user_agent, expires_at, amr)
		 VALUES ($1, $2, NULLIF($3, '')::inet, NULLIF($4, ''), $5, $6)
		 RETURNING id, auth_time, amr, expires_at, last_seen_at`,
		sessionHash, accountID, ip, userAgent, time.Now().Add(maxLifetime), strArray(amr)).
		Scan(&s.ID, &s.AuthTime, scanArray(&s.AMR), &s.ExpiresAt, &s.LastSeenAt)
	return s, err
}

// liveSession is the one definition of "this session can still be used": not revoked, before its
// absolute end, used within the idle timeout ($2, in seconds), and its account is active.
const liveSession = `SELECT s.id, s.account_id, s.auth_time, s.amr, s.expires_at, s.last_seen_at
	FROM session s JOIN account a ON a.id = s.account_id
	WHERE %s = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
	  AND s.last_seen_at > now() - make_interval(secs => $2)
	  AND a.status = 'active' AND a.deleted_at IS NULL`

func loadLiveSession(column, value string, idleTimeout time.Duration) (Session, error) {
	var s Session
	err := GetDatabaseConnection().QueryRow(fmt.Sprintf(liveSession, column), value, idleTimeout.Seconds()).
		Scan(&s.ID, &s.AccountID, &s.AuthTime, scanArray(&s.AMR), &s.ExpiresAt, &s.LastSeenAt)
	if err != nil {
		return Session{}, err
	}
	// Using a session keeps it from going idle. The write is skipped when the last one was recent.
	if time.Since(s.LastSeenAt) > touchInterval {
		GetDatabaseConnection().Exec(`UPDATE session SET last_seen_at = now() WHERE id = $1`, s.ID)
	}
	return s, nil
}

// GetSessionByHash returns the session for a cookie value's hash, only if it is live (see liveSession).
func GetSessionByHash(sessionHash string, idleTimeout time.Duration) (Session, error) {
	return loadLiveSession("s.session_hash", sessionHash, idleTimeout)
}

// GetLiveSession returns the session with this id, only if it is live (see liveSession). Token refreshes
// and userinfo use it, so an app that keeps refreshing keeps the session from going idle.
func GetLiveSession(sessionID string, idleTimeout time.Duration) (Session, error) {
	if !IsUUID(sessionID) {
		return Session{}, sql.ErrNoRows
	}
	return loadLiveSession("s.id::text", sessionID, idleTimeout)
}

// RevokeSession ends a session and every refresh token issued under it, and returns the apps that
// need a back-channel logout notification. Access tokens already issued under the session cannot be
// refreshed any more and are refused by userinfo; they expire within the app's token lifetime.
// Returns no targets if already revoked.
func RevokeSession(sessionID string) ([]LogoutTarget, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE session SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, sessionID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(`UPDATE refresh_token SET revoked_at = now() WHERE session_id = $1 AND revoked_at IS NULL`, sessionID); err != nil {
		return nil, err
	}

	rows, err := tx.Query(
		`SELECT a.client_id, a.backchannel_logout_uri FROM session_app sa JOIN app a ON a.id = sa.app_id
		 WHERE sa.session_id = $1 AND a.backchannel_logout_uri IS NOT NULL`, sessionID)
	if err != nil {
		return nil, err
	}
	var targets []LogoutTarget
	for rows.Next() {
		var t LogoutTarget
		if err := rows.Scan(&t.ClientID, &t.URI); err != nil {
			rows.Close()
			return nil, err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return targets, tx.Commit()
}

// TrackSessionApp records that an app received tokens under this session.
func TrackSessionApp(sessionID, appID string) {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO session_app (session_id, app_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, sessionID, appID)
	if err != nil {
		slog.Error("failed to track a session app", "error", err)
	}
}

// GetConsent returns the scopes the account has granted to the app (empty if none/revoked).
func GetConsent(accountID, appID string) ([]string, error) {
	var scopes []string
	err := GetDatabaseConnection().QueryRow(
		`SELECT scopes FROM account_consent WHERE account_id = $1 AND app_id = $2 AND revoked_at IS NULL`,
		accountID, appID).Scan(scanArray(&scopes))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return scopes, err
}

func SaveConsent(accountID, appID string, scopes []string) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO account_consent (account_id, app_id, scopes) VALUES ($1, $2, $3)
		 ON CONFLICT (account_id, app_id)
		 DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = now(), revoked_at = NULL`,
		accountID, appID, strArray(scopes))
	return err
}

// Audit appends to audit_log. Failures are logged, never returned: auditing must not break a request.
func Audit(eventType, accountID, appID, ip string, meta map[string]any) {
	if meta == nil {
		meta = map[string]any{}
	}
	b, _ := json.Marshal(meta)
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO audit_log (event_type, actor_account_id, actor_app_id, ip_address, metadata)
		 VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, NULLIF($4, '')::inet, $5::jsonb)`,
		eventType, accountID, appID, ip, string(b))
	if err != nil {
		slog.Error("failed to write the audit log", "error", err)
	}
}

// Reauthenticate records that the session's user has just proved who they are again: it moves the
// session's auth_time (the OIDC auth_time) to now, which opens the window for protected changes.
func Reauthenticate(sessionID string) (time.Time, error) {
	var t time.Time
	err := GetDatabaseConnection().QueryRow(
		`UPDATE session SET auth_time = now() WHERE id = $1 AND revoked_at IS NULL RETURNING auth_time`, sessionID).Scan(&t)
	return t, err
}
