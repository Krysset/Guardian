package database

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/lib/pq"
)

// touchInterval limits last_seen_at writes: a session is written at most this often, so the hot
// read path is a pure SELECT.
const touchInterval = 5 * time.Minute

// CreateSession stores a new SSO session. sessionHash is the hash of the cookie value.
func CreateSession(accountID, sessionHash, ip, userAgent string, ttl time.Duration) (Session, error) {
	s := Session{AccountID: accountID}
	err := GetDatabaseConnection().QueryRow(
		`INSERT INTO session (session_hash, account_id, ip_address, user_agent, expires_at)
		 VALUES ($1, $2, NULLIF($3, '')::inet, NULLIF($4, ''), $5)
		 RETURNING id, auth_time, expires_at, last_seen_at`,
		sessionHash, accountID, ip, userAgent, time.Now().Add(ttl)).Scan(&s.ID, &s.AuthTime, &s.ExpiresAt, &s.LastSeenAt)
	return s, err
}

// GetSessionByHash returns the session only if it is live and its account is active.
func GetSessionByHash(sessionHash string) (Session, error) {
	var s Session
	err := GetDatabaseConnection().QueryRow(
		`SELECT s.id, s.account_id, s.auth_time, s.expires_at, s.last_seen_at
		 FROM session s JOIN account a ON a.id = s.account_id
		 WHERE s.session_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
		   AND a.status = 'active' AND a.deleted_at IS NULL`, sessionHash).
		Scan(&s.ID, &s.AccountID, &s.AuthTime, &s.ExpiresAt, &s.LastSeenAt)
	if err != nil {
		return Session{}, err
	}
	if time.Since(s.LastSeenAt) > touchInterval {
		GetDatabaseConnection().Exec(`UPDATE session SET last_seen_at = now() WHERE id = $1`, s.ID)
	}
	return s, nil
}

func SessionActive(sessionID string) bool {
	if !IsUUID(sessionID) {
		return false
	}
	var ok bool
	err := GetDatabaseConnection().QueryRow(
		`SELECT EXISTS (SELECT 1 FROM session WHERE id = $1 AND revoked_at IS NULL AND expires_at > now())`,
		sessionID).Scan(&ok)
	return err == nil && ok
}

// RevokeSession ends a session and every refresh token issued under it, and returns the apps that
// need a back-channel logout notification. Access tokens of the session stop being valid by
// themselves (introspection requires a non-revoked session). Returns no targets if already revoked.
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
		log.Println("Failed to track session app:", err)
	}
}

// GetConsent returns the scopes the account has granted to the app (empty if none/revoked).
func GetConsent(accountID, appID string) ([]string, error) {
	var scopes []string
	err := GetDatabaseConnection().QueryRow(
		`SELECT scopes FROM account_consent WHERE account_id = $1 AND app_id = $2 AND revoked_at IS NULL`,
		accountID, appID).Scan(pq.Array(&scopes))
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
		accountID, appID, pq.Array(scopes))
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
		log.Println("Failed to write audit log:", err)
	}
}
