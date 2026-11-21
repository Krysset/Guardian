package store

import (
	"database/sql"
	"errors"
	"time"
)

// What the account area shows a user about their own account: the address waiting for confirmation, their
// sessions, the apps they use, and their groups. Everything here is scoped to one account.

// PendingEmail returns the newest address waiting for confirmation (not a sign-up's), and when its link
// expires. "" when there is none.
func PendingEmail(accountID string) (string, *time.Time, error) {
	var address string
	var expires time.Time
	err := GetDatabaseConnection().QueryRow(
		`SELECT metadata->>'email', expires_at FROM account_token
		 WHERE account_id = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
		   AND COALESCE((metadata->>'signup')::boolean, false) = false
		 ORDER BY created_at DESC LIMIT 1`, accountID, TokenEmailVerify).Scan(&address, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	expires = expires.UTC()
	return address, &expires, nil
}

// CancelPendingEmail voids every confirmation link for a new address, so none of them changes the address
// any more. It reports whether there was one.
func CancelPendingEmail(accountID string) (bool, error) {
	res, err := GetDatabaseConnection().Exec(
		`UPDATE account_token SET used_at = now()
		 WHERE account_id = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
		   AND COALESCE((metadata->>'signup')::boolean, false) = false`, accountID, TokenEmailVerify)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RemoveEmail removes the account's address, and voids links for a new one. It returns the address that
// was removed ("" if there was none).
func RemoveEmail(accountID string) (string, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var old sql.NullString
	if err := tx.QueryRow(`SELECT email FROM account WHERE id = $1 FOR UPDATE`, accountID).Scan(&old); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE account SET email = NULL, email_verified_at = NULL, updated_at = now() WHERE id = $1`, accountID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE account_token SET used_at = now()
		 WHERE account_id = $1 AND purpose = $2 AND used_at IS NULL`, accountID, TokenEmailVerify); err != nil {
		return "", err
	}
	return old.String, tx.Commit()
}

// SessionInfo is one live session, as its owner sees it.
type SessionInfo struct {
	ID         string    `json:"id"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ListLiveSessions returns the account's sessions that are neither revoked, expired nor idle for longer
// than idleTimeout, most recently used first.
func ListLiveSessions(accountID string, idleTimeout time.Duration) ([]SessionInfo, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT id, COALESCE(user_agent, ''), COALESCE(host(ip_address), ''), created_at, last_seen_at, expires_at
		 FROM session
		 WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > now()
		   AND last_seen_at > now() - make_interval(secs => $2)
		 ORDER BY last_seen_at DESC`, accountID, idleTimeout.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := []SessionInfo{}
	for rows.Next() {
		var s SessionInfo
		if err := rows.Scan(&s.ID, &s.UserAgent, &s.IPAddress, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		s.CreatedAt, s.LastSeenAt, s.ExpiresAt = s.CreatedAt.UTC(), s.LastSeenAt.UTC(), s.ExpiresAt.UTC()
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// RevokeOwnSession ends one of the account's sessions. A session of another account is sql.ErrNoRows,
// so nobody learns that it exists.
func RevokeOwnSession(accountID, sessionID string) ([]LogoutNotice, error) {
	if !IsUUID(sessionID) {
		return nil, sql.ErrNoRows
	}
	var owner string
	err := GetDatabaseConnection().QueryRow(
		`SELECT account_id FROM session WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`, sessionID).Scan(&owner)
	if err != nil {
		return nil, err
	}
	if owner != accountID {
		return nil, sql.ErrNoRows
	}
	targets, err := RevokeSession(sessionID)
	if err != nil {
		return nil, err
	}
	notices := make([]LogoutNotice, 0, len(targets))
	for _, t := range targets {
		notices = append(notices, LogoutNotice{LogoutTarget: t, AccountID: accountID, SessionID: sessionID})
	}
	return notices, nil
}

// ConnectedApp is an app the account has signed in to, with what it may see.
type ConnectedApp struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	LogoURL     string    `json:"logo_url,omitempty"`
	HomepageURL string    `json:"homepage_url,omitempty"`
	Scopes      []string  `json:"scopes"`
	FirstUsedAt time.Time `json:"first_used_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
}

// ConnectedApps lists the apps the account has signed in to. Scopes are what the user agreed to, or for a
// first-party app (which asks nobody) the scopes it may ask for.
func ConnectedApps(accountID string) ([]ConnectedApp, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT a.id, a.name, a.pretty_name, a.description, COALESCE(a.logo_url, ''), COALESCE(a.homepage_url, ''),
		        COALESCE(c.scopes, ARRAY(SELECT s.scope_name FROM app_scope s WHERE s.app_id = a.id ORDER BY 1)),
		        u.first_signed_in_at, u.last_signed_in_at
		 FROM app_user u JOIN app a ON a.id = u.app_id
		 LEFT JOIN account_consent c ON c.account_id = u.account_id AND c.app_id = u.app_id AND c.revoked_at IS NULL
		 WHERE u.account_id = $1
		 ORDER BY u.last_signed_in_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []ConnectedApp{}
	for rows.Next() {
		var a ConnectedApp
		if err := rows.Scan(&a.ID, &a.Name, &a.DisplayName, &a.Description, &a.LogoURL, &a.HomepageURL,
			scanArray(&a.Scopes), &a.FirstUsedAt, &a.LastUsedAt); err != nil {
			return nil, err
		}
		a.FirstUsedAt, a.LastUsedAt = a.FirstUsedAt.UTC(), a.LastUsedAt.UTC()
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// RemoveAppAccess forgets that the account used the app: its consent, the app's refresh tokens for the
// account, and the record that the app may look the account up (app_user). It returns the back-channel
// logouts to send for the account's live sessions with the app; sql.ErrNoRows when the account never used it.
func RemoveAppAccess(accountID, appID string) ([]LogoutNotice, error) {
	if !IsUUID(appID) {
		return nil, sql.ErrNoRows
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	notices, err := logoutNotices(tx,
		`SELECT a.client_id, a.backchannel_logout_uri, a.signing_alg, s.account_id, s.id
		 FROM session s JOIN session_app sa ON sa.session_id = s.id JOIN app a ON a.id = sa.app_id
		 WHERE s.account_id = $1 AND a.id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()
		   AND a.backchannel_logout_uri IS NOT NULL`, accountID, appID)
	if err != nil {
		return nil, err
	}
	res, err := tx.Exec(`DELETE FROM app_user WHERE account_id = $1 AND app_id = $2`, accountID, appID)
	if err != nil {
		return nil, err
	}
	used, _ := res.RowsAffected()
	res, err = tx.Exec(`DELETE FROM account_consent WHERE account_id = $1 AND app_id = $2`, accountID, appID)
	if err != nil {
		return nil, err
	}
	consented, _ := res.RowsAffected()
	if used == 0 && consented == 0 {
		return nil, sql.ErrNoRows
	}
	if _, err := tx.Exec(`UPDATE refresh_token SET revoked_at = now()
		 WHERE account_id = $1 AND app_id = $2 AND revoked_at IS NULL`, accountID, appID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM session_app
		 WHERE app_id = $2 AND session_id IN (SELECT id FROM session WHERE account_id = $1)`, accountID, appID); err != nil {
		return nil, err
	}
	return notices, tx.Commit()
}

// MyGroup is a group the account is an active member of.
type MyGroup struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// ManagedGroup is a group the account manages as an owner.
type ManagedGroup struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	MemberCount int      `json:"member_count"`
	Apps        []string `json:"apps"` // display names of the linked apps
}

// MyGroups lists the groups the account is in (memberships that have not expired).
func MyGroups(accountID string) ([]MyGroup, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT g.id, g.display_name, g.description, m.expires_at
		 FROM group_member m JOIN user_group g ON g.id = m.group_id
		 WHERE m.account_id = $1 AND `+activeMember+`
		 ORDER BY lower(g.display_name), g.key`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []MyGroup{}
	for rows.Next() {
		var g MyGroup
		var expires sql.NullTime
		if err := rows.Scan(&g.ID, &g.DisplayName, &g.Description, &expires); err != nil {
			return nil, err
		}
		if expires.Valid {
			t := expires.Time.UTC()
			g.ExpiresAt = &t
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// ManagedGroups lists the groups the account owns through membership of their owner group.
func ManagedGroups(accountID string) ([]ManagedGroup, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT g.id, g.display_name, g.description,
		        (SELECT count(*) FROM group_member m WHERE m.group_id = g.id AND `+activeMember+`),
		        ARRAY(SELECT a.pretty_name FROM app_group ag JOIN app a ON a.id = ag.app_id
		              WHERE ag.group_id = g.id ORDER BY lower(a.pretty_name))
		 FROM user_group g
		 WHERE NOT g.is_system AND EXISTS (SELECT 1 FROM group_member m
		        WHERE m.group_id = g.owner_group_id AND m.account_id = $1 AND `+activeMember+`)
		 ORDER BY lower(g.display_name), g.key`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []ManagedGroup{}
	for rows.Next() {
		var g ManagedGroup
		if err := rows.Scan(&g.ID, &g.DisplayName, &g.Description, &g.MemberCount, scanArray(&g.Apps)); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}
