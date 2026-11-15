package store

import (
	"database/sql"
	"errors"
	"time"
)

var ErrInvalidGrant = errors.New("invalid grant")

// ---- Authorization codes ----------------------------------------------------

func SaveAuthCode(codeHash string, c AuthCode, ttl time.Duration) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO authorization_code
		   (code_hash, app_id, account_id, session_id, redirect_uri, scopes, nonce, code_challenge, code_challenge_method, auth_time, expires_at)
		 VALUES ($1, $2, $3, NULLIF($4, '')::uuid, $5, $6, NULLIF($7, ''), NULLIF($8, ''),
		         CASE WHEN $8 = '' THEN NULL ELSE 'S256' END, $9, $10)`,
		codeHash, c.AppID, c.AccountID, c.SessionID, c.RedirectURI, strArray(c.Scopes), c.Nonce, c.CodeChallenge,
		c.AuthTime, time.Now().Add(ttl))
	return err
}

// ConsumeAuthCode atomically marks a code used and returns it. A code can only ever be redeemed once.
func ConsumeAuthCode(codeHash string) (AuthCode, error) {
	var c AuthCode
	err := GetDatabaseConnection().QueryRow(
		`UPDATE authorization_code SET used_at = now()
		 WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING app_id, account_id, COALESCE(session_id::text, ''), redirect_uri, scopes,
		           COALESCE(nonce, ''), COALESCE(code_challenge, ''), auth_time`, codeHash).
		Scan(&c.AppID, &c.AccountID, &c.SessionID, &c.RedirectURI, scanArray(&c.Scopes), &c.Nonce, &c.CodeChallenge, &c.AuthTime)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthCode{}, ErrInvalidGrant
	}
	return c, err
}

// ---- Refresh tokens ---------------------------------------------------------
//
// An app with a secret gets one refresh token per sign-in and keeps using it until the session ends. It
// is not replaced at each refresh, so several replicas of an app, or a retry after a lost answer, can
// use it at the same time. What a refresh may return is decided at refresh time, from the session,
// the account, the app and the groups as they are then.

func SaveRefreshToken(tokenHash, appID, accountID, sessionID string, scopes []string) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO refresh_token (token_hash, app_id, account_id, session_id, scopes) VALUES ($1, $2, $3, $4, $5)`,
		tokenHash, appID, accountID, sessionID, strArray(scopes))
	return err
}

// GetRefreshToken returns the app's refresh token with this hash if it has not been revoked. Whether its
// session is still live is for the caller to check (GetLiveSession).
func GetRefreshToken(tokenHash, appID string) (RefreshToken, error) {
	var rt RefreshToken
	err := GetDatabaseConnection().QueryRow(
		`SELECT id, app_id, account_id, session_id, scopes FROM refresh_token
		 WHERE token_hash = $1 AND app_id = $2 AND revoked_at IS NULL`, tokenHash, appID).
		Scan(&rt.ID, &rt.AppID, &rt.AccountID, &rt.SessionID, scanArray(&rt.Scopes))
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrInvalidGrant
	}
	return rt, err
}

// RevokeRefreshToken ends one refresh token of the app (RFC 7009). It reports whether a token was revoked.
func RevokeRefreshToken(tokenHash, appID string) (bool, error) {
	res, err := GetDatabaseConnection().Exec(
		`UPDATE refresh_token SET revoked_at = now() WHERE token_hash = $1 AND app_id = $2 AND revoked_at IS NULL`,
		tokenHash, appID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ---- Signing keys -----------------------------------------------------------

// EnsureSigningKey creates an active key if none exists. Safe with several instances starting at once.
func EnsureSigningKey(generate func() (SigningKey, error)) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(727275)`); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM signing_key WHERE status = 'active')`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	k, err := generate()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO signing_key (kid, alg, public_jwk, private_key_encrypted, status) VALUES ($1, $2, $3::jsonb, $4, 'active')`,
		k.KID, k.Alg, string(k.PublicJWK), k.PrivateKeyEncrypted); err != nil {
		return err
	}
	return tx.Commit()
}

func GetActiveSigningKey() (SigningKey, error) {
	var k SigningKey
	err := GetDatabaseConnection().QueryRow(
		`SELECT kid, alg, public_jwk, private_key_encrypted, status FROM signing_key
		 WHERE status = 'active' ORDER BY created_at DESC LIMIT 1`).
		Scan(&k.KID, &k.Alg, &k.PublicJWK, &k.PrivateKeyEncrypted, &k.Status)
	return k, err
}

func GetPublishedSigningKeys() ([]SigningKey, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT kid, alg, public_jwk, private_key_encrypted, status FROM signing_key WHERE status IN ('active', 'retiring')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.KID, &k.Alg, &k.PublicJWK, &k.PrivateKeyEncrypted, &k.Status); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
