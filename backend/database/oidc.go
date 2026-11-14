package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"
)

var (
	ErrInvalidGrant = errors.New("invalid grant")
	ErrTokenReuse   = errors.New("refresh token reuse detected")
)

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
		Scan(&c.AppID, &c.AccountID, &c.SessionID, &c.RedirectURI, pq.Array(&c.Scopes), &c.Nonce, &c.CodeChallenge, &c.AuthTime)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthCode{}, ErrInvalidGrant
	}
	return c, err
}

// ---- Refresh tokens ---------------------------------------------------------

func SaveRefreshToken(tokenHash, familyID, appID, accountID, sessionID string, scopes []string, expires time.Time) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO refresh_token (token_hash, family_id, app_id, account_id, session_id, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid, $6, $7)`,
		tokenHash, familyID, appID, accountID, sessionID, strArray(scopes), expires)
	return err
}

// RotateRefreshToken redeems oldHash and stores newHash in the same family, atomically.
// Presenting an already-rotated token revokes the whole family (it was probably stolen).
func RotateRefreshToken(oldHash, appID, newHash string, newExpires time.Time) (RefreshToken, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return RefreshToken{}, err
	}
	defer tx.Rollback()

	var rt RefreshToken
	var rotated, revoked sql.NullTime
	var expires time.Time
	err = tx.QueryRow(
		`SELECT id, family_id, app_id, account_id, COALESCE(session_id::text, ''), scopes, rotated_at, revoked_at, expires_at
		 FROM refresh_token WHERE token_hash = $1 AND app_id = $2 FOR UPDATE`, oldHash, appID).
		Scan(&rt.ID, &rt.FamilyID, &rt.AppID, &rt.AccountID, &rt.SessionID, pq.Array(&rt.Scopes), &rotated, &revoked, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrInvalidGrant
	}
	if err != nil {
		return RefreshToken{}, err
	}
	if revoked.Valid || time.Now().After(expires) {
		return RefreshToken{}, ErrInvalidGrant
	}
	if rotated.Valid {
		if _, err := tx.Exec(`UPDATE refresh_token SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`, rt.FamilyID); err != nil {
			return RefreshToken{}, err
		}
		if err := tx.Commit(); err != nil {
			return RefreshToken{}, err
		}
		return RefreshToken{}, ErrTokenReuse
	}

	if _, err := tx.Exec(`UPDATE refresh_token SET rotated_at = now() WHERE id = $1`, rt.ID); err != nil {
		return RefreshToken{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO refresh_token (token_hash, family_id, app_id, account_id, session_id, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid, $6, $7)`,
		newHash, rt.FamilyID, rt.AppID, rt.AccountID, rt.SessionID, strArray(rt.Scopes), newExpires); err != nil {
		return RefreshToken{}, err
	}
	return rt, tx.Commit()
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

// ---- Access tokens (opaque) -------------------------------------------------

func SaveAccessToken(tokenHash, appID, accountID, sessionID string, scopes []string, expires time.Time) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO access_token (token_hash, app_id, account_id, session_id, scopes, expires_at)
		 VALUES ($1, $2, $3, NULLIF($4, '')::uuid, $5, $6)`,
		tokenHash, appID, accountID, sessionID, strArray(scopes), expires)
	return err
}

// TokenInfo is what introspection knows about a live access token.
type TokenInfo struct {
	AccountID   string
	AppID       string // app the token was issued to
	ClientID    string // ...and its client_id
	SessionID   string // "" if none
	Scopes      []string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Permissions []string        // what the account holds in callerAppID, computed NOW
	Attributes  json.RawMessage // per-permission attributes of direct grants in callerAppID ({} if none)
}

// IntrospectAccessToken answers "is this token valid right now, and what may its user do in callerAppID?"
// with ONE query against live data. The token is valid only while: not expired or revoked, its app is
// enabled, its account is active, and its session (if any) is not revoked. callerAppID may be "" when
// permissions are not needed. Returns sql.ErrNoRows for any invalid token.
func IntrospectAccessToken(tokenHash, callerAppID string) (TokenInfo, error) {
	var ti TokenInfo
	var attrs []byte
	err := GetDatabaseConnection().QueryRow(
		`SELECT t.account_id, t.app_id, a.client_id, COALESCE(t.session_id::text, ''), t.scopes, t.created_at, t.expires_at,
		        ARRAY(SELECT e.name FROM account_effective_permission e
		              WHERE e.account_id = t.account_id AND e.app_id = NULLIF($2, '')::uuid ORDER BY e.name),
		        (SELECT COALESCE(jsonb_object_agg(p.name, g.attributes), '{}'::jsonb)
		           FROM account_app_permission g JOIN app_permission p ON p.id = g.permission_id
		          WHERE g.account_id = t.account_id AND p.app_id = NULLIF($2, '')::uuid
		            AND g.attributes <> '{}'::jsonb AND (g.expires_at IS NULL OR g.expires_at > now()))
		 FROM access_token t
		 JOIN app a ON a.id = t.app_id AND a.enabled
		 JOIN account acc ON acc.id = t.account_id AND acc.status = 'active' AND acc.deleted_at IS NULL
		 LEFT JOIN session s ON s.id = t.session_id
		 WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now()
		   AND (t.session_id IS NULL OR s.revoked_at IS NULL)`,
		tokenHash, callerAppID).
		Scan(&ti.AccountID, &ti.AppID, &ti.ClientID, &ti.SessionID, pq.Array(&ti.Scopes), &ti.IssuedAt, &ti.ExpiresAt,
			pq.Array(&ti.Permissions), &attrs)
	if err != nil {
		return TokenInfo{}, err
	}
	ti.Attributes = json.RawMessage(attrs)
	return ti, nil
}
