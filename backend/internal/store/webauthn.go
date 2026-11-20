package store

import (
	"database/sql"
	"errors"
	"time"
)

// Security keys and passkeys (WebAuthn) are account_mfa rows of type 'webauthn'. credential holds the
// library's stored credential as JSON (public key, flags, transports, counter); credential_id is kept
// beside it so a passkey sign-in can find the row. Nothing in them is secret.

// SecurityKey is one security key or passkey, as the account area lists it.
type SecurityKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Passkey    bool       `json:"passkey"` // synced (backup eligible), so usable on the user's other devices
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// StoredKey is a security key with its stored credential, for the WebAuthn ceremonies.
type StoredKey struct {
	SecurityKey
	Credential []byte // the library's Credential as JSON
}

// ErrKeyNotFound means the account has no security key with that id.
var ErrKeyNotFound = errors.New("security key not found")

// ErrCredentialInUse means the security key is already registered (to this or another account).
var ErrCredentialInUse = errors.New("this security key is already registered")

const keyColumns = `id, COALESCE(name, ''), COALESCE((credential->'flags'->>'backupEligible')::boolean, false),
	created_at, last_used_at, credential`

func scanKey(row interface{ Scan(...any) error }) (StoredKey, error) {
	var k StoredKey
	var used sql.NullTime
	err := row.Scan(&k.ID, &k.Name, &k.Passkey, &k.CreatedAt, &used, &k.Credential)
	if used.Valid {
		k.LastUsedAt = &used.Time
	}
	return k, err
}

// ListSecurityKeys returns the account's security keys and passkeys, oldest first.
func ListSecurityKeys(accountID string) ([]StoredKey, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT `+keyColumns+` FROM account_mfa WHERE account_id = $1 AND type = 'webauthn' ORDER BY created_at, id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredKey{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// AccountForCredential returns the account a credential id is registered to, or sql.ErrNoRows.
func AccountForCredential(credentialID []byte) (string, error) {
	var id string
	err := GetDatabaseConnection().QueryRow(
		`SELECT account_id FROM account_mfa WHERE type = 'webauthn' AND credential_id = $1`, credentialID).Scan(&id)
	return id, err
}

// AddSecurityKey saves a new security key. codeHashes are recovery codes to save with it, for an account
// that had no second factor yet (nil otherwise).
func AddSecurityKey(accountID, name string, credentialID, credential []byte, signCount uint32, codeHashes []string) (SecurityKey, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return SecurityKey{}, err
	}
	defer tx.Rollback()
	k, err := scanKey(tx.QueryRow(`INSERT INTO account_mfa (account_id, type, name, credential_id, credential, sign_count)
		VALUES ($1, 'webauthn', $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING `+keyColumns,
		accountID, name, credentialID, credential, int64(signCount)))
	if errors.Is(err, sql.ErrNoRows) {
		return SecurityKey{}, ErrCredentialInUse
	}
	if err != nil {
		return SecurityKey{}, err
	}
	if codeHashes != nil {
		if _, err := tx.Exec(`DELETE FROM account_mfa WHERE account_id = $1 AND type = 'recovery_code'`, accountID); err != nil {
			return SecurityKey{}, err
		}
		if err := insertRecoveryCodes(tx, accountID, codeHashes); err != nil {
			return SecurityKey{}, err
		}
	}
	return k.SecurityKey, tx.Commit()
}

// UseSecurityKey records a successful use: the new stored credential (its counter moves) and the time.
func UseSecurityKey(id string, credential []byte, signCount uint32) error {
	_, err := GetDatabaseConnection().Exec(
		`UPDATE account_mfa SET credential = $2, sign_count = $3, last_used_at = now() WHERE id = $1 AND type = 'webauthn'`,
		id, credential, int64(signCount))
	return err
}

// RenameSecurityKey changes a key's name.
func RenameSecurityKey(accountID, id, name string) (SecurityKey, error) {
	if !IsUUID(id) {
		return SecurityKey{}, ErrKeyNotFound
	}
	k, err := scanKey(GetDatabaseConnection().QueryRow(
		`UPDATE account_mfa SET name = $3 WHERE id = $2 AND account_id = $1 AND type = 'webauthn' RETURNING `+keyColumns,
		accountID, id, name))
	if errors.Is(err, sql.ErrNoRows) {
		return SecurityKey{}, ErrKeyNotFound
	}
	return k.SecurityKey, err
}

// ErrLastFactor means removing the method would leave an account that must use two-factor without it.
var ErrLastFactor = errors.New("the last two-factor method of an account that must use two-factor")

// RemoveFactor removes one two-factor method: the authenticator app (id "totp") or a security key. The
// recovery codes go with the last method. required refuses removing the last one (ErrLastFactor). It returns
// the removed key's name ("" for the app) and how many methods are left.
func RemoveFactor(accountID, id string, required bool) (name string, left int, err error) {
	if id != "totp" && !IsUUID(id) {
		return "", 0, ErrKeyNotFound
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	// Lock the account's methods, so two removals at once cannot both think another one is left.
	var factors int
	if err := tx.QueryRow(`SELECT count(*) FROM (SELECT 1 FROM account_mfa WHERE account_id = $1
		AND type IN ('totp', 'webauthn') FOR UPDATE) f`, accountID).Scan(&factors); err != nil {
		return "", 0, err
	}
	var row *sql.Row
	if id == "totp" {
		row = tx.QueryRow(`DELETE FROM account_mfa WHERE account_id = $1 AND type = 'totp' RETURNING ''`, accountID)
	} else {
		row = tx.QueryRow(`DELETE FROM account_mfa WHERE account_id = $1 AND id = $2 AND type = 'webauthn'
			RETURNING COALESCE(name, '')`, accountID, id)
	}
	if err := row.Scan(&name); errors.Is(err, sql.ErrNoRows) {
		if id == "totp" {
			return "", 0, ErrNoTOTP
		}
		return "", 0, ErrKeyNotFound
	} else if err != nil {
		return "", 0, err
	}
	left = factors - 1
	if left == 0 {
		if required {
			return "", 0, ErrLastFactor
		}
		if _, err := tx.Exec(`DELETE FROM account_mfa WHERE account_id = $1 AND type = 'recovery_code'`, accountID); err != nil {
			return "", 0, err
		}
	}
	return name, left, tx.Commit()
}

// UseChallenge marks a WebAuthn challenge as answered, and reports false if it was answered already.
func UseChallenge(challenge string, expires time.Time) (bool, error) {
	res, err := GetDatabaseConnection().Exec(
		`INSERT INTO used_challenge (challenge, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING`, challenge, expires)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
