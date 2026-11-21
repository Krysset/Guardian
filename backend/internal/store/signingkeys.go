package store

import (
	"database/sql"
	"errors"
	"time"
)

// Signing keys and their lifecycle: pending -> active -> retiring -> retired. The decisions (when to
// rotate) are in the auth package; this file only moves rows, each move in one transaction under an
// advisory lock, so several replicas can run the same schedule safely.
//
// Every algorithm in SigningAlgs has its own active key and its own rotation: an app's tokens are signed
// with the algorithm the app chose (app.signing_alg), and both keys are always published.

// SigningAlgs are the algorithms Guardian signs with. RS256 comes first: OIDC requires it, and it is the
// default for apps.
var SigningAlgs = []string{"RS256", "ES256"}

const signingKeyLock = 727275

const signingKeyColumns = `kid, alg, public_jwk, COALESCE(private_key_encrypted, ''), status, created_at, activated_at, retire_at, retired_at`

func scanSigningKey(s scanner) (SigningKey, error) {
	var k SigningKey
	err := s.Scan(&k.KID, &k.Alg, &k.PublicJWK, &k.PrivateKeyEncrypted, &k.Status, &k.CreatedAt, &k.ActivatedAt, &k.RetireAt, &k.RetiredAt)
	return k, err
}

func querySigningKeys(q string, args ...any) ([]SigningKey, error) {
	rows, err := GetDatabaseConnection().Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func lockSigningKeys(tx *sql.Tx) error {
	_, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, signingKeyLock)
	return err
}

// EnsureSigningKeys creates an active key for each algorithm that has none (the first start, or the first
// start of a version that adds an algorithm: nobody can have used such a key yet, so it signs at once). Safe
// with several instances starting at once.
func EnsureSigningKeys(generate func(alg string) (SigningKey, error)) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockSigningKeys(tx); err != nil {
		return err
	}
	for _, alg := range SigningAlgs {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM signing_key WHERE status = 'active' AND alg = $1)`, alg).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		k, err := generate(alg)
		if err != nil {
			return err
		}
		if err := insertSigningKey(tx, k, "active"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertSigningKey(tx *sql.Tx, k SigningKey, status string) error {
	_, err := tx.Exec(`INSERT INTO signing_key (kid, alg, public_jwk, private_key_encrypted, status, activated_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, CASE WHEN $5 = 'active' THEN now() END)`,
		k.KID, k.Alg, string(k.PublicJWK), k.PrivateKeyEncrypted, status)
	return err
}

// GetActiveSigningKeys returns the keys that sign, one per algorithm.
func GetActiveSigningKeys() ([]SigningKey, error) {
	return querySigningKeys(`SELECT ` + signingKeyColumns + ` FROM signing_key WHERE status = 'active' ORDER BY alg`)
}

// GetPublishedSigningKeys returns the keys in the JWKS: pending, active and retiring.
func GetPublishedSigningKeys() ([]SigningKey, error) {
	return querySigningKeys(`SELECT ` + signingKeyColumns + ` FROM signing_key
		WHERE status IN ('pending', 'active', 'retiring') ORDER BY created_at`)
}

// ListSigningKeys returns every key, the newest first.
func ListSigningKeys() ([]SigningKey, error) {
	return querySigningKeys(`SELECT ` + signingKeyColumns + ` FROM signing_key ORDER BY created_at DESC`)
}

// KeySchedule is what the rotation schedule needs to know.
type KeySchedule struct {
	// Lifetime is how long a key signs before the next one takes over (SIGNING_KEY_LIFETIME).
	Lifetime time.Duration
	// Pending is how long a new key is published before it signs.
	Pending time.Duration
	// Skew is added to the longest token lifetime before a retiring key stops being published.
	Skew time.Duration
}

// RotationStep is one change the schedule made.
type RotationStep struct {
	Event string // signing_key.created, signing_key.activated, signing_key.retired
	KID   string
}

// AdvanceSigningKeys runs the schedule once, for each algorithm: it creates a pending key when the active
// one is due for replacement, activates a pending key that has been published long enough (the old one of
// the same algorithm starts retiring), and retires keys whose tokens have all expired. generate is called
// only when a key is created.
func AdvanceSigningKeys(s KeySchedule, generate func(alg string) (SigningKey, error)) ([]RotationStep, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := lockSigningKeys(tx); err != nil {
		return nil, err
	}
	var steps []RotationStep

	// Retiring keys whose tokens have all expired.
	rows, err := tx.Query(`UPDATE signing_key SET status = 'retired', retired_at = now(), private_key_encrypted = NULL
		WHERE status = 'retiring' AND retire_at <= now() RETURNING kid`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var kid string
		rows.Scan(&kid)
		steps = append(steps, RotationStep{"signing_key.retired", kid})
	}
	rows.Close()

	for _, alg := range SigningAlgs {
		// A pending key that has been published long enough takes over.
		var pending string
		err = tx.QueryRow(`SELECT kid FROM signing_key WHERE status = 'pending' AND alg = $2
			AND created_at <= now() - make_interval(secs => $1) ORDER BY created_at LIMIT 1`, s.Pending.Seconds(), alg).Scan(&pending)
		switch {
		case err == nil:
			if err := activate(tx, pending, alg, s.Skew); err != nil {
				return nil, err
			}
			steps = append(steps, RotationStep{"signing_key.activated", pending})
		case !errors.Is(err, sql.ErrNoRows):
			return nil, err
		}

		// The active key is due: publish its successor, which takes over after s.Pending.
		var due bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM signing_key WHERE status = 'active' AND alg = $2
				AND activated_at <= now() - make_interval(secs => $1))
			AND NOT EXISTS (SELECT 1 FROM signing_key WHERE status = 'pending' AND alg = $2)`,
			(s.Lifetime - s.Pending).Seconds(), alg).Scan(&due); err != nil {
			return nil, err
		}
		if due {
			k, err := generate(alg)
			if err != nil {
				return nil, err
			}
			if err := insertSigningKey(tx, k, "pending"); err != nil {
				return nil, err
			}
			steps = append(steps, RotationStep{"signing_key.created", k.KID})
		}
	}
	return steps, tx.Commit()
}

// activate makes kid the active key of its algorithm; the previous one starts retiring. It stays published
// until the longest token lifetime of any app, plus skew, has passed.
func activate(tx *sql.Tx, kid, alg string, skew time.Duration) error {
	if _, err := tx.Exec(`UPDATE signing_key SET status = 'retiring',
			retire_at = now() + make_interval(secs => $1 + COALESCE((SELECT max(access_token_ttl_seconds) FROM app), 300))
		WHERE status = 'active' AND alg = $2`, skew.Seconds(), alg); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE signing_key SET status = 'active', activated_at = now() WHERE kid = $1`, kid)
	return err
}

// AddPendingSigningKey publishes a new key now; the schedule activates it once it has been published long
// enough (`guardian keys rotate`). It refuses while another key of its algorithm is pending (ErrKeyPending).
func AddPendingSigningKey(k SigningKey) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockSigningKeys(tx); err != nil {
		return err
	}
	var pending bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM signing_key WHERE status = 'pending' AND alg = $1)`, k.Alg).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrKeyPending
	}
	if err := insertSigningKey(tx, k, "pending"); err != nil {
		return err
	}
	return tx.Commit()
}

// ErrKeyPending means a new key is already waiting to take over.
var ErrKeyPending = errors.New("a new signing key is already pending")

// EmergencyRotate is the emergency path: k signs at once, and the current key of its algorithm is retired
// at once (no longer published, its private key wiped), so tokens it signed stop verifying wherever the
// JWKS is fetched again. A pending key of that algorithm is retired too. It returns the retired keys.
func EmergencyRotate(k SigningKey) ([]string, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := lockSigningKeys(tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`UPDATE signing_key SET status = 'retired', retired_at = now(), private_key_encrypted = NULL
		WHERE status IN ('active', 'pending') AND alg = $1 RETURNING kid`, k.Alg)
	if err != nil {
		return nil, err
	}
	var retired []string
	for rows.Next() {
		var kid string
		rows.Scan(&kid)
		retired = append(retired, kid)
	}
	rows.Close()
	if err := insertSigningKey(tx, k, "active"); err != nil {
		return nil, err
	}
	return retired, tx.Commit()
}
