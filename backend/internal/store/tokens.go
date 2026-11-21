package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Purposes of account tokens: the links Guardian sends by email.
const (
	TokenEmailVerify   = "email_verify"
	TokenPasswordReset = "password_reset"
)

// AccountToken is a one-time link. Only the hash of its secret is stored.
type AccountToken struct {
	ID        string
	AccountID string
	Purpose   string
	Metadata  TokenMetadata
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// TokenMetadata is what a token carries besides its account.
type TokenMetadata struct {
	Email    string `json:"email,omitempty"`     // email_verify: the address being confirmed
	Signup   bool   `json:"signup,omitempty"`    // email_verify: sign-up waits for this confirmation
	Browser  string `json:"browser,omitempty"`   // email_verify at sign-up: hash of the browser's sign-up cookie
	ReturnTo string `json:"return_to,omitempty"` // email_verify at sign-up: where sign-in continues
}

var (
	ErrTokenInvalid = errors.New("the link is not valid")
	ErrTokenExpired = errors.New("the link has expired")
	ErrTokenUsed    = errors.New("the link was already used")
	// ErrEmailTaken means another account confirmed the address first.
	ErrEmailTaken = errors.New("the email address is used by another account")
)

// CreateAccountToken stores a new token and replaces the account's unused tokens of the same purpose, so
// only the newest link works.
func CreateAccountToken(accountID, purpose, tokenHash string, ttl time.Duration, meta TokenMetadata) (AccountToken, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return AccountToken{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM account_token WHERE account_id = $1 AND purpose = $2 AND used_at IS NULL`,
		accountID, purpose); err != nil {
		return AccountToken{}, err
	}
	b, _ := json.Marshal(meta)
	t := AccountToken{AccountID: accountID, Purpose: purpose, Metadata: meta}
	err = tx.QueryRow(`INSERT INTO account_token (account_id, purpose, token_hash, metadata, expires_at)
		VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5)) RETURNING id, expires_at`,
		accountID, purpose, tokenHash, string(b), ttl.Seconds()).Scan(&t.ID, &t.ExpiresAt)
	if err != nil {
		return AccountToken{}, err
	}
	return t, tx.Commit()
}

const tokenColumns = `id, account_id, purpose, metadata, expires_at, used_at`

func scanToken(s scanner) (AccountToken, error) {
	var t AccountToken
	var meta []byte
	var used sql.NullTime
	if err := s.Scan(&t.ID, &t.AccountID, &t.Purpose, &meta, &t.ExpiresAt, &used); err != nil {
		return t, err
	}
	json.Unmarshal(meta, &t.Metadata)
	if used.Valid {
		t.UsedAt = &used.Time
	}
	return t, nil
}

// checkToken turns a found token into ErrTokenUsed or ErrTokenExpired when it can no longer be used.
func checkToken(t AccountToken, err error, purpose string) (AccountToken, error) {
	switch {
	case errors.Is(err, sql.ErrNoRows) || (err == nil && t.Purpose != purpose):
		return AccountToken{}, ErrTokenInvalid
	case err != nil:
		return AccountToken{}, err
	case t.UsedAt != nil:
		return t, ErrTokenUsed
	case time.Now().After(t.ExpiresAt):
		return t, ErrTokenExpired
	}
	return t, nil
}

// PeekAccountToken returns a usable token without using it (to show the form a link leads to).
func PeekAccountToken(tokenHash, purpose string) (AccountToken, error) {
	t, err := scanToken(GetDatabaseConnection().QueryRow(
		`SELECT `+tokenColumns+` FROM account_token WHERE token_hash = $1`, tokenHash))
	return checkToken(t, err, purpose)
}

// FindSignupToken returns the newest email confirmation of the sign-up made in a browser, identified by
// the hash of that browser's sign-up cookie. A used or expired one comes with ErrTokenUsed or
// ErrTokenExpired: the sign-up may still wait (its address was taken, or the link ran out).
func FindSignupToken(browserHash string) (AccountToken, error) {
	t, err := scanToken(GetDatabaseConnection().QueryRow(
		`SELECT `+tokenColumns+` FROM account_token
		 WHERE purpose = 'email_verify' AND metadata->>'browser' = $1
		 ORDER BY created_at DESC LIMIT 1`, browserHash))
	return checkToken(t, err, TokenEmailVerify)
}

// useToken marks a token used, inside tx, and returns it. Two clicks at once cannot both use it.
func useToken(tx *sql.Tx, tokenHash, purpose string) (AccountToken, error) {
	t, err := scanToken(tx.QueryRow(
		`SELECT `+tokenColumns+` FROM account_token WHERE token_hash = $1 FOR UPDATE`, tokenHash))
	if t, err = checkToken(t, err, purpose); err != nil {
		return t, err
	}
	_, err = tx.Exec(`UPDATE account_token SET used_at = now() WHERE id = $1`, t.ID)
	return t, err
}

// ConfirmEmail uses an email_verify token: the address becomes the account's (confirmed) email, and an
// account that was waiting for it at sign-up becomes active. If another account confirmed the same address
// first, it returns ErrEmailTaken and the token stays used.
func ConfirmEmail(tokenHash string) (AccountToken, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return AccountToken{}, err
	}
	defer tx.Rollback()
	t, err := useToken(tx, tokenHash, TokenEmailVerify)
	if err != nil {
		return t, err
	}
	var taken bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM account WHERE lower(email) = lower($1) AND id <> $2)`,
		t.Metadata.Email, t.AccountID).Scan(&taken); err != nil {
		return t, err
	}
	if taken {
		return t, commitThen(tx, ErrEmailTaken)
	}
	res, err := tx.Exec(`UPDATE account SET email = $2, email_verified_at = now(), updated_at = now(),
			status = CASE WHEN status = 'pending' THEN 'active' ELSE status END
		 WHERE id = $1 AND deleted_at IS NULL AND status IN ('pending', 'active')`, t.AccountID, t.Metadata.Email)
	if IsUniqueViolation(err) {
		// Another confirmation of the same address won the race.
		tx.Rollback()
		return t, ErrEmailTaken
	}
	if err != nil {
		return t, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return t, commitThen(tx, ErrTokenInvalid)
	}
	return t, tx.Commit()
}

func commitThen(tx *sql.Tx, result error) error {
	if err := tx.Commit(); err != nil {
		return err
	}
	return result
}

// ResetPassword uses a password_reset token and sets the new password hash. It ends every session of the
// account and returns the back-channel logouts to send.
func ResetPassword(tokenHash, newHash string) (AccountToken, []LogoutNotice, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return AccountToken{}, nil, err
	}
	defer tx.Rollback()
	t, err := useToken(tx, tokenHash, TokenPasswordReset)
	if err != nil {
		return t, nil, err
	}
	res, err := tx.Exec(`UPDATE account SET password_hash = $2, must_change_password = FALSE, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NULL AND status = 'active'`, t.AccountID, newHash)
	if err != nil {
		return t, nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return t, nil, ErrTokenInvalid
	}
	notices, err := revokeAccountSessions(tx, t.AccountID, "")
	if err != nil {
		return t, nil, err
	}
	return t, notices, tx.Commit()
}

// CreatePendingAccount creates an account that waits for its email address to be confirmed. It cannot sign
// in until then, and maintenance removes it if the confirmation never comes.
func CreatePendingAccount(username, passwordHash string) (Account, error) {
	var id string
	err := GetDatabaseConnection().QueryRow(withDefaultGroups(
		`INSERT INTO account (username, password_hash, status) VALUES ($1, $2, 'pending') RETURNING id`),
		username, passwordHash).Scan(&id)
	if err != nil {
		return Account{}, err
	}
	return GetAccount(id)
}

// EmailInUse reports whether an account already has this (confirmed) address.
func EmailInUse(email string) (bool, error) {
	var used bool
	err := GetDatabaseConnection().QueryRow(
		`SELECT EXISTS (SELECT 1 FROM account WHERE lower(email) = lower($1))`, email).Scan(&used)
	return used, err
}

// PendingSignupLifetime is how long an account may wait for its email confirmation before maintenance
// removes it (and frees its username): the link's 24 hours, and a day to spare.
const PendingSignupLifetime = 48 * time.Hour
