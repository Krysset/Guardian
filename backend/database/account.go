package database

import (
	"database/sql"
	"errors"
	"log"

	"github.com/lib/pq"
)

const accountColumns = `id, username, COALESCE(display_name, ''), COALESCE(given_name, ''), COALESCE(family_name, ''),
	COALESCE(picture_url, ''), COALESCE(locale, ''), COALESCE(zoneinfo, ''),
	COALESCE(email, ''), email_verified_at IS NOT NULL, COALESCE(phone_number, ''), phone_verified_at IS NOT NULL,
	status, must_change_password, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanAccount(s scanner, extra ...any) (Account, error) {
	var a Account
	dest := []any{&a.ID, &a.Username, &a.DisplayName, &a.GivenName, &a.FamilyName, &a.PictureURL, &a.Locale, &a.Zoneinfo,
		&a.Email, &a.EmailVerified, &a.PhoneNumber, &a.PhoneVerified, &a.Status, &a.MustChangePassword, &a.CreatedAt, &a.UpdatedAt}
	dest = append(dest, extra...)
	err := s.Scan(dest...)
	return a, err
}

// IsUniqueViolation reports whether err is a Postgres unique-constraint violation.
func IsUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

func GetAccount(id string) (Account, error) {
	if !IsUUID(id) {
		return Account{}, sql.ErrNoRows
	}
	return scanAccount(GetDatabaseConnection().QueryRow(
		`SELECT `+accountColumns+` FROM account WHERE id = $1 AND deleted_at IS NULL`, id))
}

// GetAccountByUsername also returns the stored password hash ("" if the account has none).
func GetAccountByUsername(username string) (Account, string, error) {
	var hash string
	a, err := scanAccount(GetDatabaseConnection().QueryRow(
		`SELECT `+accountColumns+`, COALESCE(password_hash, '') FROM account
		 WHERE lower(username) = lower($1) AND deleted_at IS NULL`, username), &hash)
	return a, hash, err
}

func GetPasswordHash(id string) (string, error) {
	var hash string
	err := GetDatabaseConnection().QueryRow(
		`SELECT COALESCE(password_hash, '') FROM account WHERE id = $1 AND deleted_at IS NULL`, id).Scan(&hash)
	return hash, err
}

func CreateAccount(username, passwordHash string) (Account, error) {
	var id string
	err := GetDatabaseConnection().QueryRow(
		`INSERT INTO account (username, password_hash) VALUES ($1, $2) RETURNING id`, username, passwordHash).Scan(&id)
	if err != nil {
		log.Println("Failed to create account:", err)
		return Account{}, err
	}
	return GetAccount(id)
}

// UpdateProfile writes the user-editable profile fields. Changing the email clears its verification.
func UpdateProfile(a Account) (Account, error) {
	_, err := GetDatabaseConnection().Exec(
		`UPDATE account SET
			display_name = NULLIF($2, ''), given_name = NULLIF($3, ''), family_name = NULLIF($4, ''),
			picture_url = NULLIF($5, ''), locale = NULLIF($6, ''), zoneinfo = NULLIF($7, ''),
			email_verified_at = CASE WHEN email IS DISTINCT FROM NULLIF($8, '') THEN NULL ELSE email_verified_at END,
			email = NULLIF($8, ''), updated_at = now()
		 WHERE id = $1 AND deleted_at IS NULL`,
		a.ID, a.DisplayName, a.GivenName, a.FamilyName, a.PictureURL, a.Locale, a.Zoneinfo, a.Email)
	if err != nil {
		return Account{}, err
	}
	return GetAccount(a.ID)
}

func UpdateUsername(id, newUsername string) error {
	_, err := GetDatabaseConnection().Exec(
		`UPDATE account SET username = $2, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`, id, newUsername)
	return err
}

func UpdatePasswordHash(id, hash string) error {
	_, err := GetDatabaseConnection().Exec(
		`UPDATE account SET password_hash = $2, must_change_password = FALSE, updated_at = now() WHERE id = $1`, id, hash)
	return err
}

func TouchLogin(id string) {
	GetDatabaseConnection().Exec(`UPDATE account SET last_login_at = now() WHERE id = $1`, id)
}

// SoftDeleteAccount disables the account and ends all its sessions and refresh tokens, in one
// transaction. Access tokens stop being valid on their own: introspection requires an active account
// and a non-revoked session.
func SoftDeleteAccount(id string) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		`UPDATE account SET deleted_at = now(), status = 'disabled' WHERE id = $1 AND deleted_at IS NULL`,
		`UPDATE session SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL`,
		`UPDATE refresh_token SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL`,
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetAdminPasswordIfUnset gives the seeded admin account its first password. Returns true if it changed anything.
func SetAdminPasswordIfUnset(hash string) (bool, error) {
	res, err := GetDatabaseConnection().Exec(
		`UPDATE account SET password_hash = $1 WHERE username = 'admin' AND password_hash IS NULL`, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
