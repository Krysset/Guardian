package store

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

const accountColumns = `id, username, COALESCE(display_name, ''), COALESCE(given_name, ''), COALESCE(family_name, ''),
	COALESCE(picture_url, ''), COALESCE(locale, ''), COALESCE(zoneinfo, ''),
	COALESCE(email, ''), email_verified_at IS NOT NULL,
	status, must_change_password, created_at, updated_at, last_login_at`

type scanner interface{ Scan(dest ...any) error }

func scanAccount(s scanner, extra ...any) (Account, error) {
	var a Account
	var lastLogin sql.NullTime
	dest := []any{&a.ID, &a.Username, &a.DisplayName, &a.GivenName, &a.FamilyName, &a.PictureURL, &a.Locale, &a.Zoneinfo,
		&a.Email, &a.EmailVerified, &a.Status, &a.MustChangePassword, &a.CreatedAt, &a.UpdatedAt, &lastLogin}
	dest = append(dest, extra...)
	err := s.Scan(dest...)
	// Times leave the API in UTC, whatever time zone the server runs in.
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	if lastLogin.Valid {
		t := lastLogin.Time.UTC()
		a.LastLoginAt = &t
	}
	return a, err
}

// IsUniqueViolation reports whether err is a Postgres unique-constraint violation.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
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

// GetAccountForLogin finds the account to sign in by its username or its (always confirmed) email address.
// Usernames cannot contain "@", so the two never clash.
func GetAccountForLogin(login string) (Account, string, error) {
	if !strings.Contains(login, "@") {
		return GetAccountByUsername(login)
	}
	var hash string
	a, err := scanAccount(GetDatabaseConnection().QueryRow(
		`SELECT `+accountColumns+`, COALESCE(password_hash, '') FROM account
		 WHERE lower(email) = lower($1) AND deleted_at IS NULL`, login), &hash)
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
		slog.Error("failed to create an account", "error", err)
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
// transaction. From then on every refresh fails, and userinfo refuses the account's access tokens. It
// returns the back-channel logouts to send, so apps that support them drop the user at once.
// It refuses to delete the last administrator (ErrLastAdmin).
func SoftDeleteAccount(id string) ([]LogoutNotice, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	adminGroupID, err := lockAdminGroup(tx)
	if err != nil {
		return nil, err
	}
	var isAdmin bool
	if err := tx.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM group_member WHERE group_id = $1 AND account_id = $2)`, adminGroupID, id).Scan(&isAdmin); err != nil {
		return nil, err
	}
	if isAdmin {
		if n, err := otherPermanentAdmins(tx, adminGroupID, id); err != nil {
			return nil, err
		} else if n == 0 {
			return nil, ErrLastAdmin
		}
	}
	notices, err := revokeAccountSessions(tx, id, "")
	if err != nil {
		return nil, err
	}
	stmts := []string{
		`UPDATE account SET deleted_at = now(), status = 'disabled' WHERE id = $1 AND deleted_at IS NULL`,
		// A deleted account must not keep counting as a group member, for example as an administrator.
		`DELETE FROM group_member WHERE account_id = $1`,
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q, id); err != nil {
			return nil, err
		}
	}
	return notices, tx.Commit()
}

// queryer is the part of *sql.DB and *sql.Tx that logoutNotices needs.
type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// logoutNotices runs a query that returns client_id, backchannel_logout_uri, account_id, session_id.
func logoutNotices(q queryer, query string, args ...any) ([]LogoutNotice, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogoutNotice
	for rows.Next() {
		var n LogoutNotice
		if err := rows.Scan(&n.ClientID, &n.URI, &n.AccountID, &n.SessionID); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
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
