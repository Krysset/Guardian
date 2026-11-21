package store

import (
	"database/sql"
	"errors"
	"time"
)

// Two-factor: one authenticator app (TOTP) per account, security keys and passkeys (webauthn.go), and the
// recovery codes that come with the first of them, in account_mfa. The TOTP secret is stored encrypted with
// the key encryption key; recovery codes only as hashes, and a used code is deleted.

// MFAStatus is what an account has set up.
type MFAStatus struct {
	TOTP              bool          `json:"totp"`
	TOTPAddedAt       *time.Time    `json:"totp_added_at,omitempty"`
	RecoveryCodesLeft int           `json:"recovery_codes_left"`
	SecurityKeys      []SecurityKey `json:"security_keys"`
}

// Any reports whether the account has a second factor: the authenticator app or a security key.
func (s MFAStatus) Any() bool { return s.TOTP || len(s.SecurityKeys) > 0 }

// GetMFAStatus returns the account's two-factor methods.
func GetMFAStatus(accountID string) (MFAStatus, error) {
	var s MFAStatus
	var added sql.NullTime
	err := GetDatabaseConnection().QueryRow(`SELECT
		(SELECT min(created_at) FROM account_mfa WHERE account_id = $1 AND type = 'totp'),
		(SELECT count(*) FROM account_mfa WHERE account_id = $1 AND type = 'recovery_code')`, accountID).
		Scan(&added, &s.RecoveryCodesLeft)
	if err != nil {
		return s, err
	}
	if added.Valid {
		s.TOTP, s.TOTPAddedAt = true, &added.Time
	}
	keys, err := ListSecurityKeys(accountID)
	s.SecurityKeys = make([]SecurityKey, len(keys))
	for i, k := range keys {
		s.SecurityKeys[i] = k.SecurityKey
	}
	return s, err
}

// HasTOTP reports whether the account has an authenticator app.
func HasTOTP(accountID string) (bool, error) {
	s, err := GetMFAStatus(accountID)
	return s.TOTP, err
}

// HasSecondFactor reports whether the account has an authenticator app or a security key.
func HasSecondFactor(accountID string) (bool, error) {
	var has bool
	err := GetDatabaseConnection().QueryRow(
		`SELECT EXISTS (SELECT 1 FROM account_mfa WHERE account_id = $1 AND type IN ('totp', 'webauthn'))`, accountID).Scan(&has)
	return has, err
}

// MFARequirement says why an account must use two-factor, or "" if it need not: members of
// guardian-admins, owners (members of a group that owns another group), and app admins (members of a group
// that owns an app).
func MFARequirement(accountID string) (string, error) {
	var admin, owner, appAdmin bool
	err := GetDatabaseConnection().QueryRow(`SELECT
		EXISTS (SELECT 1 FROM group_member m JOIN user_group g ON g.id = m.group_id
		        WHERE m.account_id = $1 AND g.key = $2 AND `+activeMember+`),
		EXISTS (SELECT 1 FROM group_member m JOIN user_group owned ON owned.owner_group_id = m.group_id
		        WHERE m.account_id = $1 AND `+activeMember+`),
		EXISTS (SELECT 1 FROM group_member m JOIN app a ON a.owner_group_id = m.group_id
		        WHERE m.account_id = $1 AND `+activeMember+`)`, accountID, AdminGroupKey).Scan(&admin, &owner, &appAdmin)
	switch {
	case err != nil:
		return "", err
	case admin:
		return "Administrators must use two-factor.", nil
	case owner:
		return "Group owners must use two-factor.", nil
	case appAdmin:
		return "App admins must use two-factor.", nil
	}
	return "", nil
}

// TOTPFactor is an account's authenticator app.
type TOTPFactor struct {
	ID            string
	SealedSecret  string
	LastStep      int64
	AccountID     string
	RecoveryCount int
}

// GetTOTP returns the account's authenticator app, or sql.ErrNoRows.
func GetTOTP(accountID string) (TOTPFactor, error) {
	f := TOTPFactor{AccountID: accountID}
	var last sql.NullInt64
	err := GetDatabaseConnection().QueryRow(
		`SELECT id, secret, sign_count FROM account_mfa WHERE account_id = $1 AND type = 'totp'`, accountID).
		Scan(&f.ID, &f.SealedSecret, &last)
	f.LastStep = last.Int64
	return f, err
}

// UseTOTPStep records a time step as used. It fails (false) if that step or a later one was used already,
// so a code cannot be used twice even by two requests at once.
func UseTOTPStep(factorID string, step int64) (bool, error) {
	res, err := GetDatabaseConnection().Exec(
		`UPDATE account_mfa SET sign_count = $2, last_used_at = now()
		 WHERE id = $1 AND COALESCE(sign_count, -1) < $2`, factorID, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// SaveTOTP sets up the account's authenticator app with its recovery codes, replacing any it had. step is
// the time step of the code that confirmed the setup, so that code cannot sign in as well.
func SaveTOTP(accountID, sealedSecret string, codeHashes []string, step int64) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM account_mfa WHERE account_id = $1 AND type IN ('totp', 'recovery_code')`, accountID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO account_mfa (account_id, type, name, secret, sign_count)
		VALUES ($1, 'totp', 'Authenticator app', $2, $3)`, accountID, sealedSecret, step); err != nil {
		return err
	}
	if err := insertRecoveryCodes(tx, accountID, codeHashes); err != nil {
		return err
	}
	return tx.Commit()
}

func insertRecoveryCodes(tx *sql.Tx, accountID string, hashes []string) error {
	_, err := tx.Exec(`INSERT INTO account_mfa (account_id, type, secret)
		SELECT $1, 'recovery_code', h FROM unnest($2::text[]) AS h`, accountID, strArray(hashes))
	return err
}

// ErrNoTOTP means the account has no authenticator app.
var ErrNoTOTP = errors.New("the account has no authenticator app")

// ErrNoSecondFactor means the account has no two-factor method, so recovery codes have nothing to recover.
var ErrNoSecondFactor = errors.New("the account has no two-factor method")

// ReplaceRecoveryCodes gives an account with a second factor a new set of recovery codes.
func ReplaceRecoveryCodes(accountID string, codeHashes []string) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var has bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM account_mfa WHERE account_id = $1 AND type IN ('totp', 'webauthn') FOR UPDATE)`,
		accountID).Scan(&has); err != nil {
		return err
	}
	if !has {
		return ErrNoSecondFactor
	}
	if _, err := tx.Exec(`DELETE FROM account_mfa WHERE account_id = $1 AND type = 'recovery_code'`, accountID); err != nil {
		return err
	}
	if err := insertRecoveryCodes(tx, accountID, codeHashes); err != nil {
		return err
	}
	return tx.Commit()
}

// UseRecoveryCode deletes the recovery code with this hash, and returns whether it existed and how many
// codes are left.
func UseRecoveryCode(accountID, codeHash string) (bool, int, error) {
	res, err := GetDatabaseConnection().Exec(
		`DELETE FROM account_mfa WHERE account_id = $1 AND type = 'recovery_code' AND secret = $2`, accountID, codeHash)
	if err != nil {
		return false, 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, 0, nil
	}
	var left int
	err = GetDatabaseConnection().QueryRow(
		`SELECT count(*) FROM account_mfa WHERE account_id = $1 AND type = 'recovery_code'`, accountID).Scan(&left)
	return true, left, err
}

// RemoveMFA removes every two-factor method of the account and returns how many there were.
func RemoveMFA(accountID string) (int, error) {
	res, err := GetDatabaseConnection().Exec(`DELETE FROM account_mfa WHERE account_id = $1`, accountID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// StepUpSession records that the session's user has just passed two-factor: method ("otp" for a code,
// "hwk" for a security key) joins the session's amr, and auth_time moves to now.
func StepUpSession(sessionID, method string) error {
	_, err := GetDatabaseConnection().Exec(
		`UPDATE session SET amr = ARRAY(SELECT DISTINCT unnest(amr || ARRAY[$2]) ORDER BY 1), auth_time = now()
		 WHERE id = $1 AND revoked_at IS NULL`, sessionID, method)
	return err
}

// TwoFactorAMR are the amr values that show a session passed two-factor: a code from the authenticator app
// or a recovery code ("otp"), or a security key or passkey ("hwk").
var TwoFactorAMR = []string{"otp", "hwk"}
