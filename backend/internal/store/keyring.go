package store

// The values the encryption keyring protects. Each is stored as "v1:<key id>:...", with the table, column
// and row as associated data (auth.AAD). Re-encryption reads them all and rewrites those under an older key.

// EncryptedValue is one keyring value and where it is stored.
type EncryptedValue struct {
	Table, Column, Row string // Row is the signing key's kid, or the account id of an authenticator app
	Value              string
}

// EncryptedValues returns every keyring value in the database.
func EncryptedValues() ([]EncryptedValue, error) {
	rows, err := GetDatabaseConnection().Query(`
		SELECT 'signing_key', 'private_key_encrypted', kid, private_key_encrypted FROM signing_key WHERE private_key_encrypted IS NOT NULL
		UNION ALL
		SELECT 'account_mfa', 'secret', account_id::text, secret FROM account_mfa WHERE type = 'totp'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EncryptedValue
	for rows.Next() {
		var v EncryptedValue
		if err := rows.Scan(&v.Table, &v.Column, &v.Row, &v.Value); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ReplaceEncryptedValue writes a re-encrypted value, only if the stored value is still the one that was
// read (another replica may have re-encrypted it, or the row changed).
func ReplaceEncryptedValue(v EncryptedValue, newValue string) (bool, error) {
	q := `UPDATE signing_key SET private_key_encrypted = $3 WHERE kid = $1 AND private_key_encrypted = $2`
	if v.Table == "account_mfa" {
		q = `UPDATE account_mfa SET secret = $3 WHERE account_id::text = $1 AND type = 'totp' AND secret = $2`
	}
	res, err := GetDatabaseConnection().Exec(q, v.Row, v.Value, newValue)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// TOTPAccounts returns the accounts with an authenticator app, with their email address if they have one.
func TOTPAccounts() ([]Account, error) {
	rows, err := GetDatabaseConnection().Query(`SELECT ` + accountColumns + ` FROM account
		WHERE id IN (SELECT account_id FROM account_mfa WHERE type = 'totp') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RemoveAllTOTP removes every authenticator app (`guardian mfa reset-totp --all`, after a keyring key leaked:
// the apps' secrets are encrypted with it). Security keys hold nothing secret and stay, and so do the recovery
// codes of accounts that keep a key; the codes of accounts left without a second factor go. It returns how
// many apps were removed.
func RemoveAllTOTP() (int, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM account_mfa WHERE type = 'totp'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec(`DELETE FROM account_mfa c WHERE c.type = 'recovery_code' AND NOT EXISTS (
		SELECT 1 FROM account_mfa k WHERE k.account_id = c.account_id AND k.type = 'webauthn')`); err != nil {
		return 0, err
	}
	return int(n), tx.Commit()
}
