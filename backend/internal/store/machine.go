package store

import (
	"database/sql"
	"errors"
)

// The machine API lets an app read, with its own credentials, what it needs about its users: its linked
// groups, their members, and the accounts it may know about. An app may know about an account that is an
// active member of one of its linked groups, or that has signed in to it. Nothing else is visible.

// RecordAppUser notes that the account signed in to the app. It is called when an authorization code is
// exchanged, not on refreshes.
func RecordAppUser(appID, accountID string) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO app_user (app_id, account_id) VALUES ($1, $2)
		 ON CONFLICT (app_id, account_id) DO UPDATE SET last_signed_in_at = now()`, appID, accountID)
	return err
}

// SetMachineAccess turns the app's machine API access (the client_credentials grant) on or off. Only
// apps with a secret can have it. Tokens already issued stop working at once, because the machine API
// checks the grant on every request.
func SetMachineAccess(appID string, on bool) error {
	res, err := GetDatabaseConnection().Exec(
		`UPDATE app SET grant_types = CASE
		     WHEN $2 THEN array_append(array_remove(grant_types, 'client_credentials'), 'client_credentials')
		     ELSE array_remove(grant_types, 'client_credentials') END
		 WHERE id = $1 AND (client_type = 'confidential' OR NOT $2)`, appID, on)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// AppGroup is a group as an app sees it.
type AppGroup struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	MemberCount int    `json:"member_count"`
}

// ListAppGroups returns the groups linked to the app.
func ListAppGroups(appID string) ([]AppGroup, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT g.key, g.display_name, g.description,
		        (SELECT count(*) FROM group_member m JOIN account a ON a.id = m.account_id AND a.deleted_at IS NULL
		          WHERE m.group_id = g.id AND `+activeMember+`)
		 FROM app_group ag JOIN user_group g ON g.id = ag.group_id
		 WHERE ag.app_id = $1 ORDER BY g.key`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppGroup{}
	for rows.Next() {
		var g AppGroup
		if err := rows.Scan(&g.Key, &g.DisplayName, &g.Description, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListAppGroupMembers returns the active members of one of the app's linked groups, by the group's key.
// A group that exists but is not linked to the app is reported as not found.
func ListAppGroupMembers(appID, groupKey string) ([]Account, error) {
	var groupID string
	err := GetDatabaseConnection().QueryRow(
		`SELECT g.id FROM user_group g JOIN app_group ag ON ag.group_id = g.id AND ag.app_id = $1 WHERE g.key = $2`,
		appID, groupKey).Scan(&groupID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, err
	}
	// accountColumns are unqualified; none of them exists in group_member, so they are unambiguous here.
	rows, err := GetDatabaseConnection().Query(
		`SELECT `+accountColumns+` FROM group_member m JOIN account a ON a.id = m.account_id
		 WHERE m.group_id = $1 AND `+activeMember+` AND a.deleted_at IS NULL ORDER BY lower(a.username)`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		acct, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, acct)
	}
	return out, rows.Err()
}

// AppMayKnowAccount reports whether the app may look the account up: the account is an active member of
// a group linked to the app, or it has signed in to the app.
func AppMayKnowAccount(appID, accountID string) (bool, error) {
	if !IsUUID(accountID) {
		return false, nil
	}
	var ok bool
	err := GetDatabaseConnection().QueryRow(
		`SELECT EXISTS (SELECT 1 FROM app_user WHERE app_id = $1 AND account_id = $2)
		     OR EXISTS (SELECT 1 FROM group_member m JOIN app_group ag ON ag.group_id = m.group_id AND ag.app_id = $1
		                WHERE m.account_id = $2 AND `+activeMember+`)`, appID, accountID).Scan(&ok)
	return ok, err
}
