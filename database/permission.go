package database

import (
	_ "github.com/lib/pq"
)

func UserHasAdmin(uID string) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM account WHERE id = $1 AND is_admin = true)`
	var hasAdmin bool
	err := GetDatabaseConnection().QueryRow(query, uID).Scan(&hasAdmin)
	if err != nil {
		return false, err
	}
	return hasAdmin, nil
}

func GetUserPermissions(uID string, appID string) ([]Permission, error) {
	var permissions []Permission
	query := `SELECT p.id, p.name, p.pretty_name, p.description FROM permission p
	JOIN account_permission ap ON p.id = ap.permission_id
	WHERE ap.account_id = $1 AND ap.app_id = $2`
	rows, err := GetDatabaseConnection().Query(query, uID, appID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var permission Permission
		err := rows.Scan(&permission.ID, &permission.Name, &permission.PrettyName, &permission.Description)
		if err != nil {
			continue
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}
