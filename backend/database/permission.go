package database

// All permission questions are answered from the account_effective_permission view (see schema.sql),
// straight from Postgres on every call. There is deliberately no cache: a role or grant that was
// committed is visible to the very next call, on every Guardian replica.

func AccountHasRole(accountID, roleName string) (bool, error) {
	var ok bool
	err := GetDatabaseConnection().QueryRow(
		`SELECT EXISTS (SELECT 1 FROM account_role ar JOIN role r ON r.id = ar.role_id
		   WHERE ar.account_id = $1 AND r.name = $2 AND (ar.expires_at IS NULL OR ar.expires_at > now()))`,
		accountID, roleName).Scan(&ok)
	return ok, err
}

func AccountHasPermission(accountID, appName, permission string) (bool, error) {
	var ok bool
	err := GetDatabaseConnection().QueryRow(
		`SELECT EXISTS (SELECT 1 FROM account_effective_permission e JOIN app a ON a.id = e.app_id
		   WHERE e.account_id = $1 AND a.name = $2 AND e.name = $3)`,
		accountID, appName, permission).Scan(&ok)
	return ok, err
}
