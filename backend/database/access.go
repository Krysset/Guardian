package database

import (
	"errors"
	"time"

	"github.com/lib/pq"
)

// Every function here changes who may do what. Nothing is cached anywhere, so a committed change is
// seen by the very next permission check or token introspection, on every replica.

var ErrSystemRole = errors.New("role not found, or it is a built-in system role")

type Role struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	PrettyName     string   `json:"pretty_name"`
	Description    string   `json:"description"`
	AllPermissions bool     `json:"all_permissions"`
	IsSystem       bool     `json:"is_system"`
	PermissionIDs  []string `json:"permission_ids"`
}

type AppPermission struct {
	ID          string `json:"id"`
	AppID       string `json:"app_id"`
	AppName     string `json:"app_name"`
	Name        string `json:"name"`
	PrettyName  string `json:"pretty_name"`
	Description string `json:"description"`
}

func ListRoles() ([]Role, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT r.id, r.name, r.pretty_name, r.description, r.all_permissions, r.is_system,
		        COALESCE(array_agg(rp.permission_id::text) FILTER (WHERE rp.permission_id IS NOT NULL), '{}')
		 FROM role r LEFT JOIN role_permission rp ON rp.role_id = r.id
		 GROUP BY r.id ORDER BY r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.PrettyName, &r.Description, &r.AllPermissions, &r.IsSystem, pq.Array(&r.PermissionIDs)); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func ListAppPermissions() ([]AppPermission, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT p.id, p.app_id, a.name, p.name, p.pretty_name, p.description
		 FROM app_permission p JOIN app a ON a.id = p.app_id ORDER BY a.name, p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppPermission{}
	for rows.Next() {
		var p AppPermission
		if err := rows.Scan(&p.ID, &p.AppID, &p.AppName, &p.Name, &p.PrettyName, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreateAppPermission defines a permission for an app. Catchall roles hold it automatically.
func CreateAppPermission(appID, name, prettyName, description string) (string, error) {
	var id string
	err := GetDatabaseConnection().QueryRow(
		`INSERT INTO app_permission (app_id, name, pretty_name, description) VALUES ($1, $2, $3, $4) RETURNING id`,
		appID, name, prettyName, description).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

// CreateRole makes a new role (it has no holders yet, so nothing to invalidate).
func CreateRole(name, prettyName, description string, allPermissions bool, permissionIDs []string) (string, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id string
	if err := tx.QueryRow(
		`INSERT INTO role (name, pretty_name, description, all_permissions) VALUES ($1, $2, $3, $4) RETURNING id`,
		name, prettyName, description, allPermissions).Scan(&id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO role_permission (role_id, permission_id) SELECT $1::uuid, id FROM app_permission WHERE id = ANY($2::uuid[])`,
		id, pq.Array(permissionIDs)); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

// SetRolePermissions replaces a role's permission set (effective for all holders at commit).
func SetRolePermissions(roleID string, permissionIDs []string) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var isSystem bool
	if err := tx.QueryRow(`SELECT is_system FROM role WHERE id = $1 FOR UPDATE`, roleID).Scan(&isSystem); err != nil {
		return err
	}
	if isSystem {
		return ErrSystemRole
	}
	if _, err := tx.Exec(`DELETE FROM role_permission WHERE role_id = $1`, roleID); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO role_permission (role_id, permission_id) SELECT $1::uuid, id FROM app_permission WHERE id = ANY($2::uuid[])`,
		roleID, pq.Array(permissionIDs)); err != nil {
		return err
	}
	return tx.Commit()
}

func DeleteRole(roleID string) error {
	res, err := GetDatabaseConnection().Exec(`DELETE FROM role WHERE id = $1 AND NOT is_system`, roleID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSystemRole
	}
	return nil
}

func GrantRole(accountID, roleID, grantedBy string, expiresAt *time.Time) error {
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO account_role (account_id, role_id, granted_by, expires_at)
		 VALUES ($1, $2, NULLIF($3, '')::uuid, $4)
		 ON CONFLICT (account_id, role_id)
		 DO UPDATE SET expires_at = EXCLUDED.expires_at, granted_by = EXCLUDED.granted_by, granted_at = now()`,
		accountID, roleID, grantedBy, expiresAt)
	return err
}

func RevokeRole(accountID, roleID string) error {
	_, err := GetDatabaseConnection().Exec(`DELETE FROM account_role WHERE account_id = $1 AND role_id = $2`, accountID, roleID)
	return err
}

// GrantPermission gives one permission directly. attributes is a JSON object the app interprets
// (limits, resource ids, ...); "" means {}.
func GrantPermission(accountID, permissionID, grantedBy, attributes string, expiresAt *time.Time) error {
	if attributes == "" {
		attributes = "{}"
	}
	_, err := GetDatabaseConnection().Exec(
		`INSERT INTO account_app_permission (account_id, permission_id, attributes, granted_by, expires_at)
		 VALUES ($1, $2, $3::jsonb, NULLIF($4, '')::uuid, $5)
		 ON CONFLICT (account_id, permission_id)
		 DO UPDATE SET attributes = EXCLUDED.attributes, expires_at = EXCLUDED.expires_at,
		               granted_by = EXCLUDED.granted_by, granted_at = now()`,
		accountID, permissionID, attributes, grantedBy, expiresAt)
	return err
}

func RevokePermission(accountID, permissionID string) error {
	_, err := GetDatabaseConnection().Exec(
		`DELETE FROM account_app_permission WHERE account_id = $1 AND permission_id = $2`, accountID, permissionID)
	return err
}
