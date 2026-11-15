package store

import (
	"database/sql"
	"log/slog"
	"regexp"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID guards queries against invalid input (Postgres errors on malformed uuid literals).
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

// appColumns includes the allowed scopes, so one query loads a complete App.
const appColumns = `id, name, pretty_name, description, COALESCE(logo_url, ''), COALESCE(homepage_url, ''),
	client_id, client_type, token_endpoint_auth_method, grant_types, redirect_uris, post_logout_redirect_uris,
	COALESCE(backchannel_logout_uri, ''), require_pkce, is_first_party, access_token_ttl_seconds, refresh_mode, enabled,
	ARRAY(SELECT scope_name FROM app_scope WHERE app_scope.app_id = app.id ORDER BY scope_name),
	access_rule, ARRAY(SELECT group_id::text FROM app_group WHERE app_group.app_id = app.id ORDER BY 1)`

func scanApp(s scanner) (App, error) {
	var a App
	err := s.Scan(&a.ID, &a.Name, &a.PrettyName, &a.Description, &a.LogoURL, &a.HomepageURL,
		&a.ClientID, &a.ClientType, &a.TokenEndpointAuthMethod,
		scanArray(&a.GrantTypes), scanArray(&a.RedirectURIs), scanArray(&a.PostLogoutRedirectURIs),
		&a.BackchannelLogoutURI, &a.RequirePKCE, &a.IsFirstParty, &a.AccessTokenTTL, &a.RefreshMode, &a.Enabled,
		scanArray(&a.Scopes), &a.AccessRule, scanArray(&a.GroupIDs))
	return a, err
}

// AddApp creates an app, its first secret (if secretHash != ""), its allowed scopes and its linked groups.
// An empty a.AccessRule means "groups": nobody may sign in until a group is linked or the rule is changed.
func AddApp(a App, scopes []string, secretHash string) (App, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return App{}, err
	}
	defer tx.Rollback()

	// An app with a secret may refresh: a stolen refresh token is useless without the secret. An app
	// without one (a browser-only or mobile app) gets no refresh tokens for now.
	authMethod, grants, refreshMode := "client_secret_basic", []string{"authorization_code", "refresh_token"}, "stable"
	if a.ClientType == "public" {
		authMethod, grants, refreshMode = "none", []string{"authorization_code"}, "none"
	}
	var id string
	err = tx.QueryRow(
		`INSERT INTO app (name, pretty_name, description, logo_url, homepage_url, client_type, token_endpoint_auth_method,
			redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, is_first_party, access_token_ttl_seconds, access_rule,
			grant_types, refresh_mode)
		 VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7, $8, $9, NULLIF($10, ''), $11, COALESCE(NULLIF($12, 0), 300),
		         COALESCE(NULLIF($13, ''), 'groups'), $14, $15)
		 RETURNING id`,
		a.Name, a.PrettyName, a.Description, a.LogoURL, a.HomepageURL, a.ClientType, authMethod,
		strArray(a.RedirectURIs), strArray(a.PostLogoutRedirectURIs), a.BackchannelLogoutURI, a.IsFirstParty,
		a.AccessTokenTTL, a.AccessRule, grants, refreshMode).Scan(&id)
	if err != nil {
		slog.Error("failed to create an app", "app", a.Name, "error", err)
		return App{}, err
	}
	if secretHash != "" {
		if _, err := tx.Exec(`INSERT INTO app_secret (app_id, secret_hash, label) VALUES ($1, $2, 'initial')`, id, secretHash); err != nil {
			return App{}, err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO app_scope (app_id, scope_name) SELECT $1::uuid, name FROM scope
		 WHERE name = ANY($2) AND (app_id IS NULL OR app_id = $1::uuid)`, id, strArray(scopes)); err != nil {
		return App{}, err
	}
	if err := linkAppGroups(tx, id, a.GroupIDs); err != nil {
		return App{}, err
	}
	if err := tx.Commit(); err != nil {
		return App{}, err
	}
	return GetApp(id)
}

func RemoveApp(id string) error {
	_, err := GetDatabaseConnection().Exec(`DELETE FROM app WHERE id = $1`, id)
	return err
}

func GetApp(id string) (App, error) {
	if !IsUUID(id) {
		return App{}, sql.ErrNoRows
	}
	return scanApp(GetDatabaseConnection().QueryRow(`SELECT `+appColumns+` FROM app WHERE id = $1`, id))
}

func GetAppByClientID(clientID string) (App, error) {
	if !IsUUID(clientID) {
		return App{}, sql.ErrNoRows
	}
	return scanApp(GetDatabaseConnection().QueryRow(`SELECT `+appColumns+` FROM app WHERE client_id = $1`, clientID))
}

// GetAppByClientIDAndSecret authenticates a confidential client in ONE query: it returns the app only if it
// is enabled and secretHash matches one of its active secrets.
func GetAppByClientIDAndSecret(clientID, secretHash string) (App, error) {
	if !IsUUID(clientID) {
		return App{}, sql.ErrNoRows
	}
	return scanApp(GetDatabaseConnection().QueryRow(
		`SELECT `+appColumns+` FROM app
		 WHERE client_id = $1 AND enabled
		   AND EXISTS (SELECT 1 FROM app_secret s WHERE s.app_id = app.id AND s.secret_hash = $2
		               AND s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > now()))`,
		clientID, secretHash))
}

func GetApps() ([]App, error) {
	rows, err := GetDatabaseConnection().Query(`SELECT ` + appColumns + ` FROM app ORDER BY pretty_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []App{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// GetScopes returns scope details (for the consent screen).
func GetScopes(names []string) ([]Scope, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT name, description, claims FROM scope WHERE name = ANY($1) ORDER BY name`, strArray(names))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scope
	for rows.Next() {
		var s Scope
		if err := rows.Scan(&s.Name, &s.Description, scanArray(&s.Claims)); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetScopeClaims returns the claim names released by the given scopes.
func GetScopeClaims(scopes []string) ([]string, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT DISTINCT c FROM scope, unnest(claims) AS c WHERE name = ANY($1)`, strArray(scopes))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
