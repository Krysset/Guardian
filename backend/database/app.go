package database

import (
	"database/sql"
	"log"
	"regexp"

	"github.com/lib/pq"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID guards queries against invalid input (Postgres errors on malformed uuid literals).
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

// appColumns includes the allowed scopes, so one query loads a complete App.
const appColumns = `id, name, pretty_name, description, COALESCE(logo_url, ''), COALESCE(homepage_url, ''),
	client_id, client_type, token_endpoint_auth_method, grant_types, redirect_uris, post_logout_redirect_uris,
	COALESCE(backchannel_logout_uri, ''), require_pkce, is_first_party, access_token_ttl_seconds, refresh_token_ttl_seconds, enabled,
	ARRAY(SELECT scope_name FROM app_scope WHERE app_scope.app_id = app.id ORDER BY scope_name)`

func scanApp(s scanner) (App, error) {
	var a App
	err := s.Scan(&a.ID, &a.Name, &a.PrettyName, &a.Description, &a.LogoURL, &a.HomepageURL,
		&a.ClientID, &a.ClientType, &a.TokenEndpointAuthMethod,
		pq.Array(&a.GrantTypes), pq.Array(&a.RedirectURIs), pq.Array(&a.PostLogoutRedirectURIs),
		&a.BackchannelLogoutURI, &a.RequirePKCE, &a.IsFirstParty, &a.AccessTokenTTL, &a.RefreshTokenTTL, &a.Enabled,
		pq.Array(&a.Scopes))
	return a, err
}

// AddApp creates an app, its first secret (if secretHash != "") and its allowed scopes.
func AddApp(a App, scopes []string, secretHash string) (App, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return App{}, err
	}
	defer tx.Rollback()

	authMethod := "client_secret_basic"
	if a.ClientType == "public" {
		authMethod = "none"
	}
	var id string
	err = tx.QueryRow(
		`INSERT INTO app (name, pretty_name, description, logo_url, homepage_url, client_type, token_endpoint_auth_method,
			redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, is_first_party, access_token_ttl_seconds)
		 VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7, $8, $9, NULLIF($10, ''), $11, COALESCE(NULLIF($12, 0), 900))
		 RETURNING id`,
		a.Name, a.PrettyName, a.Description, a.LogoURL, a.HomepageURL, a.ClientType, authMethod,
		pq.Array(a.RedirectURIs), pq.Array(a.PostLogoutRedirectURIs), a.BackchannelLogoutURI, a.IsFirstParty,
		a.AccessTokenTTL).Scan(&id)
	if err != nil {
		log.Println("Failed to create app:", a.Name, err)
		return App{}, err
	}
	if secretHash != "" {
		if _, err := tx.Exec(`INSERT INTO app_secret (app_id, secret_hash, label) VALUES ($1, $2, 'initial')`, id, secretHash); err != nil {
			return App{}, err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO app_scope (app_id, scope_name) SELECT $1::uuid, name FROM scope
		 WHERE name = ANY($2) AND (app_id IS NULL OR app_id = $1::uuid)`, id, pq.Array(scopes)); err != nil {
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
		`SELECT name, description, claims FROM scope WHERE name = ANY($1) ORDER BY name`, pq.Array(names))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scope
	for rows.Next() {
		var s Scope
		if err := rows.Scan(&s.Name, &s.Description, pq.Array(&s.Claims)); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetScopeClaims returns the claim names released by the given scopes.
func GetScopeClaims(scopes []string) ([]string, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT DISTINCT c FROM scope, unnest(claims) AS c WHERE name = ANY($1)`, pq.Array(scopes))
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
