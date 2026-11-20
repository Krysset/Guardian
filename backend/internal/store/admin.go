package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// revokeAccountSessions ends every live session of an account except keepSessionID (may be ""), and
// their refresh tokens. It returns the back-channel logouts to send, collected before the sessions end.
func revokeAccountSessions(tx *sql.Tx, accountID, keepSessionID string) ([]LogoutNotice, error) {
	keep := keepSessionID
	if keep == "" {
		keep = "00000000-0000-0000-0000-000000000000"
	}
	notices, err := logoutNotices(tx,
		`SELECT a.client_id, a.backchannel_logout_uri, s.account_id, s.id
		 FROM session s JOIN session_app sa ON sa.session_id = s.id JOIN app a ON a.id = sa.app_id
		 WHERE s.account_id = $1 AND s.id <> $2 AND s.revoked_at IS NULL AND s.expires_at > now()
		   AND a.backchannel_logout_uri IS NOT NULL`, accountID, keep)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(
		`UPDATE refresh_token SET revoked_at = now()
		 WHERE account_id = $1 AND session_id <> $2 AND revoked_at IS NULL`, accountID, keep); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(
		`UPDATE session SET revoked_at = now() WHERE account_id = $1 AND id <> $2 AND revoked_at IS NULL`, accountID, keep); err != nil {
		return nil, err
	}
	return notices, nil
}

// RevokeOtherSessions ends every session of the account except keepSessionID, for example after the
// user changed their password.
func RevokeOtherSessions(accountID, keepSessionID string) ([]LogoutNotice, error) {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	notices, err := revokeAccountSessions(tx, accountID, keepSessionID)
	if err != nil {
		return nil, err
	}
	return notices, tx.Commit()
}

// AccountUpdate lists the account fields to change; nil fields are left alone. An empty string clears an
// optional field.
type AccountUpdate struct {
	Username, DisplayName, GivenName, FamilyName, PictureURL, Locale, Zoneinfo *string
	// Email is only for administrators: an address an administrator sets counts as verified. Users set
	// their own address through email verification (release 0.3).
	Email *string
	// Status is "active" or "disabled". Disabling ends every session, and is refused for the last
	// administrator (ErrLastAdmin).
	Status *string
}

// UpdateAccount applies u in one transaction. It returns the updated account and, when the account was
// disabled, the back-channel logouts to send. A missing account is sql.ErrNoRows; a taken username or
// email is a unique violation.
func UpdateAccount(id string, u AccountUpdate) (Account, []LogoutNotice, error) {
	if !IsUUID(id) {
		return Account{}, nil, sql.ErrNoRows
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return Account{}, nil, err
	}
	defer tx.Rollback()

	disabling := u.Status != nil && *u.Status == "disabled"
	if disabling {
		// Lock first, so a concurrent change cannot remove the last administrator in between.
		adminGroupID, err := lockAdminGroup(tx)
		if err != nil {
			return Account{}, nil, err
		}
		var isAdmin bool
		if err := tx.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM group_member m WHERE m.group_id = $1 AND m.account_id = $2 AND `+activeMember+`)`,
			adminGroupID, id).Scan(&isAdmin); err != nil {
			return Account{}, nil, err
		}
		if isAdmin {
			if n, err := otherPermanentAdmins(tx, adminGroupID, id); err != nil {
				return Account{}, nil, err
			} else if n == 0 {
				return Account{}, nil, ErrLastAdmin
			}
		}
	}

	sets := []string{"updated_at = now()"}
	args := []any{id}
	set := func(column string, v *string, nullable bool) {
		if v == nil {
			return
		}
		args = append(args, *v)
		p := "$" + strconv.Itoa(len(args))
		if nullable {
			p = "NULLIF(" + p + ", '')"
		}
		sets = append(sets, column+" = "+p)
	}
	set("username", u.Username, false)
	set("display_name", u.DisplayName, true)
	set("given_name", u.GivenName, true)
	set("family_name", u.FamilyName, true)
	set("picture_url", u.PictureURL, true)
	set("locale", u.Locale, true)
	set("zoneinfo", u.Zoneinfo, true)
	if u.Email != nil {
		set("email", u.Email, true)
		sets = append(sets, fmt.Sprintf("email_verified_at = CASE WHEN $%d = '' THEN NULL ELSE now() END", len(args)))
	}
	set("status", u.Status, false)

	res, err := tx.Exec(`UPDATE account SET `+strings.Join(sets, ", ")+` WHERE id = $1 AND deleted_at IS NULL`, args...)
	if err != nil {
		return Account{}, nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Account{}, nil, sql.ErrNoRows
	}
	var notices []LogoutNotice
	if disabling {
		if notices, err = revokeAccountSessions(tx, id, ""); err != nil {
			return Account{}, nil, err
		}
	}
	acct, err := scanAccount(tx.QueryRow(`SELECT `+accountColumns+` FROM account WHERE id = $1`, id))
	if err != nil {
		return Account{}, nil, err
	}
	return acct, notices, tx.Commit()
}

// CreateAccountWithEmail creates an account for an administrator. A non-empty email counts as verified. The
// password is the administrator's choice, so the user must choose their own at the first sign-in (A3, U3).
func CreateAccountWithEmail(username, passwordHash, email string) (Account, error) {
	var id string
	err := GetDatabaseConnection().QueryRow(
		`INSERT INTO account (username, password_hash, email, email_verified_at, must_change_password)
		 VALUES ($1, $2, NULLIF($3, ''), CASE WHEN $3 = '' THEN NULL ELSE now() END, true) RETURNING id`,
		username, passwordHash, email).Scan(&id)
	if err != nil {
		return Account{}, err
	}
	return GetAccount(id)
}

// SetPasswordByAdmin replaces an account's password, makes the user choose a new one at their next
// sign-in, and ends all of the account's sessions. It returns the back-channel logouts to send.
func SetPasswordByAdmin(id, hash string) ([]LogoutNotice, error) {
	if !IsUUID(id) {
		return nil, sql.ErrNoRows
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(
		`UPDATE account SET password_hash = $2, must_change_password = TRUE, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NULL`, id, hash)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, sql.ErrNoRows
	}
	notices, err := revokeAccountSessions(tx, id, "")
	if err != nil {
		return nil, err
	}
	return notices, tx.Commit()
}

// AccountFilter selects accounts for ListAccounts.
type AccountFilter struct {
	Query  string // matched case-insensitively against username, display name and email
	Status string // "active", "disabled", "must_change_password" (active, with a temporary password), or "" for any
	After  string // cursor: list accounts whose lower-case username sorts after this
	Limit  int
}

// accountWhere is the WHERE clause (and its arguments) for the filter's query and status, without the cursor.
func accountWhere(f AccountFilter, args []any) ([]string, []any) {
	where := []string{"deleted_at IS NULL"}
	if f.Query != "" {
		args = append(args, "%"+likeEscape(strings.ToLower(f.Query))+"%")
		p := "$" + strconv.Itoa(len(args))
		where = append(where, "(lower(username) LIKE "+p+" OR lower(COALESCE(display_name, '')) LIKE "+p+
			" OR lower(COALESCE(email, '')) LIKE "+p+")")
	}
	switch f.Status {
	case "":
	case "must_change_password":
		where = append(where, "status = 'active' AND must_change_password")
	default:
		args = append(args, f.Status)
		where = append(where, "status = $"+strconv.Itoa(len(args)))
	}
	return where, args
}

// CountAccounts returns how many accounts match the filter's query and status, on every page.
func CountAccounts(f AccountFilter) (int, error) {
	where, args := accountWhere(f, nil)
	var n int
	err := GetDatabaseConnection().QueryRow(`SELECT count(*) FROM account WHERE `+strings.Join(where, " AND "), args...).Scan(&n)
	return n, err
}

// ListAccounts returns accounts ordered by lower-case username (byte order), at most f.Limit of them.
func ListAccounts(f AccountFilter) ([]Account, error) {
	// Byte order ("C"), so paging does not depend on the database's locale.
	where, args := accountWhere(f, []any{strings.ToLower(f.After)})
	where = append(where, `lower(username) COLLATE "C" > $1`)
	args = append(args, f.Limit)
	rows, err := GetDatabaseConnection().Query(
		`SELECT `+accountColumns+` FROM account WHERE `+strings.Join(where, " AND ")+
			` ORDER BY lower(username) COLLATE "C" LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// likeEscape makes % and _ in user input match themselves in a LIKE pattern (the default escape is \).
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Membership is one group an account is in.
type Membership struct {
	GroupID     string     `json:"group_id"`
	Key         string     `json:"key"`
	DisplayName string     `json:"display_name"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// AccountGroups lists the groups an account is an active member of, by key.
func AccountGroups(accountID string) ([]Membership, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT g.id, g.key, g.display_name, m.expires_at FROM group_member m JOIN user_group g ON g.id = m.group_id
		 WHERE m.account_id = $1 AND `+activeMember+` ORDER BY g.key`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Membership{}
	for rows.Next() {
		var m Membership
		var expires sql.NullTime
		if err := rows.Scan(&m.GroupID, &m.Key, &m.DisplayName, &expires); err != nil {
			return nil, err
		}
		if expires.Valid {
			t := expires.Time.UTC()
			m.ExpiresAt = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AppUpdate lists the app settings to change; nil fields are left alone. The name, client id and client
// type never change, and access (rule, groups, machine API) has its own call.
type AppUpdate struct {
	PrettyName, Description, LogoURL, HomepageURL, BackchannelLogoutURI *string
	RedirectURIs, PostLogoutRedirectURIs, Scopes                        *[]string
	IsFirstParty, Enabled, RequireMFA                                   *bool
	AccessTokenTTL                                                      *int
}

// UpdateApp applies u in one transaction. A missing app is sql.ErrNoRows.
func UpdateApp(id string, u AppUpdate) (App, error) {
	if !IsUUID(id) {
		return App{}, sql.ErrNoRows
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return App{}, err
	}
	defer tx.Rollback()

	sets := []string{"id = id"} // app has no updated_at column; this keeps the statement valid
	args := []any{id}
	add := func(column string, v any, wrap string) {
		args = append(args, v)
		p := "$" + strconv.Itoa(len(args))
		if wrap != "" {
			p = fmt.Sprintf(wrap, p)
		}
		sets = append(sets, column+" = "+p)
	}
	if u.PrettyName != nil {
		add("pretty_name", *u.PrettyName, "")
	}
	if u.Description != nil {
		add("description", *u.Description, "")
	}
	if u.LogoURL != nil {
		add("logo_url", *u.LogoURL, "NULLIF(%s, '')")
	}
	if u.HomepageURL != nil {
		add("homepage_url", *u.HomepageURL, "NULLIF(%s, '')")
	}
	if u.BackchannelLogoutURI != nil {
		add("backchannel_logout_uri", *u.BackchannelLogoutURI, "NULLIF(%s, '')")
	}
	if u.RedirectURIs != nil {
		add("redirect_uris", strArray(*u.RedirectURIs), "")
	}
	if u.PostLogoutRedirectURIs != nil {
		add("post_logout_redirect_uris", strArray(*u.PostLogoutRedirectURIs), "")
	}
	if u.IsFirstParty != nil {
		add("is_first_party", *u.IsFirstParty, "")
	}
	if u.RequireMFA != nil {
		add("require_mfa", *u.RequireMFA, "")
	}
	if u.Enabled != nil {
		add("enabled", *u.Enabled, "")
	}
	if u.AccessTokenTTL != nil {
		add("access_token_ttl_seconds", *u.AccessTokenTTL, "")
	}
	res, err := tx.Exec(`UPDATE app SET `+strings.Join(sets, ", ")+` WHERE id = $1`, args...)
	if err != nil {
		return App{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return App{}, sql.ErrNoRows
	}
	if u.Scopes != nil {
		if _, err := tx.Exec(`DELETE FROM app_scope WHERE app_id = $1`, id); err != nil {
			return App{}, err
		}
		if _, err := tx.Exec(
			`INSERT INTO app_scope (app_id, scope_name) SELECT $1::uuid, name FROM scope
			 WHERE name = ANY($2) AND (app_id IS NULL OR app_id = $1::uuid)`, id, strArray(*u.Scopes)); err != nil {
			return App{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return App{}, err
	}
	return GetApp(id)
}

// RotateAppSecret adds a new secret for an app. The app's other secrets stop working after grace (at
// once when grace is 0), so the new secret can be rolled out before the old one ends.
func RotateAppSecret(appID, secretHash string, grace time.Duration) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE app_secret SET expires_at = now() + make_interval(secs => $2)
		 WHERE app_id = $1 AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now() + make_interval(secs => $2))`,
		appID, grace.Seconds()); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO app_secret (app_id, secret_hash, label) VALUES ($1, $2, 'rotated')`, appID, secretHash); err != nil {
		return err
	}
	return tx.Commit()
}

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID             int64          `json:"id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	EventType      string         `json:"event_type"`
	ActorAccountID string         `json:"actor_account_id,omitempty"`
	ActorAppID     string         `json:"actor_app_id,omitempty"`
	ActorUsername  string         `json:"actor_username,omitempty"` // "" once the account is erased
	IPAddress      string         `json:"ip_address,omitempty"`
	Metadata       map[string]any `json:"metadata"`
}

// AuditFilter selects audit entries for ListAudit.
type AuditFilter struct {
	EventType string // exact event type, or "" for all
	AccountID string // entries whose actor is this account, or "" for all
	About     string // entries this account did or that were done to it (metadata "account" or "target"), or "" for all
	Before    int64  // cursor: entries with a smaller id; 0 for the newest
	Limit     int
}

// ListAudit returns audit entries, newest first.
func ListAudit(f AuditFilter) ([]AuditEntry, error) {
	where := []string{"TRUE"}
	var args []any
	arg := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }
	if f.Before > 0 {
		where = append(where, "l.id < "+arg(f.Before))
	}
	if f.EventType != "" {
		where = append(where, "l.event_type = "+arg(f.EventType))
	}
	if f.AccountID != "" {
		where = append(where, "l.actor_account_id = "+arg(f.AccountID)+"::uuid")
	}
	if f.About != "" {
		p := arg(f.About)
		// One parameter used as text twice, so Postgres infers one type for it.
		where = append(where, "(l.actor_account_id = "+p+"::text::uuid OR l.metadata->>'account' = "+p+"::text OR l.metadata->>'target' = "+p+"::text)")
	}
	rows, err := GetDatabaseConnection().Query(
		`SELECT l.id, l.occurred_at, l.event_type, COALESCE(l.actor_account_id::text, ''), COALESCE(l.actor_app_id::text, ''),
		        COALESCE(host(l.ip_address), ''), l.metadata, COALESCE(a.username, '')
		 FROM audit_log l LEFT JOIN account a ON a.id = l.actor_account_id
		 WHERE `+strings.Join(where, " AND ")+` ORDER BY l.id DESC LIMIT `+arg(f.Limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var meta []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.EventType, &e.ActorAccountID, &e.ActorAppID, &e.IPAddress, &meta, &e.ActorUsername); err != nil {
			return nil, err
		}
		e.OccurredAt = e.OccurredAt.UTC()
		if err := json.Unmarshal(meta, &e.Metadata); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
