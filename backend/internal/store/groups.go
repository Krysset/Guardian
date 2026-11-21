package store

import (
	"database/sql"
	"errors"
	"time"
)

// Groups are how Guardian says who may do what. Guardian only knows membership; each app decides what
// a group means. Nothing here is cached, so a committed change is seen by the next check on every replica.

// AdminGroupKey is the built-in group whose members may do everything in Guardian.
const AdminGroupKey = "guardian-admins"

var (
	ErrGroupNotFound = errors.New("group not found")
	ErrSystemGroup   = errors.New("built-in groups cannot be changed or deleted")
	ErrInvalidOwner  = errors.New("the owner must be another existing group")
	// ErrGroupBound: the group is bound to another app (or to an app that was deleted), so it cannot be
	// linked to this one.
	ErrGroupBound = errors.New("the group is bound to another app")
	// ErrAlreadyBound: a binding is permanent and cannot be moved.
	ErrAlreadyBound = errors.New("the group is already bound to an app; a binding cannot be changed")
	// ErrLinkedElsewhere: a group can only be bound to an app if it is linked to no other app.
	ErrLinkedElsewhere = errors.New("the group is linked to another app")
	// ErrAppNotFound: the app to bind a group to does not exist.
	ErrAppNotFound = errors.New("app not found")
	// ErrLastAdmin protects against locking everyone out: one active account must always be an
	// administrator through a membership that does not expire.
	ErrLastAdmin = errors.New("Guardian must keep at least one active administrator whose membership does not expire")
)

type Group struct {
	ID           string    `json:"id"`
	Key          string    `json:"key"`
	DisplayName  string    `json:"display_name"`
	Description  string    `json:"description"`
	IsSystem     bool      `json:"is_system"`
	OwnerGroupID string    `json:"owner_group_id,omitempty"`
	MemberCount  int       `json:"member_count"` // memberships that have not expired
	AppIDs       []string  `json:"app_ids"`      // apps this group is linked to
	CreatedAt    time.Time `json:"created_at"`

	// SingleApp groups are bound to one app for good (BoundAppID), and can be linked to no other. A
	// single-app group without BoundAppID lost its app: BoundAppDeletedAt says when.
	SingleApp         bool       `json:"single_app"`
	BoundAppID        string     `json:"bound_app_id,omitempty"`
	BoundAt           *time.Time `json:"bound_at,omitempty"`
	BoundAppDeletedAt *time.Time `json:"bound_app_deleted_at,omitempty"`

	Hidden        bool `json:"hidden"`          // left out of its members' own group list
	Requestable   bool `json:"requestable"`     // people may ask to join
	JoinByDefault bool `json:"join_by_default"` // every new account joins
	OpenRequests  int  `json:"open_requests"`   // requests to join waiting for a decision
}

type GroupMember struct {
	AccountID   string     `json:"account_id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name,omitempty"`
	AddedBy     string     `json:"added_by,omitempty"`
	AddedAt     time.Time  `json:"added_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// activeMember is the one definition of "this membership counts". Use it with the alias m.
const activeMember = `(m.expires_at IS NULL OR m.expires_at > now())`

const groupColumns = `g.id, g.key, g.display_name, g.description, g.is_system, COALESCE(g.owner_group_id::text, ''),
	(SELECT count(*) FROM group_member m WHERE m.group_id = g.id AND ` + activeMember + `),
	ARRAY(SELECT ag.app_id::text FROM app_group ag WHERE ag.group_id = g.id ORDER BY 1), g.created_at,
	COALESCE(g.bound_app_id::text, ''), g.bound_at, g.bound_app_deleted_at, g.hidden, g.requestable, g.join_by_default,
	(SELECT count(*) FROM group_request q WHERE q.group_id = g.id AND q.decision IS NULL)`

func scanGroup(s scanner) (Group, error) {
	var g Group
	var boundAt, deletedAt sql.NullTime
	err := s.Scan(&g.ID, &g.Key, &g.DisplayName, &g.Description, &g.IsSystem, &g.OwnerGroupID, &g.MemberCount,
		scanArray(&g.AppIDs), &g.CreatedAt, &g.BoundAppID, &boundAt, &deletedAt, &g.Hidden, &g.Requestable, &g.JoinByDefault,
		&g.OpenRequests)
	g.CreatedAt = g.CreatedAt.UTC()
	if boundAt.Valid {
		t := boundAt.Time.UTC()
		g.SingleApp, g.BoundAt = true, &t
	}
	if deletedAt.Valid {
		t := deletedAt.Time.UTC()
		g.BoundAppDeletedAt = &t
	}
	return g, err
}

func queryGroups(query string, args ...any) ([]Group, error) {
	rows, err := GetDatabaseConnection().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func ListGroups() ([]Group, error) {
	return queryGroups(`SELECT ` + groupColumns + ` FROM user_group g ORDER BY g.key`)
}

// ListGroupsOwnedBy returns the groups whose members the account may manage as an owner: those whose
// owner group the account is an active member of.
func ListGroupsOwnedBy(accountID string) ([]Group, error) {
	return queryGroups(`SELECT `+groupColumns+` FROM user_group g
		 WHERE NOT g.is_system AND EXISTS (SELECT 1 FROM group_member m
		        WHERE m.group_id = g.owner_group_id AND m.account_id = $1 AND `+activeMember+`)
		 ORDER BY g.key`, accountID)
}

func GetGroup(id string) (Group, error) {
	if !IsUUID(id) {
		return Group{}, ErrGroupNotFound
	}
	g, err := scanGroup(GetDatabaseConnection().QueryRow(`SELECT `+groupColumns+` FROM user_group g WHERE g.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	return g, err
}

// CreateGroup makes a new, empty group. The key can never be changed afterwards, because apps match on it.
// ownerGroupID may be "". With boundAppID the group is a single-app group: bound to that app for good
// and linked to it.
func CreateGroup(key, displayName, description, ownerGroupID, boundAppID string) (string, error) {
	if ownerGroupID != "" {
		if _, err := GetGroup(ownerGroupID); err != nil {
			return "", ErrInvalidOwner
		}
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRow(
		`INSERT INTO user_group (key, display_name, description, owner_group_id)
		 VALUES ($1, $2, $3, NULLIF($4, '')::uuid) RETURNING id`,
		key, displayName, description, ownerGroupID).Scan(&id)
	if err != nil {
		return "", err
	}
	if boundAppID != "" {
		if err := bindGroup(tx, id, boundAppID); err != nil {
			return "", err
		}
	}
	return id, tx.Commit()
}

// CopyGroup makes a new group from another one: the given key, names and owner group, and the source's
// current members with their expiry dates (memberships that have already expired are left behind). The copy
// is linked to no app and bound to none; from then on the two groups are unrelated. by is who copied.
func CopyGroup(sourceID, key, displayName, description, ownerGroupID, by string) (id string, members int, err error) {
	if _, err := GetGroup(sourceID); err != nil {
		return "", 0, err
	}
	if ownerGroupID != "" {
		if _, err := GetGroup(ownerGroupID); err != nil {
			return "", 0, ErrInvalidOwner
		}
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	if err := tx.QueryRow(
		`INSERT INTO user_group (key, display_name, description, owner_group_id)
		 VALUES ($1, $2, $3, NULLIF($4, '')::uuid) RETURNING id`,
		key, displayName, description, ownerGroupID).Scan(&id); err != nil {
		return "", 0, err
	}
	res, err := tx.Exec(
		`INSERT INTO group_member (group_id, account_id, added_by, expires_at)
		 SELECT $1, m.account_id, NULLIF($3, '')::uuid, m.expires_at FROM group_member m
		 WHERE m.group_id = $2 AND `+activeMember, id, sourceID, by)
	if err != nil {
		return "", 0, err
	}
	n, _ := res.RowsAffected()
	return id, int(n), tx.Commit()
}

// BindGroup makes an existing group a single-app group: bound to the app for good, and linked to it. It is
// refused for built-in groups, for groups that are already bound (a binding never moves) and for groups
// linked to any other app.
func BindGroup(groupID, appID string) error {
	if !IsUUID(groupID) {
		return ErrGroupNotFound
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := bindGroup(tx, groupID, appID); err != nil {
		return err
	}
	return tx.Commit()
}

func bindGroup(tx *sql.Tx, groupID, appID string) error {
	if !IsUUID(appID) {
		return ErrAppNotFound
	}
	// The row lock keeps a concurrent link (linkAppGroups locks the same rows) from slipping in between
	// the check and the binding.
	var isSystem, bound bool
	err := tx.QueryRow(`SELECT is_system, bound_at IS NOT NULL FROM user_group WHERE id = $1 FOR UPDATE`, groupID).
		Scan(&isSystem, &bound)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrGroupNotFound
	}
	if err != nil {
		return err
	}
	switch {
	case isSystem:
		return ErrSystemGroup
	case bound:
		return ErrAlreadyBound
	}
	var appExists, linkedElsewhere bool
	err = tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM app WHERE id = $2),
		        EXISTS (SELECT 1 FROM app_group WHERE group_id = $1 AND app_id <> $2)`, groupID, appID).
		Scan(&appExists, &linkedElsewhere)
	if err != nil {
		return err
	}
	if !appExists {
		return ErrAppNotFound
	}
	if linkedElsewhere {
		return ErrLinkedElsewhere
	}
	if _, err := tx.Exec(`UPDATE user_group SET bound_app_id = $2, bound_at = now() WHERE id = $1`, groupID, appID); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO app_group (app_id, group_id) VALUES ($2, $1) ON CONFLICT DO NOTHING`, groupID, appID)
	return err
}

// GroupUpdate lists what UpdateGroup may change. A nil field is left as it is.
type GroupUpdate struct {
	DisplayName   *string
	Description   *string
	OwnerGroupID  *string // "" removes the owner
	Hidden        *bool
	Requestable   *bool
	JoinByDefault *bool
}

// ErrHiddenRequestable: a hidden group cannot also be open to requests, which would show it to everyone.
var ErrHiddenRequestable = errors.New("a hidden group cannot be open to requests")

// UpdateGroup changes a group's display name, description or owner. Built-in groups cannot be changed.
func UpdateGroup(id string, u GroupUpdate) error {
	g, err := GetGroup(id)
	if err != nil {
		return err
	}
	if g.IsSystem {
		return ErrSystemGroup
	}
	if u.OwnerGroupID != nil && *u.OwnerGroupID != "" {
		if _, err := GetGroup(*u.OwnerGroupID); err != nil || *u.OwnerGroupID == id {
			return ErrInvalidOwner
		}
	}
	hidden, requestable := g.Hidden, g.Requestable
	if u.Hidden != nil {
		hidden = *u.Hidden
	}
	if u.Requestable != nil {
		requestable = *u.Requestable
	}
	if hidden && requestable {
		return ErrHiddenRequestable
	}
	_, err = GetDatabaseConnection().Exec(
		`UPDATE user_group SET
			display_name    = COALESCE($2, display_name),
			description     = COALESCE($3, description),
			owner_group_id  = CASE WHEN $4::boolean THEN NULLIF($5, '')::uuid ELSE owner_group_id END,
			hidden          = COALESCE($6, hidden),
			requestable     = COALESCE($7, requestable),
			join_by_default = COALESCE($8, join_by_default)
		 WHERE id = $1 AND NOT is_system`,
		id, u.DisplayName, u.Description, u.OwnerGroupID != nil, deref(u.OwnerGroupID), u.Hidden, u.Requestable, u.JoinByDefault)
	if err == nil && u.Requestable != nil && !*u.Requestable {
		// Closing a group to requests withdraws the open ones.
		_, err = GetDatabaseConnection().Exec(`UPDATE group_request SET decision = 'withdrawn', decided_at = now()
			WHERE group_id = $1 AND decision IS NULL`, id)
	}
	return err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// DeleteGroup removes a group, its memberships and its app links. Built-in groups cannot be deleted.
func DeleteGroup(id string) error {
	if !IsUUID(id) {
		return ErrGroupNotFound
	}
	var isSystem bool
	err := GetDatabaseConnection().QueryRow(
		`DELETE FROM user_group WHERE id = $1 AND NOT is_system RETURNING is_system`, id).Scan(&isSystem)
	if errors.Is(err, sql.ErrNoRows) {
		if _, getErr := GetGroup(id); getErr != nil {
			return getErr
		}
		return ErrSystemGroup
	}
	return err
}

func ListGroupMembers(groupID string) ([]GroupMember, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT m.account_id, a.username, COALESCE(a.display_name, ''), COALESCE(m.added_by::text, ''), m.added_at, m.expires_at
		 FROM group_member m JOIN account a ON a.id = m.account_id AND a.deleted_at IS NULL
		 WHERE m.group_id = $1 AND `+activeMember+` ORDER BY lower(a.username)`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupMember{}
	for rows.Next() {
		var m GroupMember
		var expires sql.NullTime
		if err := rows.Scan(&m.AccountID, &m.Username, &m.DisplayName, &m.AddedBy, &m.AddedAt, &expires); err != nil {
			return nil, err
		}
		// Times leave the API in UTC, whatever time zone the server runs in.
		m.AddedAt = m.AddedAt.UTC()
		if expires.Valid {
			utc := expires.Time.UTC()
			m.ExpiresAt = &utc
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// lockAdminGroup serialises every change that could remove the last administrator, so two such changes
// cannot each see the other's account as the one that remains. It returns the administrators group's id.
func lockAdminGroup(tx *sql.Tx) (string, error) {
	var id string
	err := tx.QueryRow(`SELECT id FROM user_group WHERE key = $1 FOR UPDATE`, AdminGroupKey).Scan(&id)
	return id, err
}

// otherPermanentAdmins counts active accounts, other than accountID, that are administrators through a
// membership without an expiry.
func otherPermanentAdmins(tx *sql.Tx, adminGroupID, accountID string) (int, error) {
	var n int
	err := tx.QueryRow(
		`SELECT count(*) FROM group_member m JOIN account a ON a.id = m.account_id
		 WHERE m.group_id = $1 AND m.account_id <> $2 AND m.expires_at IS NULL
		   AND a.status = 'active' AND a.deleted_at IS NULL`, adminGroupID, accountID).Scan(&n)
	return n, err
}

// AddGroupMember adds an account to a group, or changes the expiry of an existing membership.
// expiresAt nil means the membership does not expire.
func AddGroupMember(groupID, accountID, addedBy string, expiresAt *time.Time) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	adminGroupID, err := lockAdminGroup(tx)
	if err != nil {
		return err
	}
	// Giving the only permanent administrator an expiry date would leave nobody once it passes.
	if groupID == adminGroupID && expiresAt != nil {
		if n, err := otherPermanentAdmins(tx, adminGroupID, accountID); err != nil {
			return err
		} else if n == 0 {
			return ErrLastAdmin
		}
	}
	_, err = tx.Exec(
		`INSERT INTO group_member (group_id, account_id, added_by, expires_at)
		 VALUES ($1, $2, NULLIF($3, '')::uuid, $4)
		 ON CONFLICT (group_id, account_id)
		 DO UPDATE SET expires_at = EXCLUDED.expires_at, added_by = EXCLUDED.added_by, added_at = now()`,
		groupID, accountID, addedBy, expiresAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveGroupMember takes an account out of a group. It refuses to remove the last administrator.
func RemoveGroupMember(groupID, accountID string) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	adminGroupID, err := lockAdminGroup(tx)
	if err != nil {
		return err
	}
	if groupID == adminGroupID {
		if n, err := otherPermanentAdmins(tx, adminGroupID, accountID); err != nil {
			return err
		} else if n == 0 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.Exec(`DELETE FROM group_member WHERE group_id = $1 AND account_id = $2`, groupID, accountID); err != nil {
		return err
	}
	return tx.Commit()
}

// GroupChangeLogoutNotices returns the back-channel logouts to send after the account left the group:
// one for each live session of the account in each app that is linked to that group. Those apps drop
// what they hold for the user, who then signs in again and gets tokens without the group, or is
// refused by the app's access rule. Apps that are not linked to the group are not disturbed.
func GroupChangeLogoutNotices(accountID, groupID string) ([]LogoutNotice, error) {
	return logoutNotices(GetDatabaseConnection(),
		`SELECT a.client_id, a.backchannel_logout_uri, a.signing_alg, s.account_id, s.id
		 FROM session s
		 JOIN session_app sa ON sa.session_id = s.id
		 JOIN app a ON a.id = sa.app_id AND a.backchannel_logout_uri IS NOT NULL
		 JOIN app_group ag ON ag.app_id = a.id AND ag.group_id = $2
		 WHERE s.account_id = $1 AND s.revoked_at IS NULL AND s.expires_at > now()`, accountID, groupID)
}

// AccountInGroup reports whether the account is an active member of the group with this key.
func AccountInGroup(accountID, groupKey string) (bool, error) {
	var ok bool
	err := GetDatabaseConnection().QueryRow(
		`SELECT EXISTS (SELECT 1 FROM group_member m JOIN user_group g ON g.id = m.group_id
		   WHERE m.account_id = $1 AND g.key = $2 AND `+activeMember+`)`,
		accountID, groupKey).Scan(&ok)
	return ok, err
}

// IsAdmin reports whether the account may do everything in Guardian.
func IsAdmin(accountID string) (bool, error) {
	return AccountInGroup(accountID, AdminGroupKey)
}

// OwnsGroup reports whether the account may manage the group's members as an owner, and returns the key
// of the owner group that gives it that right. Built-in groups have no owners.
func OwnsGroup(accountID, groupID string) (ownerKey string, ok bool, err error) {
	err = GetDatabaseConnection().QueryRow(
		`SELECT o.key FROM user_group g
		 JOIN user_group o ON o.id = g.owner_group_id
		 JOIN group_member m ON m.group_id = o.id AND m.account_id = $1 AND `+activeMember+`
		 WHERE g.id = $2 AND NOT g.is_system`, accountID, groupID).Scan(&ownerKey)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return ownerKey, err == nil, err
}

// SetAppAccess sets who may sign in to an app: the access rule ("groups" or "anyone") and the complete
// set of groups linked to the app.
func SetAppAccess(appID, accessRule string, groupIDs []string) error {
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE app SET access_rule = $2 WHERE id = $1`, appID, accessRule)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if err := linkAppGroups(tx, appID, groupIDs); err != nil {
		return err
	}
	return tx.Commit()
}

// linkAppGroups replaces the app's linked groups. Unknown group ids are an error, so a typo cannot
// silently leave an app without the group that was meant to open it.
// Groups bound to another app (or to a deleted one) are refused with ErrGroupBound.
func linkAppGroups(tx *sql.Tx, appID string, groupIDs []string) error {
	// Lock the groups so that a concurrent BindGroup sees these links, or this sees its binding.
	var boundElsewhere bool
	err := tx.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM (SELECT bound_at, bound_app_id FROM user_group
		        WHERE id = ANY($2::text[]::uuid[]) FOR SHARE) g
		        WHERE g.bound_at IS NOT NULL AND g.bound_app_id IS DISTINCT FROM $1::uuid)`,
		appID, strArray(groupIDs)).Scan(&boundElsewhere)
	if err != nil {
		return err
	}
	if boundElsewhere {
		return ErrGroupBound
	}
	if _, err := tx.Exec(`DELETE FROM app_group WHERE app_id = $1`, appID); err != nil {
		return err
	}
	res, err := tx.Exec(
		`INSERT INTO app_group (app_id, group_id)
		 SELECT $1::uuid, id FROM user_group WHERE id = ANY($2::text[]::uuid[])`, appID, strArray(groupIDs))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); int(n) != len(uniqueStrings(groupIDs)) {
		return ErrGroupNotFound
	}
	return nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// AccountAppGroups returns the keys of the groups that the account is an active member of and that are
// linked to the app. These are the only groups the app is ever told about.
func AccountAppGroups(accountID, appID string) ([]string, error) {
	var keys []string
	err := GetDatabaseConnection().QueryRow(
		`SELECT ARRAY(SELECT g.key FROM group_member m
		        JOIN user_group g ON g.id = m.group_id
		        JOIN app_group ag ON ag.group_id = g.id AND ag.app_id = $2
		        WHERE m.account_id = $1 AND `+activeMember+` ORDER BY g.key)`,
		accountID, appID).Scan(scanArray(&keys))
	if keys == nil {
		keys = []string{}
	}
	return keys, err
}

// AccountMayUseApp applies the app's access rule: with "anyone" every account may sign in, with "groups"
// only active members of a group linked to the app.
func AccountMayUseApp(accountID string, app App) (bool, error) {
	if app.AccessRule == "anyone" {
		return true, nil
	}
	keys, err := AccountAppGroups(accountID, app.ID)
	return len(keys) > 0, err
}

// GroupSummary names a group without its members or settings.
type GroupSummary struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
}

// GroupSummaries names the groups with these ids, in key order. Unknown ids are left out.
func GroupSummaries(ids []string) ([]GroupSummary, error) {
	out := []GroupSummary{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := GetDatabaseConnection().Query(
		`SELECT id, key, display_name FROM user_group WHERE id::text = ANY($1) ORDER BY key`, strArray(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var g GroupSummary
		if err := rows.Scan(&g.ID, &g.Key, &g.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
