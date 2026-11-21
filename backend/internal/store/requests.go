package store

import (
	"database/sql"
	"errors"
	"time"
)

// Requests to join a group (A33). Only requestable groups can be asked for. A group's owners decide, or
// Guardian admins when the group has no owner group; an approval adds the membership in the same
// transaction.

// GroupRequest is one request, as its requester or a decider sees it.
type GroupRequest struct {
	ID          string     `json:"id"`
	GroupID     string     `json:"group_id"`
	GroupName   string     `json:"group_name"`
	AccountID   string     `json:"account_id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name,omitempty"`
	Message     string     `json:"message,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	Decision    string     `json:"decision,omitempty"` // approved, denied or withdrawn; "" while open
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

// RequestableGroup is a group that may be asked for, as someone outside it sees it.
type RequestableGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Requested   bool   `json:"requested"` // the account has an open request for it
}

var (
	// ErrNotRequestable: the group cannot be asked for (not requestable, or the account is in it already).
	ErrNotRequestable = errors.New("this group cannot be requested")
	// ErrAlreadyRequested: the account already has an open request for the group.
	ErrAlreadyRequested = errors.New("there is already an open request for this group")
	// ErrRequestNotOpen: the request was decided or withdrawn already, or does not exist.
	ErrRequestNotOpen = errors.New("the request is not open")
)

const requestColumns = `q.id, q.group_id, g.display_name, q.account_id, a.username, COALESCE(a.display_name, ''),
	q.message, q.created_at, COALESCE(q.decision, ''), q.decided_at`

func queryRequests(query string, args ...any) ([]GroupRequest, error) {
	rows, err := GetDatabaseConnection().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupRequest{}
	for rows.Next() {
		var q GroupRequest
		var decided sql.NullTime
		if err := rows.Scan(&q.ID, &q.GroupID, &q.GroupName, &q.AccountID, &q.Username, &q.DisplayName,
			&q.Message, &q.CreatedAt, &q.Decision, &decided); err != nil {
			return nil, err
		}
		if decided.Valid {
			t := decided.Time.UTC()
			q.DecidedAt = &t
		}
		q.CreatedAt = q.CreatedAt.UTC()
		out = append(out, q)
	}
	return out, rows.Err()
}

// RequestableGroups lists the groups the account may ask to join: requestable, and not already its own. With
// appID, only the groups linked to that app.
func RequestableGroups(accountID, appID string) ([]RequestableGroup, error) {
	rows, err := GetDatabaseConnection().Query(
		`SELECT g.id, g.display_name, g.description,
		        EXISTS (SELECT 1 FROM group_request q WHERE q.group_id = g.id AND q.account_id = $1 AND q.decision IS NULL)
		 FROM user_group g
		 WHERE g.requestable
		   AND NOT EXISTS (SELECT 1 FROM group_member m WHERE m.group_id = g.id AND m.account_id = $1 AND `+activeMember+`)
		   AND ($2 = '' OR EXISTS (SELECT 1 FROM app_group ag WHERE ag.group_id = g.id AND ag.app_id::text = $2))
		 ORDER BY lower(g.display_name), g.key`, accountID, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RequestableGroup{}
	for rows.Next() {
		var g RequestableGroup
		if err := rows.Scan(&g.ID, &g.DisplayName, &g.Description, &g.Requested); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RequestGroup records the account's request to join the group.
func RequestGroup(accountID, groupID, message string) (GroupRequest, error) {
	if !IsUUID(groupID) {
		return GroupRequest{}, ErrNotRequestable
	}
	var id string
	err := GetDatabaseConnection().QueryRow(
		`INSERT INTO group_request (group_id, account_id, message)
		 SELECT g.id, $2, $3 FROM user_group g
		 WHERE g.id = $1 AND g.requestable
		   AND NOT EXISTS (SELECT 1 FROM group_member m WHERE m.group_id = g.id AND m.account_id = $2 AND `+activeMember+`)
		 RETURNING id`, groupID, accountID, message).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return GroupRequest{}, ErrNotRequestable
	case IsUniqueViolation(err):
		return GroupRequest{}, ErrAlreadyRequested
	case err != nil:
		return GroupRequest{}, err
	}
	return GetGroupRequest(id)
}

// GetGroupRequest returns one request.
func GetGroupRequest(id string) (GroupRequest, error) {
	if !IsUUID(id) {
		return GroupRequest{}, ErrRequestNotOpen
	}
	qs, err := queryRequests(`SELECT `+requestColumns+` FROM group_request q
		JOIN user_group g ON g.id = q.group_id JOIN account a ON a.id = q.account_id WHERE q.id = $1`, id)
	if err != nil {
		return GroupRequest{}, err
	}
	if len(qs) == 0 {
		return GroupRequest{}, ErrRequestNotOpen
	}
	return qs[0], nil
}

// MyGroupRequests lists the account's requests: open ones, and those decided in the last 30 days.
func MyGroupRequests(accountID string) ([]GroupRequest, error) {
	return queryRequests(`SELECT `+requestColumns+` FROM group_request q
		JOIN user_group g ON g.id = q.group_id JOIN account a ON a.id = q.account_id
		WHERE q.account_id = $1 ORDER BY q.created_at DESC`, accountID)
}

// OpenGroupRequests lists the open requests for a group, oldest first.
func OpenGroupRequests(groupID string) ([]GroupRequest, error) {
	return queryRequests(`SELECT `+requestColumns+` FROM group_request q
		JOIN user_group g ON g.id = q.group_id JOIN account a ON a.id = q.account_id
		WHERE q.group_id = $1 AND q.decision IS NULL AND a.deleted_at IS NULL ORDER BY q.created_at`, groupID)
}

// WithdrawGroupRequest withdraws the account's own open request.
func WithdrawGroupRequest(accountID, requestID string) (GroupRequest, error) {
	if !IsUUID(requestID) {
		return GroupRequest{}, ErrRequestNotOpen
	}
	res, err := GetDatabaseConnection().Exec(`UPDATE group_request SET decision = 'withdrawn', decided_at = now()
		WHERE id = $1 AND account_id = $2 AND decision IS NULL`, requestID, accountID)
	if err != nil {
		return GroupRequest{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return GroupRequest{}, ErrRequestNotOpen
	}
	return GetGroupRequest(requestID)
}

// DecideGroupRequest approves or denies an open request of the group. An approval adds the membership
// (until expiresAt, if given) in the same transaction; a membership that already exists is kept as it is.
func DecideGroupRequest(groupID, requestID, by string, approve bool, expiresAt *time.Time) (GroupRequest, error) {
	if !IsUUID(groupID) || !IsUUID(requestID) {
		return GroupRequest{}, ErrRequestNotOpen
	}
	tx, err := GetDatabaseConnection().Begin()
	if err != nil {
		return GroupRequest{}, err
	}
	defer tx.Rollback()
	decision := "denied"
	if approve {
		decision = "approved"
	}
	var accountID string
	err = tx.QueryRow(`UPDATE group_request SET decision = $3, decided_by = $4, decided_at = now()
		WHERE id = $1 AND group_id = $2 AND decision IS NULL RETURNING account_id`,
		requestID, groupID, decision, by).Scan(&accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return GroupRequest{}, ErrRequestNotOpen
	}
	if err != nil {
		return GroupRequest{}, err
	}
	if approve {
		if _, err := tx.Exec(`INSERT INTO group_member (group_id, account_id, added_by, expires_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (group_id, account_id) DO UPDATE SET expires_at = EXCLUDED.expires_at, added_by = EXCLUDED.added_by,
			    added_at = now()
			WHERE group_member.expires_at IS NOT NULL AND group_member.expires_at <= now()`,
			groupID, accountID, by, expiresAt); err != nil {
			return GroupRequest{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return GroupRequest{}, err
	}
	return GetGroupRequest(requestID)
}

// GroupDeciders are the accounts that decide requests for the group, with a confirmed email address: the
// owner group's active members, or Guardian admins when the group has no owner group.
func GroupDeciders(groupID string) ([]Account, error) {
	rows, err := GetDatabaseConnection().Query(`SELECT `+accountColumns+` FROM account a
		WHERE a.status = 'active' AND a.deleted_at IS NULL AND a.email IS NOT NULL AND a.email_verified_at IS NOT NULL
		  AND EXISTS (SELECT 1 FROM group_member m JOIN user_group g ON g.id = $1
		      WHERE m.account_id = a.id AND `+activeMember+`
		        AND m.group_id = COALESCE(g.owner_group_id, (SELECT id FROM user_group WHERE key = $2)))`, groupID, AdminGroupKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		acct, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, acct)
	}
	return out, rows.Err()
}

// pruneGroupRequests removes decided requests older than 30 days.
const pruneGroupRequests = `DELETE FROM group_request WHERE decided_at < now() - interval '30 days'`
