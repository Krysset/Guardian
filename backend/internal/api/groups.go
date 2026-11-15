package api

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
	"guardian/internal/oidc"
	db "guardian/internal/store"
)

// Groups: administrators (members of guardian-admins) may do everything. A group's owners, the members
// of its owner group, may only see it and list, add and remove its members. Nothing is cached, so a
// change is seen by the next check on every replica.

// groupKeyRe: lower case, so a key reads the same everywhere it is typed into an app's configuration.
var groupKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

func groupFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrGroupNotFound):
		httpx.Error(w, http.StatusNotFound, "Group not found")
	case errors.Is(err, db.ErrSystemGroup):
		httpx.Error(w, http.StatusForbidden, "Built-in groups cannot be changed or deleted")
	case errors.Is(err, db.ErrLastAdmin):
		httpx.ErrorCode(w, http.StatusConflict, "last_admin", "Guardian must keep at least one active administrator whose membership does not expire")
	case errors.Is(err, db.ErrInvalidOwner):
		httpx.Error(w, http.StatusBadRequest, "owner_group_id must be another existing group")
	case db.IsUniqueViolation(err):
		httpx.Error(w, http.StatusConflict, "A group with that key already exists")
	default:
		slog.Error("group change failed", "error", err)
		httpx.Error(w, http.StatusInternalServerError, "Request failed")
	}
}

// groupAccess decides whether the caller may see and change the members of the group in the URL. It
// returns how the right was obtained ("admin" or "owner:<owner group key>") for the audit log. When
// access is refused it has already written the response.
func groupAccess(w http.ResponseWriter, r *http.Request) (group db.Group, via string, ok bool) {
	group, err := db.GetGroup(chi.URLParam(r, "group"))
	if err != nil {
		groupFail(w, err)
		return db.Group{}, "", false
	}
	admin, err := db.IsAdmin(httpx.AccountID(r))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return db.Group{}, "", false
	}
	if admin {
		return group, "admin", true
	}
	ownerKey, owns, err := db.OwnsGroup(httpx.AccountID(r), group.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return db.Group{}, "", false
	}
	if !owns {
		httpx.Error(w, http.StatusForbidden, "Only administrators and the group's owners may do this")
		return db.Group{}, "", false
	}
	return group, "owner:" + ownerKey, true
}

// listGroups returns every group to an administrator, and to anyone else the groups they own.
func listGroups(w http.ResponseWriter, r *http.Request) {
	admin, err := db.IsAdmin(httpx.AccountID(r))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var groups []db.Group
	if admin {
		groups, err = db.ListGroups()
	} else {
		groups, err = db.ListGroupsOwnedBy(httpx.AccountID(r))
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to list groups")
		return
	}
	httpx.JSON(w, http.StatusOK, list(groups))
}

func getGroup(w http.ResponseWriter, r *http.Request) {
	if group, _, ok := groupAccess(w, r); ok {
		httpx.JSON(w, http.StatusOK, group)
	}
}

func createGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key          string `json:"key"`
		DisplayName  string `json:"display_name"`
		Description  string `json:"description"`
		OwnerGroupID string `json:"owner_group_id"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !groupKeyRe.MatchString(req.Key) {
		httpx.Error(w, http.StatusBadRequest, "key must be 2-63 characters: lower-case letters, digits, dot, dash or underscore, starting with a letter or digit")
		return
	}
	if req.DisplayName == "" || len(req.DisplayName) > 128 || len(req.Description) > 1024 {
		httpx.Error(w, http.StatusBadRequest, "display_name is required (up to 128 characters); description may be up to 1024 characters")
		return
	}
	if req.OwnerGroupID != "" && !db.IsUUID(req.OwnerGroupID) {
		httpx.Error(w, http.StatusBadRequest, "owner_group_id must be another existing group")
		return
	}
	id, err := db.CreateGroup(req.Key, req.DisplayName, req.Description, req.OwnerGroupID)
	if err != nil {
		groupFail(w, err)
		return
	}
	db.Audit("group.created", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"group": id, "key": req.Key, "owner_group": req.OwnerGroupID})
	group, err := db.GetGroup(id)
	if err != nil {
		groupFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, group)
}

// updateGroup changes the display name, description or owner. The key never changes: apps match on it.
func updateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key          *string `json:"key"`
		DisplayName  *string `json:"display_name"`
		Description  *string `json:"description"`
		OwnerGroupID *string `json:"owner_group_id"` // "" removes the owner
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.Key != nil {
		httpx.Error(w, http.StatusBadRequest, "A group's key cannot be changed")
		return
	}
	if (req.DisplayName != nil && (*req.DisplayName == "" || len(*req.DisplayName) > 128)) ||
		(req.Description != nil && len(*req.Description) > 1024) {
		httpx.Error(w, http.StatusBadRequest, "display_name must be 1-128 characters; description may be up to 1024 characters")
		return
	}
	if req.OwnerGroupID != nil && *req.OwnerGroupID != "" && !db.IsUUID(*req.OwnerGroupID) {
		httpx.Error(w, http.StatusBadRequest, "owner_group_id must be another existing group")
		return
	}
	id := chi.URLParam(r, "group")
	err := db.UpdateGroup(id, db.GroupUpdate{DisplayName: req.DisplayName, Description: req.Description, OwnerGroupID: req.OwnerGroupID})
	if err != nil {
		groupFail(w, err)
		return
	}
	detail := map[string]any{"group": id}
	if req.OwnerGroupID != nil {
		detail["owner_group"] = *req.OwnerGroupID
	}
	db.Audit("group.updated", httpx.AccountID(r), "", httpx.ClientIP(r), detail)
	group, err := db.GetGroup(id)
	if err != nil {
		groupFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, group)
}

func deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "group")
	group, err := db.GetGroup(id)
	if err == nil {
		err = db.DeleteGroup(id)
	}
	if err != nil {
		groupFail(w, err)
		return
	}
	db.Audit("group.deleted", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"group": id, "key": group.Key})
	httpx.NoContent(w)
}

func listGroupMembers(w http.ResponseWriter, r *http.Request) {
	group, _, ok := groupAccess(w, r)
	if !ok {
		return
	}
	members, err := db.ListGroupMembers(group.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to list members")
		return
	}
	httpx.JSON(w, http.StatusOK, list(members))
}

// addGroupMember adds an account to the group, or changes when its membership expires. The body is
// optional: {"expires_at": "<RFC 3339 time>"}. Without it the membership does not expire.
func addGroupMember(w http.ResponseWriter, r *http.Request) {
	group, via, ok := groupAccess(w, r)
	if !ok {
		return
	}
	var req struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if r.ContentLength != 0 && !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		httpx.Error(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}
	member, err := db.GetAccount(chi.URLParam(r, "account"))
	if err != nil || member.Status != "active" {
		httpx.Error(w, http.StatusNotFound, "Account not found")
		return
	}
	if err := db.AddGroupMember(group.ID, member.ID, httpx.AccountID(r), req.ExpiresAt); err != nil {
		groupFail(w, err)
		return
	}
	db.Audit("group.member_added", httpx.AccountID(r), "", httpx.ClientIP(r),
		map[string]any{"group": group.ID, "key": group.Key, "account": member.ID, "via": via, "expires_at": req.ExpiresAt})
	httpx.NoContent(w)
}

func removeGroupMember(w http.ResponseWriter, r *http.Request) {
	group, via, ok := groupAccess(w, r)
	if !ok {
		return
	}
	member := chi.URLParam(r, "account")
	if !db.IsUUID(member) {
		httpx.Error(w, http.StatusNotFound, "Account not found")
		return
	}
	if err := db.RemoveGroupMember(group.ID, member); err != nil {
		groupFail(w, err)
		return
	}
	// Apps linked to this group are told to drop what they hold for the user, so the change reaches apps
	// with back-channel logout at once instead of at their next refresh.
	notices, err := db.GroupChangeLogoutNotices(member, group.ID)
	if err != nil {
		slog.Error("failed to look up apps to notify about a group change", "error", err)
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("group.member_removed", httpx.AccountID(r), "", httpx.ClientIP(r),
		map[string]any{"group": group.ID, "key": group.Key, "account": member, "via": via, "apps_notified": len(notices)})
	httpx.NoContent(w)
}
