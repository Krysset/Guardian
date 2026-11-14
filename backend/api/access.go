package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	db "guardian/database"
)

// GetAccessSubrouter manages roles and grants. Nothing is cached, so every change is effective for the
// very next permission check or token introspection.
func GetAccessSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(RequirePermission("guardian", "permissions.manage"))
	r.Get("/roles", listRoles)
	r.Get("/permissions", listPermissions)
	r.Post("/roles", createRole)
	r.Post("/roles/delete", deleteRole)
	r.Post("/roles/permissions", setRolePermissions)
	r.Post("/permissions", createPermission)
	r.Post("/grant-role", grantRole)
	r.Post("/revoke-role", revokeRole)
	r.Post("/grant-permission", grantPermission)
	r.Post("/revoke-permission", revokePermission)
	return r
}

func allUUIDs(ids ...string) bool {
	for _, id := range ids {
		if !db.IsUUID(id) {
			return false
		}
	}
	return true
}

func accessFail(w http.ResponseWriter, err error) {
	switch {
	case db.IsUniqueViolation(err):
		RespondWithError(w, http.StatusConflict, "Already exists")
	case errors.Is(err, db.ErrSystemRole):
		RespondWithError(w, http.StatusForbidden, err.Error())
	default:
		log.Println("access change failed:", err)
		RespondWithError(w, http.StatusBadRequest, "Request failed")
	}
}

func listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := db.ListRoles()
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Failed to list roles")
		return
	}
	RespondWithJSON(w, http.StatusOK, roles)
}

func listPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := db.ListAppPermissions()
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Failed to list permissions")
		return
	}
	RespondWithJSON(w, http.StatusOK, perms)
}

func createRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string   `json:"name"`
		PrettyName     string   `json:"pretty_name"`
		Description    string   `json:"description"`
		AllPermissions bool     `json:"all_permissions"`
		PermissionIDs  []string `json:"permission_ids"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !appNameRe.MatchString(req.Name) || req.PrettyName == "" || !allUUIDs(req.PermissionIDs...) {
		RespondWithError(w, http.StatusBadRequest, "Invalid name, pretty_name or permission id")
		return
	}
	id, err := db.CreateRole(req.Name, req.PrettyName, req.Description, req.AllPermissions, req.PermissionIDs)
	if err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("role.created", accountID(r), "", clientIP(r), map[string]any{"role": id, "name": req.Name})
	RespondWithJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func deleteRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if !decodeJSON(w, r, &req) || !allUUIDsOrFail(w, req.RoleID) {
		return
	}
	if err := db.DeleteRole(req.RoleID); err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("role.deleted", accountID(r), "", clientIP(r), map[string]any{"role": req.RoleID})
	RespondWithSuccess(w)
}

func setRolePermissions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID        string   `json:"role_id"`
		PermissionIDs []string `json:"permission_ids"`
	}
	if !decodeJSON(w, r, &req) || !allUUIDsOrFail(w, append([]string{req.RoleID}, req.PermissionIDs...)...) {
		return
	}
	if err := db.SetRolePermissions(req.RoleID, req.PermissionIDs); err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("role.permissions_set", accountID(r), "", clientIP(r), map[string]any{"role": req.RoleID, "permissions": req.PermissionIDs})
	RespondWithSuccess(w)
}

func createPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID       string `json:"app_id"`
		Name        string `json:"name"`
		PrettyName  string `json:"pretty_name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !db.IsUUID(req.AppID) || req.Name == "" || len(req.Name) > 128 || req.PrettyName == "" {
		RespondWithError(w, http.StatusBadRequest, "Invalid app_id, name or pretty_name")
		return
	}
	id, err := db.CreateAppPermission(req.AppID, req.Name, req.PrettyName, req.Description)
	if err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("permission.created", accountID(r), req.AppID, clientIP(r), map[string]any{"name": req.Name})
	RespondWithJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func allUUIDsOrFail(w http.ResponseWriter, ids ...string) bool {
	if !allUUIDs(ids...) {
		RespondWithError(w, http.StatusBadRequest, "Invalid id")
		return false
	}
	return true
}

type grantRoleRequest struct {
	AccountID string     `json:"account_id"`
	RoleID    string     `json:"role_id"`
	ExpiresAt *time.Time `json:"expires_at"` // optional, RFC 3339
}

func grantRole(w http.ResponseWriter, r *http.Request) {
	var req grantRoleRequest
	if !decodeJSON(w, r, &req) || !allUUIDsOrFail(w, req.AccountID, req.RoleID) {
		return
	}
	if err := db.GrantRole(req.AccountID, req.RoleID, accountID(r), req.ExpiresAt); err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("role.granted", accountID(r), "", clientIP(r), map[string]any{"account": req.AccountID, "role": req.RoleID})
	RespondWithSuccess(w)
}

func revokeRole(w http.ResponseWriter, r *http.Request) {
	var req grantRoleRequest
	if !decodeJSON(w, r, &req) || !allUUIDsOrFail(w, req.AccountID, req.RoleID) {
		return
	}
	if err := db.RevokeRole(req.AccountID, req.RoleID); err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("role.revoked", accountID(r), "", clientIP(r), map[string]any{"account": req.AccountID, "role": req.RoleID})
	RespondWithSuccess(w)
}

func grantPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID    string          `json:"account_id"`
		PermissionID string          `json:"permission_id"`
		Attributes   json.RawMessage `json:"attributes"` // optional JSON object for app-specific logic
		ExpiresAt    *time.Time      `json:"expires_at"`
	}
	if !decodeJSON(w, r, &req) || !allUUIDsOrFail(w, req.AccountID, req.PermissionID) {
		return
	}
	attrs := string(req.Attributes)
	if attrs != "" && (!json.Valid(req.Attributes) || attrs[0] != '{') {
		RespondWithError(w, http.StatusBadRequest, "attributes must be a JSON object")
		return
	}
	if err := db.GrantPermission(req.AccountID, req.PermissionID, accountID(r), attrs, req.ExpiresAt); err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("permission.granted", accountID(r), "", clientIP(r), map[string]any{"account": req.AccountID, "permission": req.PermissionID})
	RespondWithSuccess(w)
}

func revokePermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID    string `json:"account_id"`
		PermissionID string `json:"permission_id"`
	}
	if !decodeJSON(w, r, &req) || !allUUIDsOrFail(w, req.AccountID, req.PermissionID) {
		return
	}
	if err := db.RevokePermission(req.AccountID, req.PermissionID); err != nil {
		accessFail(w, err)
		return
	}
	db.Audit("permission.revoked", accountID(r), "", clientIP(r), map[string]any{"account": req.AccountID, "permission": req.PermissionID})
	RespondWithSuccess(w)
}
