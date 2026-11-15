package api

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

var appNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)

// GetAppSubrouter manages apps (OIDC clients). Every route is for administrators only: an app's
// redirect URIs and settings are not something other accounts should be able to read.
func GetAppSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(httpx.RequireAdmin)
	r.Get("/list", listApps)
	r.Get("/{uuid}", getApp)
	r.Post("/add", addApp)
	r.Post("/access", setAppAccess)
	r.Delete("/remove", removeApp)
	return r
}

type addAppRequest struct {
	Name                   string   `json:"name"`
	PrettyName             string   `json:"pretty_name"`
	Description            string   `json:"description"`
	LogoURL                string   `json:"logo_url"`
	HomepageURL            string   `json:"homepage_url"`
	ClientType             string   `json:"client_type"` // "confidential" (default) or "public"
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI   string   `json:"backchannel_logout_uri"`
	IsFirstParty           bool     `json:"is_first_party"`
	AccessTokenTTLSeconds  int      `json:"access_token_ttl_seconds"` // optional, 15-86400, default 300
	Scopes                 []string `json:"scopes"`                   // defaults to openid, profile, email, groups
	AccessRule             string   `json:"access_rule"`              // "groups" (default) or "anyone"
	GroupIDs               []string `json:"group_ids"`                // groups linked to the app
}

func validAccessRule(rule string) bool { return rule == "groups" || rule == "anyone" }

func addApp(w http.ResponseWriter, r *http.Request) {
	var req addAppRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.ClientType == "" {
		req.ClientType = "confidential"
	}
	if req.ClientType != "confidential" && req.ClientType != "public" {
		httpx.Error(w, http.StatusBadRequest, "client_type must be 'confidential' or 'public'")
		return
	}
	if !appNameRe.MatchString(req.Name) || req.PrettyName == "" {
		httpx.Error(w, http.StatusBadRequest, "name must be lowercase letters, digits, '-' or '_'; pretty_name is required")
		return
	}
	if len(req.RedirectURIs) == 0 {
		httpx.Error(w, http.StatusBadRequest, "At least one redirect URI is required")
		return
	}
	uris := append(append([]string{}, req.RedirectURIs...), req.PostLogoutRedirectURIs...)
	if req.BackchannelLogoutURI != "" {
		uris = append(uris, req.BackchannelLogoutURI)
	}
	for _, u := range uris {
		if !httpx.ValidRedirectURI(u) {
			httpx.Error(w, http.StatusBadRequest, "Invalid URI (must be https, or http on localhost): "+u)
			return
		}
	}
	// The token lifetime is how stale an app's view of a user can get. Below 15 seconds apps would do
	// little else than refresh. 60 seconds or more is recommended, because clocks differ.
	if req.AccessTokenTTLSeconds != 0 && (req.AccessTokenTTLSeconds < 15 || req.AccessTokenTTLSeconds > 86400) {
		httpx.Error(w, http.StatusBadRequest, "access_token_ttl_seconds must be between 15 and 86400")
		return
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if req.AccessRule == "" {
		req.AccessRule = "groups"
	}
	if !validAccessRule(req.AccessRule) || !allUUIDs(req.GroupIDs...) {
		httpx.Error(w, http.StatusBadRequest, "access_rule must be 'groups' or 'anyone'; group_ids must be group ids")
		return
	}

	secret, secretHash := "", ""
	if req.ClientType == "confidential" {
		var err error
		if secret, err = auth.RandomToken(32); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		secretHash = auth.HashToken(secret)
	}

	app, err := db.AddApp(db.App{
		Name: req.Name, PrettyName: req.PrettyName, Description: req.Description,
		LogoURL: req.LogoURL, HomepageURL: req.HomepageURL, ClientType: req.ClientType,
		RedirectURIs: req.RedirectURIs, PostLogoutRedirectURIs: req.PostLogoutRedirectURIs,
		BackchannelLogoutURI: req.BackchannelLogoutURI, IsFirstParty: req.IsFirstParty,
		AccessTokenTTL: req.AccessTokenTTLSeconds, AccessRule: req.AccessRule, GroupIDs: req.GroupIDs,
	}, req.Scopes, secretHash)
	if db.IsUniqueViolation(err) {
		httpx.Error(w, http.StatusConflict, "An app with that name already exists")
		return
	}
	if errors.Is(err, db.ErrGroupNotFound) {
		httpx.Error(w, http.StatusBadRequest, "group_ids contains a group that does not exist")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "Failed to add App")
		return
	}
	db.Audit("app.created", httpx.AccountID(r), app.ID, httpx.ClientIP(r), map[string]any{"name": app.Name})

	resp := map[string]any{"app": app}
	if secret != "" {
		resp["client_secret"] = secret // shown exactly once; only the hash is stored
	}
	httpx.JSON(w, http.StatusCreated, resp)
}

// setAppAccess sets who may sign in to an app: the access rule and the complete list of linked groups.
// With "groups", only members of a linked group may sign in. With "anyone", every account may; the
// linked groups then only decide which groups the app is told about.
func setAppAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string   `json:"id"`
		AccessRule string   `json:"access_rule"`
		GroupIDs   []string `json:"group_ids"`
		MachineAPI *bool    `json:"machine_api"` // optional: the app's own read-only access to /api/v1/apps/self
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !db.IsUUID(req.ID) || !validAccessRule(req.AccessRule) || !allUUIDs(req.GroupIDs...) {
		httpx.Error(w, http.StatusBadRequest, "id must be an app id; access_rule must be 'groups' or 'anyone'; group_ids must be group ids")
		return
	}
	if req.MachineAPI != nil {
		// Checked first, so a refused request changes nothing.
		app, err := db.GetApp(req.ID)
		if errors.Is(err, sql.ErrNoRows) {
			httpx.Error(w, http.StatusNotFound, "App not found")
			return
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "Failed to update the app")
			return
		}
		if *req.MachineAPI && app.ClientType != "confidential" {
			httpx.Error(w, http.StatusBadRequest, "Only apps with a secret can have machine API access")
			return
		}
	}
	switch err := db.SetAppAccess(req.ID, req.AccessRule, req.GroupIDs); {
	case errors.Is(err, sql.ErrNoRows):
		httpx.Error(w, http.StatusNotFound, "App not found")
		return
	case errors.Is(err, db.ErrGroupNotFound):
		httpx.Error(w, http.StatusBadRequest, "group_ids contains a group that does not exist")
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, "Failed to update the app")
		return
	}
	if req.MachineAPI != nil {
		if err := db.SetMachineAccess(req.ID, *req.MachineAPI); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "Failed to update the app")
			return
		}
	}
	db.Audit("app.access_changed", httpx.AccountID(r), req.ID, httpx.ClientIP(r),
		map[string]any{"access_rule": req.AccessRule, "groups": req.GroupIDs, "machine_api": req.MachineAPI})
	app, err := db.GetApp(req.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to load the app")
		return
	}
	httpx.JSON(w, http.StatusOK, app)
}

func allUUIDs(ids ...string) bool {
	for _, id := range ids {
		if !db.IsUUID(id) {
			return false
		}
	}
	return true
}

func removeApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	app, err := db.GetApp(req.ID)
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "App not found")
		return
	}
	if err := db.RemoveApp(app.ID); err != nil {
		httpx.Error(w, http.StatusBadRequest, "Failed to remove App")
		return
	}
	db.Audit("app.removed", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"name": app.Name})
	httpx.JSON(w, http.StatusOK, app)
}

func listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := db.GetApps()
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to retrieve Apps")
		return
	}
	httpx.JSON(w, http.StatusOK, apps)
}

func getApp(w http.ResponseWriter, r *http.Request) {
	app, err := db.GetApp(chi.URLParam(r, "uuid"))
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "App not found")
		return
	}
	httpx.JSON(w, http.StatusOK, app)
}
