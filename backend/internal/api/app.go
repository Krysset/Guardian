package api

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"guardian/internal/auth"
	db "guardian/internal/store"
)

var appNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)

// GetAppSubrouter manages apps (OIDC clients). Every route is for administrators only: an app's
// redirect URIs and settings are not something other accounts should be able to read.
func GetAppSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(RequireAdmin)
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
	AccessTokenTTLSeconds  int      `json:"access_token_ttl_seconds"` // optional, 60-86400, default 900
	Scopes                 []string `json:"scopes"`                   // defaults to openid, profile, email
	AccessRule             string   `json:"access_rule"`              // "groups" (default) or "anyone"
	GroupIDs               []string `json:"group_ids"`                // groups linked to the app
}

func validAccessRule(rule string) bool { return rule == "groups" || rule == "anyone" }

func addApp(w http.ResponseWriter, r *http.Request) {
	var req addAppRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ClientType == "" {
		req.ClientType = "confidential"
	}
	if req.ClientType != "confidential" && req.ClientType != "public" {
		RespondWithError(w, http.StatusBadRequest, "client_type must be 'confidential' or 'public'")
		return
	}
	if !appNameRe.MatchString(req.Name) || req.PrettyName == "" {
		RespondWithError(w, http.StatusBadRequest, "name must be lowercase letters, digits, '-' or '_'; pretty_name is required")
		return
	}
	if len(req.RedirectURIs) == 0 {
		RespondWithError(w, http.StatusBadRequest, "At least one redirect URI is required")
		return
	}
	uris := append(append([]string{}, req.RedirectURIs...), req.PostLogoutRedirectURIs...)
	if req.BackchannelLogoutURI != "" {
		uris = append(uris, req.BackchannelLogoutURI)
	}
	for _, u := range uris {
		if !validRedirectURI(u) {
			RespondWithError(w, http.StatusBadRequest, "Invalid URI (must be https, or http on localhost): "+u)
			return
		}
	}
	if req.AccessTokenTTLSeconds != 0 && (req.AccessTokenTTLSeconds < 60 || req.AccessTokenTTLSeconds > 86400) {
		RespondWithError(w, http.StatusBadRequest, "access_token_ttl_seconds must be between 60 and 86400")
		return
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile", "email"}
	}
	if req.AccessRule == "" {
		req.AccessRule = "groups"
	}
	if !validAccessRule(req.AccessRule) || !allUUIDs(req.GroupIDs...) {
		RespondWithError(w, http.StatusBadRequest, "access_rule must be 'groups' or 'anyone'; group_ids must be group ids")
		return
	}

	secret, secretHash := "", ""
	if req.ClientType == "confidential" {
		var err error
		if secret, err = auth.RandomToken(32); err != nil {
			RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
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
		RespondWithError(w, http.StatusConflict, "An app with that name already exists")
		return
	}
	if errors.Is(err, db.ErrGroupNotFound) {
		RespondWithError(w, http.StatusBadRequest, "group_ids contains a group that does not exist")
		return
	}
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to add App")
		return
	}
	db.Audit("app.created", accountID(r), app.ID, clientIP(r), map[string]any{"name": app.Name})

	resp := map[string]any{"app": app}
	if secret != "" {
		resp["client_secret"] = secret // shown exactly once; only the hash is stored
	}
	RespondWithJSON(w, http.StatusCreated, resp)
}

// setAppAccess sets who may sign in to an app: the access rule and the complete list of linked groups.
// With "groups", only members of a linked group may sign in. With "anyone", every account may; the
// linked groups then only decide which groups the app is told about.
func setAppAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string   `json:"id"`
		AccessRule string   `json:"access_rule"`
		GroupIDs   []string `json:"group_ids"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !db.IsUUID(req.ID) || !validAccessRule(req.AccessRule) || !allUUIDs(req.GroupIDs...) {
		RespondWithError(w, http.StatusBadRequest, "id must be an app id; access_rule must be 'groups' or 'anyone'; group_ids must be group ids")
		return
	}
	switch err := db.SetAppAccess(req.ID, req.AccessRule, req.GroupIDs); {
	case errors.Is(err, sql.ErrNoRows):
		RespondWithError(w, http.StatusNotFound, "App not found")
		return
	case errors.Is(err, db.ErrGroupNotFound):
		RespondWithError(w, http.StatusBadRequest, "group_ids contains a group that does not exist")
		return
	case err != nil:
		RespondWithError(w, http.StatusInternalServerError, "Failed to update the app")
		return
	}
	db.Audit("app.access_changed", accountID(r), req.ID, clientIP(r), map[string]any{"access_rule": req.AccessRule, "groups": req.GroupIDs})
	app, err := db.GetApp(req.ID)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Failed to load the app")
		return
	}
	RespondWithJSON(w, http.StatusOK, app)
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
	if !decodeJSON(w, r, &req) {
		return
	}
	app, err := db.GetApp(req.ID)
	if err != nil {
		RespondWithError(w, http.StatusNotFound, "App not found")
		return
	}
	if err := db.RemoveApp(app.ID); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to remove App")
		return
	}
	db.Audit("app.removed", accountID(r), "", clientIP(r), map[string]any{"name": app.Name})
	RespondWithJSON(w, http.StatusOK, app)
}

func listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := db.GetApps()
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve Apps")
		return
	}
	RespondWithJSON(w, http.StatusOK, apps)
}

func getApp(w http.ResponseWriter, r *http.Request) {
	app, err := db.GetApp(chi.URLParam(r, "uuid"))
	if err != nil {
		RespondWithError(w, http.StatusNotFound, "App not found")
		return
	}
	RespondWithJSON(w, http.StatusOK, app)
}
