package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

var appNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)

type createAppRequest struct {
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
	RequireMFA             bool     `json:"require_mfa"`              // signing in to the app needs two-factor
}

func validAccessRule(rule string) bool { return rule == "groups" || rule == "anyone" }

func createApp(w http.ResponseWriter, r *http.Request) {
	var req createAppRequest
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
	if msg := checkURIs(req.RedirectURIs, req.PostLogoutRedirectURIs, req.BackchannelLogoutURI, req.LogoURL, req.HomepageURL); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	if req.AccessTokenTTLSeconds != 0 && !validTTL(req.AccessTokenTTLSeconds) {
		httpx.Error(w, http.StatusBadRequest, ttlRule)
		return
	}
	if len(req.PrettyName) > 128 || len(req.Description) > 1024 {
		httpx.Error(w, http.StatusBadRequest, "pretty_name may be up to 128 characters and description up to 1024")
		return
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if !slices.Contains(req.Scopes, "openid") {
		httpx.Error(w, http.StatusBadRequest, "scopes must include openid")
		return
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
		AccessTokenTTL: req.AccessTokenTTLSeconds, AccessRule: req.AccessRule, GroupIDs: req.GroupIDs, RequireMFA: req.RequireMFA,
	}, req.Scopes, secretHash)
	if err != nil {
		appFail(w, err)
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
		AccessRule string   `json:"access_rule"`
		GroupIDs   []string `json:"group_ids"`
		MachineAPI *bool    `json:"machine_api"` // optional: the app's own read-only access to /api/v1/apps/self
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !validAccessRule(req.AccessRule) || !allUUIDs(req.GroupIDs...) {
		httpx.Error(w, http.StatusBadRequest, "access_rule must be 'groups' or 'anyone'; group_ids must be group ids")
		return
	}
	id := chi.URLParam(r, "app")
	if req.MachineAPI != nil {
		// Checked first, so a refused request changes nothing.
		app, err := db.GetApp(id)
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
	switch err := db.SetAppAccess(id, req.AccessRule, req.GroupIDs); {
	case errors.Is(err, sql.ErrNoRows):
		httpx.Error(w, http.StatusNotFound, "App not found")
		return
	case errors.Is(err, db.ErrGroupNotFound), errors.Is(err, db.ErrGroupBound):
		appFail(w, err)
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, "Failed to update the app")
		return
	}
	if req.MachineAPI != nil {
		if err := db.SetMachineAccess(id, *req.MachineAPI); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "Failed to update the app")
			return
		}
	}
	db.Audit("app.access_changed", httpx.AccountID(r), id, httpx.ClientIP(r),
		map[string]any{"access_rule": req.AccessRule, "groups": req.GroupIDs, "machine_api": req.MachineAPI})
	app, err := db.GetApp(id)
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

// deleteApp removes an app with its secrets, tokens and consents.
func deleteApp(w http.ResponseWriter, r *http.Request) {
	app, err := db.GetApp(chi.URLParam(r, "app"))
	if err != nil {
		appFail(w, err)
		return
	}
	if err := db.RemoveApp(app.ID); err != nil {
		appFail(w, err)
		return
	}
	db.Audit("app.removed", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"app": app.ID, "name": app.Name})
	httpx.NoContent(w)
}

func listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := db.GetApps()
	if err != nil {
		appFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, list(apps))
}

func getApp(w http.ResponseWriter, r *http.Request) {
	app, err := db.GetApp(chi.URLParam(r, "app"))
	if err != nil {
		appFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, app)
}

// updateApp changes an app's settings. Only fields present in the body change. The name, client id and
// client type never change; access has its own route.
func updateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrettyName             *string   `json:"pretty_name"`
		Description            *string   `json:"description"`
		LogoURL                *string   `json:"logo_url"`
		HomepageURL            *string   `json:"homepage_url"`
		RedirectURIs           *[]string `json:"redirect_uris"`
		PostLogoutRedirectURIs *[]string `json:"post_logout_redirect_uris"`
		BackchannelLogoutURI   *string   `json:"backchannel_logout_uri"`
		IsFirstParty           *bool     `json:"is_first_party"`
		AccessTokenTTLSeconds  *int      `json:"access_token_ttl_seconds"`
		Scopes                 *[]string `json:"scopes"`
		Enabled                *bool     `json:"enabled"`
		RequireMFA             *bool     `json:"require_mfa"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	val := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	vals := func(p *[]string) []string {
		if p == nil {
			return nil
		}
		return *p
	}
	switch {
	case req.PrettyName != nil && (*req.PrettyName == "" || len(*req.PrettyName) > 128):
		httpx.Error(w, http.StatusBadRequest, "pretty_name must be 1-128 characters")
		return
	case req.Description != nil && len(*req.Description) > 1024:
		httpx.Error(w, http.StatusBadRequest, "description may be up to 1024 characters")
		return
	case req.RedirectURIs != nil && len(*req.RedirectURIs) == 0:
		httpx.Error(w, http.StatusBadRequest, "At least one redirect URI is required")
		return
	case req.AccessTokenTTLSeconds != nil && !validTTL(*req.AccessTokenTTLSeconds):
		httpx.Error(w, http.StatusBadRequest, ttlRule)
		return
	case req.Scopes != nil && !slices.Contains(*req.Scopes, "openid"):
		httpx.Error(w, http.StatusBadRequest, "scopes must include openid")
		return
	}
	if msg := checkURIs(vals(req.RedirectURIs), vals(req.PostLogoutRedirectURIs), val(req.BackchannelLogoutURI),
		val(req.LogoURL), val(req.HomepageURL)); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	id := chi.URLParam(r, "app")
	app, err := db.UpdateApp(id, db.AppUpdate{
		PrettyName: req.PrettyName, Description: req.Description, LogoURL: req.LogoURL, HomepageURL: req.HomepageURL,
		BackchannelLogoutURI: req.BackchannelLogoutURI, RedirectURIs: req.RedirectURIs,
		PostLogoutRedirectURIs: req.PostLogoutRedirectURIs, Scopes: req.Scopes,
		IsFirstParty: req.IsFirstParty, Enabled: req.Enabled, AccessTokenTTL: req.AccessTokenTTLSeconds,
		RequireMFA: req.RequireMFA,
	})
	if err != nil {
		appFail(w, err)
		return
	}
	detail := map[string]any{"app": app.ID}
	if req.Enabled != nil {
		detail["enabled"] = *req.Enabled
	}
	if req.RequireMFA != nil {
		detail["require_mfa"] = *req.RequireMFA
	}
	db.Audit("app.updated", httpx.AccountID(r), app.ID, httpx.ClientIP(r), detail)
	httpx.JSON(w, http.StatusOK, app)
}

// rotateAppSecret creates a new client secret and returns it once. The app's older secrets keep working
// for grace_seconds (default 0: they stop at once, at most 7 days), so the new one can be rolled out first.
func rotateAppSecret(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GraceSeconds int `json:"grace_seconds"`
	}
	if r.ContentLength != 0 && !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.GraceSeconds < 0 || req.GraceSeconds > 7*24*3600 {
		httpx.Error(w, http.StatusBadRequest, "grace_seconds must be from 0 to 604800 (7 days)")
		return
	}
	app, err := db.GetApp(chi.URLParam(r, "app"))
	if err != nil {
		appFail(w, err)
		return
	}
	if app.ClientType != "confidential" {
		httpx.Error(w, http.StatusBadRequest, "Only confidential apps have a secret")
		return
	}
	secret, err := auth.RandomToken(32)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := db.RotateAppSecret(app.ID, auth.HashToken(secret), time.Duration(req.GraceSeconds)*time.Second); err != nil {
		appFail(w, err)
		return
	}
	db.Audit("app.secret_rotated", httpx.AccountID(r), app.ID, httpx.ClientIP(r), map[string]any{"grace_seconds": req.GraceSeconds})
	httpx.JSON(w, http.StatusCreated, map[string]any{"client_secret": secret}) // shown once; only the hash is stored
}

// appFail answers a failed app request.
func appFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		httpx.Error(w, http.StatusNotFound, "App not found")
	case errors.Is(err, db.ErrGroupNotFound):
		httpx.Error(w, http.StatusBadRequest, "group_ids contains a group that does not exist")
	case errors.Is(err, db.ErrGroupBound):
		httpx.ErrorCode(w, http.StatusConflict, "group_bound", "group_ids contains a group that is bound to another app")
	case db.IsUniqueViolation(err):
		httpx.Error(w, http.StatusConflict, "An app with that name already exists")
	default:
		slog.Error("app request failed", "error", err)
		httpx.Error(w, http.StatusInternalServerError, "Request failed")
	}
}

const ttlRule = "access_token_ttl_seconds must be between 15 and 86400"

// validTTL: the token lifetime is how stale an app's view of a user can get. Below 15 seconds apps would
// do little else than refresh; 60 seconds or more is recommended, because clocks differ.
func validTTL(n int) bool { return n >= 15 && n <= 86400 }

// checkURIs returns what is wrong with an app's URIs, or "". Empty optional URIs are fine.
func checkURIs(redirect, postLogout []string, backchannel, logo, homepage string) string {
	uris := append(append([]string{}, redirect...), postLogout...)
	for _, u := range []string{backchannel, logo, homepage} {
		if u != "" {
			uris = append(uris, u)
		}
	}
	for _, u := range uris {
		if len(u) > 2048 || !httpx.ValidRedirectURI(u) {
			return "Invalid URI (must be https, or http on localhost, without a fragment): " + u
		}
	}
	return ""
}
