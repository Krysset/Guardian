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
	SigningAlg             string   `json:"signing_alg"`              // "RS256" (default) or "ES256"
	OwnerGroupID           string   `json:"owner_group_id"`           // optional: its members are the app's admins
}

func validAccessRule(rule string) bool { return rule == "groups" || rule == "anyone" }

const signingAlgRule = "signing_alg must be 'RS256' or 'ES256'"

func validSigningAlg(alg string) bool { return slices.Contains(db.SigningAlgs, alg) }

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
	if req.SigningAlg == "" {
		req.SigningAlg = "RS256"
	}
	if !validSigningAlg(req.SigningAlg) {
		httpx.Error(w, http.StatusBadRequest, signingAlgRule)
		return
	}
	if !validOwnerGroup(w, req.OwnerGroupID) {
		return
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
		SigningAlg: req.SigningAlg, OwnerGroupID: req.OwnerGroupID,
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
	app, via, ok := appAccess(w, r)
	if !ok {
		return
	}
	id := app.ID
	// Checked first, so a refused request changes nothing.
	if req.MachineAPI != nil {
		if via != "admin" && *req.MachineAPI != slices.Contains(app.GrantTypes, "client_credentials") {
			httpx.Error(w, http.StatusForbidden, "Only administrators turn the machine API on or off")
			return
		}
		if *req.MachineAPI && app.ClientType != "confidential" {
			httpx.Error(w, http.StatusBadRequest, "Only apps with a secret can have machine API access")
			return
		}
	}
	// An app's admins link and unlink only groups they own: a link tells the app who is in the group.
	if via != "admin" {
		for _, g := range changedGroups(app.GroupIDs, req.GroupIDs) {
			_, owns, err := db.OwnsGroup(httpx.AccountID(r), g)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "Failed to update the app")
				return
			}
			if !owns {
				httpx.ErrorCode(w, http.StatusForbidden, "not_group_owner", "App admins may only link and unlink groups they own")
				return
			}
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
		map[string]any{"access_rule": req.AccessRule, "groups": req.GroupIDs, "machine_api": req.MachineAPI, "via": via})
	app, err := db.GetApp(id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to load the app")
		return
	}
	httpx.JSON(w, http.StatusOK, app)
}

// changedGroups are the groups in one list but not the other: those a change links or unlinks.
func changedGroups(before, after []string) []string {
	var out []string
	for _, g := range after {
		if !slices.Contains(before, g) {
			out = append(out, g)
		}
	}
	for _, g := range before {
		if !slices.Contains(after, g) {
			out = append(out, g)
		}
	}
	return out
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

// appAccess decides whether the caller may manage the app in the URL: Guardian admins may, and so may the
// app's admins (the active members of its owner group). Both need a session that passed two-factor. It
// returns how the right was obtained ("admin" or "owner:<owner group key>") for the audit log. When access
// is refused it has already written the response.
func appAccess(w http.ResponseWriter, r *http.Request) (app db.App, via string, ok bool) {
	app, err := db.GetApp(chi.URLParam(r, "app"))
	if err != nil {
		appFail(w, err)
		return db.App{}, "", false
	}
	admin, err := db.IsAdmin(httpx.AccountID(r))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return db.App{}, "", false
	}
	via = "admin"
	if !admin {
		ownerKey, owns, err := db.AppAdminVia(httpx.AccountID(r), app.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
			return db.App{}, "", false
		}
		if !owns {
			httpx.Error(w, http.StatusForbidden, "Only administrators and the app's admins may do this")
			return db.App{}, "", false
		}
		via = "owner:" + ownerKey
	}
	if !httpx.RequireMFASession(w, r) {
		return db.App{}, "", false
	}
	return app, via, true
}

// validOwnerGroup checks an app's owner group: "" (none) or an existing group. It answers 400 if not.
func validOwnerGroup(w http.ResponseWriter, id string) bool {
	if id == "" {
		return true
	}
	if _, err := db.GetGroup(id); err != nil {
		httpx.Error(w, http.StatusBadRequest, "owner_group_id must be an existing group")
		return false
	}
	return true
}

// listApps returns every app to an administrator, and to anyone else the apps they are an admin of.
func listApps(w http.ResponseWriter, r *http.Request) {
	admin, err := db.IsAdmin(httpx.AccountID(r))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var apps []db.App
	if admin {
		if !httpx.RequireMFASession(w, r) {
			return
		}
		apps, err = db.GetApps()
	} else {
		apps, err = db.AppsAdministeredBy(httpx.AccountID(r))
	}
	if err != nil {
		appFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, list(apps))
}

// getApp returns the app, with the names of its linked groups (an app admin cannot list every group).
func getApp(w http.ResponseWriter, r *http.Request) {
	app, _, ok := appAccess(w, r)
	if !ok {
		return
	}
	linked, err := db.GroupSummaries(app.GroupIDs)
	if err != nil {
		appFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, struct {
		db.App
		LinkedGroups []db.GroupSummary `json:"linked_groups"`
	}{app, linked})
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
		SigningAlg             *string   `json:"signing_alg"`
		OwnerGroupID           *string   `json:"owner_group_id"` // "" removes it; Guardian admins only
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
	case req.SigningAlg != nil && !validSigningAlg(*req.SigningAlg):
		httpx.Error(w, http.StatusBadRequest, signingAlgRule)
		return
	}
	if msg := checkURIs(vals(req.RedirectURIs), vals(req.PostLogoutRedirectURIs), val(req.BackchannelLogoutURI),
		val(req.LogoURL), val(req.HomepageURL)); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	current, via, ok := appAccess(w, r)
	if !ok {
		return
	}
	// Being first-party skips the consent screen, and scopes decide which claims an app may read: both are a
	// promise to the people signing in, so only Guardian admins change them. The back-channel logout URI is
	// an address Guardian's own server sends requests to, from inside the cluster, so it is theirs too.
	// Sending the current value is fine.
	if via != "admin" {
		if req.BackchannelLogoutURI != nil && *req.BackchannelLogoutURI != current.BackchannelLogoutURI {
			httpx.Error(w, http.StatusForbidden, "Only administrators change an app's back-channel logout URI")
			return
		}
		if req.IsFirstParty != nil && *req.IsFirstParty != current.IsFirstParty {
			httpx.Error(w, http.StatusForbidden, "Only administrators decide whether an app is first-party")
			return
		}
		if req.Scopes != nil && !sameSet(*req.Scopes, current.Scopes) {
			httpx.Error(w, http.StatusForbidden, "Only administrators change an app's scopes")
			return
		}
	}
	if req.OwnerGroupID != nil {
		if via != "admin" {
			httpx.Error(w, http.StatusForbidden, "Only administrators choose an app's admins")
			return
		}
		if !validOwnerGroup(w, *req.OwnerGroupID) {
			return
		}
	}
	app, err := db.UpdateApp(current.ID, db.AppUpdate{
		PrettyName: req.PrettyName, Description: req.Description, LogoURL: req.LogoURL, HomepageURL: req.HomepageURL,
		BackchannelLogoutURI: req.BackchannelLogoutURI, RedirectURIs: req.RedirectURIs,
		PostLogoutRedirectURIs: req.PostLogoutRedirectURIs, Scopes: req.Scopes,
		IsFirstParty: req.IsFirstParty, Enabled: req.Enabled, AccessTokenTTL: req.AccessTokenTTLSeconds,
		RequireMFA: req.RequireMFA, SigningAlg: req.SigningAlg, OwnerGroupID: req.OwnerGroupID,
	})
	if err != nil {
		appFail(w, err)
		return
	}
	detail := map[string]any{"app": app.ID, "via": via}
	if req.OwnerGroupID != nil {
		detail["owner_group"] = *req.OwnerGroupID
	}
	if req.SigningAlg != nil {
		detail["signing_alg"] = *req.SigningAlg
	}
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
	app, via, ok := appAccess(w, r)
	if !ok {
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
	db.Audit("app.secret_rotated", httpx.AccountID(r), app.ID, httpx.ClientIP(r), map[string]any{"grace_seconds": req.GraceSeconds, "via": via})
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

// sameSet reports whether a and b hold the same strings, in any order.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}
