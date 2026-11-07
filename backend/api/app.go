package api

import (
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"guardian/auth"
	db "guardian/database"
)

var appNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)

func GetAppSubrouter() *chi.Mux {
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		r.Use(Authenticate)
		r.Get("/list", listApps)
		r.Get("/{uuid}", getApp)
	})

	r.Group(func(r chi.Router) {
		r.Use(RequirePermission("guardian", "apps.manage"))
		r.Post("/add", addApp)
		r.Delete("/remove", removeApp)
	})

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
	Scopes                 []string `json:"scopes"` // defaults to openid, profile, email
}

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
		AccessTokenTTL: req.AccessTokenTTLSeconds,
	}, req.Scopes, secretHash)
	if db.IsUniqueViolation(err) {
		RespondWithError(w, http.StatusConflict, "An app with that name already exists")
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
	if app.Name == "guardian" {
		RespondWithError(w, http.StatusBadRequest, "The guardian app cannot be removed")
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
