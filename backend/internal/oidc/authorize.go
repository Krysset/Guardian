package oidc

import (
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
	"guardian/internal/web"
)

type authRequest struct {
	App         db.App
	RedirectURI string
	State       string
	Nonce       string
	Challenge   string
	Prompts     []string
	MaxAge      int // -1 when absent
	Scopes      []string
}

// authError with Redirect=false must be shown to the user (client_id / redirect_uri can't be trusted);
// with Redirect=true it is sent back to the client's redirect_uri.
type authError struct {
	Code        string
	Description string
	Redirect    bool
}

func parseAuthRequest(q url.Values) (*authRequest, *authError) {
	app, err := db.GetAppByClientID(q.Get("client_id"))
	if err != nil || !app.Enabled {
		return nil, &authError{"invalid_client", "Unknown application.", false}
	}
	redirectURI := q.Get("redirect_uri")
	if !slices.Contains(app.RedirectURIs, redirectURI) { // exact match only
		return nil, &authError{"invalid_request", "The redirect_uri is not registered for this application.", false}
	}
	req := &authRequest{
		App: app, RedirectURI: redirectURI, State: q.Get("state"), Nonce: q.Get("nonce"),
		Challenge: q.Get("code_challenge"), Prompts: strings.Fields(q.Get("prompt")),
		MaxAge: -1, Scopes: strings.Fields(q.Get("scope")),
	}
	fail := func(code, desc string) (*authRequest, *authError) {
		return req, &authError{code, desc, true}
	}

	if v := q.Get("max_age"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fail("invalid_request", "max_age must be a non-negative integer")
		}
		req.MaxAge = n
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "Only response_type=code is supported")
	}
	if !slices.Contains(req.Scopes, "openid") {
		return fail("invalid_scope", "The openid scope is required")
	}
	allowed := app.Scopes // loaded with the app in the same query
	for _, sc := range req.Scopes {
		if !slices.Contains(allowed, sc) {
			return fail("invalid_scope", "Scope not allowed for this application: "+sc)
		}
	}
	if req.Challenge != "" {
		if q.Get("code_challenge_method") != "S256" || len(req.Challenge) != 43 {
			return fail("invalid_request", "Only code_challenge_method=S256 is supported")
		}
	} else if app.RequirePKCE || app.ClientType == "public" {
		return fail("invalid_request", "PKCE is required: send code_challenge and code_challenge_method=S256")
	}
	return req, nil
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		web.Error(w, web.BrokenLink)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", httpx.Issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// refuseAuthRequest answers a request that parseAuthRequest refused: back to the app when its redirect
// address can be trusted, otherwise with the "broken sign-in link" page. The page never shows the reason,
// so it is logged for whoever runs the app.
func refuseAuthRequest(w http.ResponseWriter, r *http.Request, req *authRequest, aerr *authError) {
	if aerr.Redirect {
		redirectWithError(w, r, req.RedirectURI, req.State, aerr.Code, aerr.Description)
		return
	}
	slog.Info("refused an authorization request", "error", aerr.Code, "reason", aerr.Description,
		"client_id", r.FormValue("client_id"))
	web.Error(w, web.BrokenLink)
}

func authorize(w http.ResponseWriter, r *http.Request) {
	req, aerr := parseAuthRequest(r.URL.Query())
	if aerr != nil {
		refuseAuthRequest(w, r, req, aerr)
		return
	}

	sess, loggedIn := httpx.SessionFromRequest(r)
	needLogin := !loggedIn || slices.Contains(req.Prompts, "login") ||
		(req.MaxAge >= 0 && time.Since(sess.AuthTime) > time.Duration(req.MaxAge)*time.Second)
	if needLogin {
		if slices.Contains(req.Prompts, "none") {
			redirectWithError(w, r, req.RedirectURI, req.State, "login_required", "")
			return
		}
		// Come back to the same request after login, minus the parts that would force another login.
		q := r.URL.Query()
		q.Del("max_age")
		if rest := without(req.Prompts, "login"); len(rest) > 0 {
			q.Set("prompt", strings.Join(rest, " "))
		} else {
			q.Del("prompt")
		}
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape("/authorize?"+q.Encode()), http.StatusFound)
		return
	}

	acct, err := db.GetAccount(sess.AccountID)
	if err != nil {
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	// An account with a temporary password must choose its own before it may sign in to anything.
	if acct.MustChangePassword {
		if slices.Contains(req.Prompts, "none") {
			redirectWithError(w, r, req.RedirectURI, req.State, "interaction_required", "")
			return
		}
		http.Redirect(w, r, web.MustChangePasswordURL("/authorize?"+r.URL.RawQuery), http.StatusFound)
		return
	}

	// An app that requires two-factor gets a session that passed it, now or earlier.
	if req.App.RequireMFA && !httpx.TwoFactor(sess.AMR) {
		if slices.Contains(req.Prompts, "none") {
			redirectWithError(w, r, req.RedirectURI, req.State, "interaction_required", "")
			return
		}
		web.StepUp(w, r, sess.AccountID, "/authorize?"+r.URL.RawQuery, req.App.PrettyName)
		return
	}

	// The app's access rule: with "groups", only members of a group linked to the app may sign in to it.
	// Nobody else gets a code, so the app never has to notice and refuse them itself.
	allowed, err := db.AccountMayUseApp(sess.AccountID, req.App)
	if err != nil {
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	if !allowed {
		db.Audit("authorize.denied", sess.AccountID, req.App.ID, httpx.ClientIP(r), map[string]any{"reason": "access_rule"})
		if slices.Contains(req.Prompts, "none") {
			redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "The account has no access to this app")
			return
		}
		web.Render(w, http.StatusForbidden, "noaccess", web.Page{
			Title: "No access to " + req.App.PrettyName, App: req.App, Username: acct.Username,
			CSRF: httpx.CSRFToken(w, r), ReturnTo: "/authorize?" + r.URL.RawQuery,
		})
		return
	}

	granted, err := db.GetConsent(sess.AccountID, req.App.ID)
	if err != nil {
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	needConsent := !req.App.IsFirstParty && (!subset(req.Scopes, granted) || slices.Contains(req.Prompts, "consent"))
	if needConsent {
		if slices.Contains(req.Prompts, "none") {
			redirectWithError(w, r, req.RedirectURI, req.State, "consent_required", "")
			return
		}
		scopes, _ := db.GetScopes(req.Scopes)
		web.Render(w, http.StatusOK, "consent", web.Page{
			Title: "Allow " + req.App.PrettyName + "?", CSRF: httpx.CSRFToken(w, r),
			App: req.App, Scopes: web.ScopeLines(req.App.PrettyName, scopes), Username: acct.Username,
			Req: r.URL.RawQuery, ReturnTo: "/authorize?" + r.URL.RawQuery,
		})
		return
	}

	code, err := auth.RandomToken(32)
	if err != nil {
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	err = db.SaveAuthCode(auth.HashToken(code), db.AuthCode{
		AppID: req.App.ID, AccountID: sess.AccountID, SessionID: sess.ID, RedirectURI: req.RedirectURI,
		Scopes: req.Scopes, Nonce: req.Nonce, CodeChallenge: req.Challenge, AuthTime: sess.AuthTime,
	}, 60*time.Second)
	if err != nil {
		slog.Error("failed to save the authorization code", "error", err)
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}

	u, _ := url.Parse(req.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", httpx.Issuer)
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func consentSubmit(w http.ResponseWriter, r *http.Request) {
	if !httpx.CSRFValid(r) {
		web.Error(w, web.FormExpired)
		return
	}
	sess, ok := httpx.SessionFromRequest(r)
	if !ok {
		web.Error(w, web.SessionExpired)
		return
	}
	q, err := url.ParseQuery(r.PostFormValue("req"))
	if err != nil {
		web.Error(w, web.BrokenLink)
		return
	}
	req, aerr := parseAuthRequest(q)
	if aerr != nil {
		refuseAuthRequest(w, r, req, aerr)
		return
	}
	if r.PostFormValue("decision") != "allow" {
		redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "The user denied the request")
		return
	}
	existing, _ := db.GetConsent(sess.AccountID, req.App.ID)
	if err := db.SaveConsent(sess.AccountID, req.App.ID, union(existing, req.Scopes)); err != nil {
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	db.Audit("consent.granted", sess.AccountID, req.App.ID, httpx.ClientIP(r), map[string]any{"scopes": req.Scopes})

	// Continue the flow; drop prompt=consent so we don't ask again.
	if rest := without(req.Prompts, "consent"); len(rest) > 0 {
		q.Set("prompt", strings.Join(rest, " "))
	} else {
		q.Del("prompt")
	}
	http.Redirect(w, r, "/authorize?"+q.Encode(), http.StatusSeeOther)
}
