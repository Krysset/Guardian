package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"guardian/auth"
	db "guardian/database"
)

// MountOIDC registers the OIDC + login/logout endpoints at the root of the router.
func MountOIDC(r chi.Router) {
	r.Get("/.well-known/openid-configuration", discovery)
	r.Get("/jwks.json", jwks)
	r.Get("/authorize", authorize)
	r.Post("/token", tokenEndpoint)
	r.Get("/userinfo", userinfo)
	r.Post("/userinfo", userinfo)

	r.Get("/login", loginPage)
	r.Post("/login", loginSubmit)
	r.Post("/consent", consentSubmit)
	r.Get("/logout", logoutPage)
	r.Post("/logout", logoutSubmit)
}

// ---- Discovery & keys -------------------------------------------------------

func discovery(w http.ResponseWriter, r *http.Request) {
	meta := map[string]any{
		"issuer":                                Issuer,
		"authorization_endpoint":                Issuer + "/authorize",
		"token_endpoint":                        Issuer + "/token",
		"userinfo_endpoint":                     Issuer + "/userinfo",
		"jwks_uri":                              Issuer + "/jwks.json",
		"end_session_endpoint":                  Issuer + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{"sub", "name", "given_name", "family_name", "preferred_username", "picture",
			"locale", "zoneinfo", "updated_at", "email", "email_verified", "phone_number", "phone_number_verified", "sid", "auth_time"},
		"backchannel_logout_supported":         true,
		"backchannel_logout_session_supported": true,
	}
	if IntrospectionURL != "" {
		meta["introspection_endpoint"] = IntrospectionURL
		meta["introspection_endpoint_auth_methods_supported"] = []string{"client_secret_basic", "client_secret_post"}
	}
	RespondWithJSON(w, http.StatusOK, meta)
}

func jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(signingKeys.JWKS())
}

// ---- /authorize -------------------------------------------------------------

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
	if !contains(app.RedirectURIs, redirectURI) { // exact match only
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
	if !contains(req.Scopes, "openid") {
		return fail("invalid_scope", "The openid scope is required")
	}
	allowed := app.Scopes // loaded with the app in the same query
	for _, sc := range req.Scopes {
		if !contains(allowed, sc) {
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
		renderMessage(w, http.StatusBadRequest, "Authorization failed", desc)
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
	q.Set("iss", Issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func authorize(w http.ResponseWriter, r *http.Request) {
	req, aerr := parseAuthRequest(r.URL.Query())
	if aerr != nil {
		if aerr.Redirect {
			redirectWithError(w, r, req.RedirectURI, req.State, aerr.Code, aerr.Description)
		} else {
			renderMessage(w, http.StatusBadRequest, "Authorization request failed", aerr.Description)
		}
		return
	}

	sess, loggedIn := sessionFromRequest(r)
	needLogin := !loggedIn || contains(req.Prompts, "login") ||
		(req.MaxAge >= 0 && time.Since(sess.AuthTime) > time.Duration(req.MaxAge)*time.Second)
	if needLogin {
		if contains(req.Prompts, "none") {
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

	granted, err := db.GetConsent(sess.AccountID, req.App.ID)
	if err != nil {
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	needConsent := !req.App.IsFirstParty && (!subset(req.Scopes, granted) || contains(req.Prompts, "consent"))
	if needConsent {
		if contains(req.Prompts, "none") {
			redirectWithError(w, r, req.RedirectURI, req.State, "consent_required", "")
			return
		}
		scopes, _ := db.GetScopes(req.Scopes)
		acct, _ := db.GetAccount(sess.AccountID)
		renderPage(w, http.StatusOK, "consent", page{
			Title: "Authorize " + req.App.PrettyName, CSRF: csrfToken(w, r),
			App: req.App, Scopes: scopes, Username: acct.Username, Req: r.URL.RawQuery,
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
		log.Println("Failed to save auth code:", err)
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}

	u, _ := url.Parse(req.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", Issuer)
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func consentSubmit(w http.ResponseWriter, r *http.Request) {
	if !csrfValid(r) {
		renderMessage(w, http.StatusForbidden, "Request rejected", "Your form expired. Go back and try again.")
		return
	}
	sess, ok := sessionFromRequest(r)
	if !ok {
		renderMessage(w, http.StatusUnauthorized, "Signed out", "Your session has expired. Start again from the application.")
		return
	}
	q, err := url.ParseQuery(r.PostFormValue("req"))
	if err != nil {
		renderMessage(w, http.StatusBadRequest, "Invalid request", "Malformed authorization request.")
		return
	}
	req, aerr := parseAuthRequest(q)
	if aerr != nil {
		if aerr.Redirect {
			redirectWithError(w, r, req.RedirectURI, req.State, aerr.Code, aerr.Description)
		} else {
			renderMessage(w, http.StatusBadRequest, "Authorization request failed", aerr.Description)
		}
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
	db.Audit("consent.granted", sess.AccountID, req.App.ID, clientIP(r), map[string]any{"scopes": req.Scopes})

	// Continue the flow; drop prompt=consent so we don't ask again.
	if rest := without(req.Prompts, "consent"); len(rest) > 0 {
		q.Set("prompt", strings.Join(rest, " "))
	} else {
		q.Del("prompt")
	}
	http.Redirect(w, r, "/authorize?"+q.Encode(), http.StatusSeeOther)
}

// ---- /token -----------------------------------------------------------------

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="guardian"`)
	}
	RespondWithJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// authenticateClient identifies the calling app. Confidential clients must present their secret
// (checked in one query); public clients are identified by client_id only and rely on PKCE.
func authenticateClient(r *http.Request) (db.App, bool) {
	clientID, secret, hasBasic := r.BasicAuth()
	if hasBasic {
		clientID, _ = url.QueryUnescape(clientID)
		secret, _ = url.QueryUnescape(secret)
	} else {
		clientID, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if secret != "" {
		app, err := db.GetAppByClientIDAndSecret(clientID, auth.HashToken(secret))
		return app, err == nil
	}
	app, err := db.GetAppByClientID(clientID)
	return app, err == nil && app.Enabled && app.ClientType == "public"
}

func verifyPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}
	app, ok := authenticateClient(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}
	grant := r.PostFormValue("grant_type")
	if !contains(app.GrantTypes, grant) {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type not allowed for this client")
		return
	}

	switch grant {
	case "authorization_code":
		ac, err := db.ConsumeAuthCode(auth.HashToken(r.PostFormValue("code")))
		if err != nil || ac.AppID != app.ID || ac.RedirectURI != r.PostFormValue("redirect_uri") {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "Invalid, expired or already used code")
			return
		}
		if ac.CodeChallenge != "" && !verifyPKCE(r.PostFormValue("code_verifier"), ac.CodeChallenge) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		if ac.SessionID != "" && !db.SessionActive(ac.SessionID) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "Session has ended")
			return
		}
		refresh := ""
		if contains(ac.Scopes, "offline_access") && contains(app.GrantTypes, "refresh_token") {
			family, err := auth.NewUUID()
			if err == nil {
				refresh, err = auth.RandomToken(32)
			}
			if err == nil {
				err = db.SaveRefreshToken(auth.HashToken(refresh), family, app.ID, ac.AccountID, ac.SessionID, ac.Scopes,
					time.Now().Add(time.Duration(app.RefreshTokenTTL)*time.Second))
			}
			if err != nil {
				oauthError(w, http.StatusInternalServerError, "server_error", "")
				return
			}
		}
		issueTokens(w, app, ac.AccountID, ac.SessionID, ac.Scopes, ac.Nonce, ac.AuthTime, refresh)

	case "refresh_token":
		newToken, err := auth.RandomToken(32)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		old, err := db.RotateRefreshToken(auth.HashToken(r.PostFormValue("refresh_token")), app.ID,
			auth.HashToken(newToken), time.Now().Add(time.Duration(app.RefreshTokenTTL)*time.Second))
		if err == db.ErrInvalidGrant || err == db.ErrTokenReuse {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
			return
		}
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		issueTokens(w, app, old.AccountID, old.SessionID, old.Scopes, "", time.Time{}, newToken)

	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

// issueTokens builds the token response. The access token is an opaque random string (only its hash is
// stored): it carries no claims, can be revoked instantly, and services check it by calling /introspect.
// An ID token (a signed JWT, as OIDC login libraries expect) is only issued for the code grant.
func issueTokens(w http.ResponseWriter, app db.App, accountID, sessionID string, scopes []string,
	nonce string, authTime time.Time, refreshToken string) {

	acct, err := db.GetAccount(accountID)
	if err != nil || acct.Status != "active" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Account is not available")
		return
	}

	now := time.Now()
	ttl := time.Duration(app.AccessTokenTTL) * time.Second
	scopeStr := strings.Join(scopes, " ")

	accessToken, err := auth.RandomToken(32)
	if err == nil {
		err = db.SaveAccessToken(auth.HashToken(accessToken), app.ID, accountID, sessionID, scopes, now.Add(ttl))
	}
	if err != nil {
		log.Println("Failed to issue access token:", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	resp := map[string]any{
		"access_token": accessToken, "token_type": "Bearer",
		"expires_in": int(ttl.Seconds()), "scope": scopeStr,
	}

	if !authTime.IsZero() {
		idClaims := jwt.MapClaims{
			"iss": Issuer, "sub": acct.ID, "aud": app.ClientID,
			"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "auth_time": authTime.Unix(),
		}
		if nonce != "" {
			idClaims["nonce"] = nonce
		}
		if sessionID != "" {
			idClaims["sid"] = sessionID
		}
		names, _ := db.GetScopeClaims(scopes)
		for k, v := range buildClaims(acct, names) {
			if _, exists := idClaims[k]; !exists {
				idClaims[k] = v
			}
		}
		idToken, err := signingKeys.Sign(idClaims, "")
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		resp["id_token"] = idToken
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	if sessionID != "" {
		db.TrackSessionApp(sessionID, app.ID) // so back-channel logout knows to notify this app
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	RespondWithJSON(w, http.StatusOK, resp)
}

// buildClaims turns an account into OIDC claims, limited to the claim names the granted scopes allow.
func buildClaims(a db.Account, allowed []string) map[string]any {
	want := map[string]bool{}
	for _, c := range allowed {
		want[c] = true
	}
	c := map[string]any{"sub": a.ID}
	str := func(name, v string) {
		if want[name] && v != "" {
			c[name] = v
		}
	}
	str("name", a.DisplayName)
	str("given_name", a.GivenName)
	str("family_name", a.FamilyName)
	str("preferred_username", a.Username)
	str("picture", a.PictureURL)
	str("locale", a.Locale)
	str("zoneinfo", a.Zoneinfo)
	if want["updated_at"] {
		c["updated_at"] = a.UpdatedAt.Unix()
	}
	if want["email"] && a.Email != "" {
		c["email"] = a.Email
		if want["email_verified"] {
			c["email_verified"] = a.EmailVerified
		}
	}
	if want["phone_number"] && a.PhoneNumber != "" {
		c["phone_number"] = a.PhoneNumber
		if want["phone_number_verified"] {
			c["phone_number_verified"] = a.PhoneVerified
		}
	}
	return c
}

// ---- /userinfo --------------------------------------------------------------

func userinfo(w http.ResponseWriter, r *http.Request) {
	unauthorized := func() {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		RespondWithError(w, http.StatusUnauthorized, "invalid_token")
	}
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		unauthorized()
		return
	}
	// Same validity rules as introspection: live token, active account, session not revoked.
	info, err := db.IntrospectAccessToken(auth.HashToken(strings.TrimSpace(h[7:])), "")
	if err != nil {
		unauthorized()
		return
	}
	acct, err := db.GetAccount(info.AccountID)
	if err != nil {
		unauthorized()
		return
	}
	names, _ := db.GetScopeClaims(info.Scopes)
	w.Header().Set("Cache-Control", "no-store")
	RespondWithJSON(w, http.StatusOK, buildClaims(acct, names))
}
