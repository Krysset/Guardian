package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	db "guardian/internal/store"
)

// MountOIDC registers the OIDC + login/logout endpoints at the root of the router.
func MountOIDC(r chi.Router) {
	r.Get("/.well-known/openid-configuration", discovery)
	r.Get("/jwks.json", jwks)
	r.Get("/authorize", authorize)
	r.Post("/token", tokenEndpoint)
	r.Post("/revoke", revokeEndpoint)
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
	RespondWithJSON(w, http.StatusOK, map[string]any{
		"issuer":                                     Issuer,
		"authorization_endpoint":                     Issuer + "/authorize",
		"token_endpoint":                             Issuer + "/token",
		"userinfo_endpoint":                          Issuer + "/userinfo",
		"revocation_endpoint":                        Issuer + "/revoke",
		"jwks_uri":                                   Issuer + "/jwks.json",
		"end_session_endpoint":                       Issuer + "/logout",
		"response_types_supported":                   []string{"code"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                    []string{"public"},
		"id_token_signing_alg_values_supported":      []string{"RS256"},
		"scopes_supported":                           []string{"openid", "profile", "email", "groups", "offline_access"},
		"token_endpoint_auth_methods_supported":      []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":           []string{"S256"},
		"claims_supported": []string{"sub", "name", "given_name", "family_name", "preferred_username", "picture",
			"locale", "zoneinfo", "updated_at", "email", "email_verified", "groups", "sid", "auth_time", "amr"},
		"backchannel_logout_supported":         true,
		"backchannel_logout_session_supported": true,
	})
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

	// The app's access rule: with "groups", only members of a group linked to the app may sign in to it.
	// Nobody else gets a code, so the app never has to notice and refuse them itself.
	allowed, err := db.AccountMayUseApp(sess.AccountID, req.App)
	if err != nil {
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "")
		return
	}
	if !allowed {
		db.Audit("authorize.denied", sess.AccountID, req.App.ID, clientIP(r), map[string]any{"reason": "access_rule"})
		if contains(req.Prompts, "none") {
			redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "The account has no access to this app")
			return
		}
		renderMessage(w, http.StatusForbidden, "No access to "+req.App.PrettyName,
			"Your account does not have access to "+req.App.PrettyName+". Ask an administrator to add you to a group that does.")
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

// refuse answers a token request with an OAuth error and counts it.
func refuse(w http.ResponseWriter, grant string, status int, code, desc string) {
	result := "refused"
	if status >= 500 {
		result = "error"
	}
	tokenRequests.WithLabelValues(grantLabel(grant), result).Inc()
	oauthError(w, status, code, desc)
}

// grantLabel keeps the metric's label values to a fixed set, whatever a client sends.
func grantLabel(grant string) string {
	if grant == "authorization_code" || grant == "refresh_token" || grant == "client_credentials" {
		return grant
	}
	return "other"
}

func tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		refuse(w, "", http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}
	grant := r.PostFormValue("grant_type")
	app, ok := authenticateClient(r)
	if !ok {
		refuse(w, grant, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}
	if !contains(app.GrantTypes, grant) {
		refuse(w, grant, http.StatusBadRequest, "unsupported_grant_type", "Grant type not allowed for this client")
		return
	}

	switch grant {
	case "authorization_code":
		ac, err := db.ConsumeAuthCode(auth.HashToken(r.PostFormValue("code")))
		if err != nil || ac.AppID != app.ID || ac.RedirectURI != r.PostFormValue("redirect_uri") {
			refuse(w, grant, http.StatusBadRequest, "invalid_grant", "Invalid, expired or already used code")
			return
		}
		if ac.CodeChallenge != "" && !verifyPKCE(r.PostFormValue("code_verifier"), ac.CodeChallenge) {
			refuse(w, grant, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		if issueTokens(w, grant, app, ac.AccountID, ac.SessionID, ac.Scopes, ac.Nonce, app.RefreshMode == "stable") {
			// Remember that this account has used the app, so the app may look it up later.
			if err := db.RecordAppUser(app.ID, ac.AccountID); err != nil {
				slog.Error("failed to record an app user", "error", err)
			}
		}

	case "refresh_token":
		// The refresh token itself never changes. What it returns is decided now, from live data.
		rt, err := db.GetRefreshToken(auth.HashToken(r.PostFormValue("refresh_token")), app.ID)
		if errors.Is(err, db.ErrInvalidGrant) {
			refuse(w, grant, http.StatusBadRequest, "invalid_grant", "Invalid or revoked refresh token")
			return
		}
		if err != nil {
			refuse(w, grant, http.StatusInternalServerError, "server_error", "")
			return
		}
		issueTokens(w, grant, app, rt.AccountID, rt.SessionID, rt.Scopes, "", false)

	case "client_credentials":
		issueClientToken(w, app)

	default:
		refuse(w, grant, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

// issueTokens answers a token request. It is the one place that decides whether a user may (still) have
// tokens for an app, and it decides from live data every time: the session must be alive, the account
// active, and the app's access rule satisfied. Every refresh passes through here, which is why logout,
// disabling an account and group changes reach an app within one token lifetime.
//
// The access token is a signed JWT (RFC 9068) that the app validates by itself, so apps never call
// Guardian per request. It is deliberately lean: who, for which app, which scopes and groups. Profile
// data goes into the ID token, which is issued again at every refresh, and into /userinfo.
//
// It reports whether tokens were issued.
func issueTokens(w http.ResponseWriter, grant string, app db.App, accountID, sessionID string, scopes []string,
	nonce string, newRefreshToken bool) bool {

	sess, err := db.GetLiveSession(sessionID, SessionIdleTimeout)
	if err != nil || sess.AccountID != accountID {
		refuse(w, grant, http.StatusBadRequest, "invalid_grant", "The sign-in session has ended")
		return false
	}
	acct, err := db.GetAccount(accountID)
	if err != nil || acct.Status != "active" {
		refuse(w, grant, http.StatusBadRequest, "invalid_grant", "Account is not available")
		return false
	}
	groups, err := db.AccountAppGroups(accountID, app.ID)
	if err != nil {
		refuse(w, grant, http.StatusInternalServerError, "server_error", "")
		return false
	}
	if app.AccessRule != "anyone" && len(groups) == 0 {
		refuse(w, grant, http.StatusBadRequest, "invalid_grant", "The account no longer has access to this app")
		return false
	}

	now := time.Now()
	ttl := time.Duration(app.AccessTokenTTL) * time.Second
	withGroups := contains(scopes, "groups")
	jti, err := auth.RandomToken(16)
	if err != nil {
		refuse(w, grant, http.StatusInternalServerError, "server_error", "")
		return false
	}

	accessClaims := jwt.MapClaims{
		"iss": Issuer, "sub": acct.ID, "aud": app.ClientID, "client_id": app.ClientID,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": jti,
		"scope": strings.Join(scopes, " "), "sid": sess.ID, "amr": sess.AMR,
	}
	idClaims := jwt.MapClaims{
		"iss": Issuer, "sub": acct.ID, "aud": app.ClientID,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "auth_time": sess.AuthTime.Unix(),
		"sid": sess.ID, "amr": sess.AMR,
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	if withGroups {
		accessClaims["groups"] = groups
		idClaims["groups"] = groups
	}
	names, _ := db.GetScopeClaims(scopes)
	for k, v := range buildClaims(acct, names) {
		if _, exists := idClaims[k]; !exists {
			idClaims[k] = v
		}
	}

	accessToken, err := signingKeys.Sign(accessClaims, accessTokenType)
	if err != nil {
		refuse(w, grant, http.StatusInternalServerError, "server_error", "")
		return false
	}
	idToken, err := signingKeys.Sign(idClaims, "")
	if err != nil {
		refuse(w, grant, http.StatusInternalServerError, "server_error", "")
		return false
	}
	resp := map[string]any{
		"access_token": accessToken, "token_type": "Bearer", "id_token": idToken,
		"expires_in": int(ttl.Seconds()), "scope": strings.Join(scopes, " "),
	}

	if newRefreshToken {
		refresh, err := auth.RandomToken(32)
		if err == nil {
			err = db.SaveRefreshToken(auth.HashToken(refresh), app.ID, acct.ID, sess.ID, scopes)
		}
		if err != nil {
			slog.Error("failed to save a refresh token", "error", err)
			refuse(w, grant, http.StatusInternalServerError, "server_error", "")
			return false
		}
		resp["refresh_token"] = refresh
	}
	db.TrackSessionApp(sess.ID, app.ID) // so back-channel logout knows to notify this app

	tokenRequests.WithLabelValues(grantLabel(grant), "issued").Inc()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	RespondWithJSON(w, http.StatusOK, resp)
	return true
}

// accessTokenType is the JWT "typ" of access tokens (RFC 9068). It is what keeps an ID token from being
// accepted as an access token, and the other way round.
const accessTokenType = "at+jwt"

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
	return c
}

// ---- /revoke ----------------------------------------------------------------

// revokeEndpoint implements RFC 7009 for refresh tokens: an app ends its own refresh token, for example
// when the user signs out of the app only. Access tokens are not stored and cannot be revoked one by one;
// they expire within the app's token lifetime. As the RFC asks, the answer is 200 whether or not the token
// was known, so the endpoint cannot be used to test tokens.
func revokeEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}
	app, ok := authenticateClient(r)
	if !ok || app.ClientType != "confidential" {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}
	token := r.PostFormValue("token")
	if token == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	revoked, err := db.RevokeRefreshToken(auth.HashToken(token), app.ID)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if revoked {
		db.Audit("token.revoked", "", app.ID, clientIP(r), nil)
	}
	w.WriteHeader(http.StatusOK)
}

// ---- /userinfo --------------------------------------------------------------

// userinfo returns the user's claims for a valid access token. Unlike an app, which checks the token's
// signature and expiry by itself, Guardian also checks live data here: the session must still be alive
// and the account active. So this is also where an app can ask "is this user still signed in?".
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
	claims, ok := parseAccessToken(strings.TrimSpace(h[7:]))
	if !ok {
		unauthorized()
		return
	}
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	clientID, _ := claims["client_id"].(string)
	scope, _ := claims["scope"].(string)

	sess, err := db.GetLiveSession(sid, SessionIdleTimeout)
	if err != nil || sess.AccountID != sub {
		unauthorized()
		return
	}
	acct, err := db.GetAccount(sub)
	if err != nil || acct.Status != "active" {
		unauthorized()
		return
	}
	app, err := db.GetAppByClientID(clientID)
	if err != nil || !app.Enabled {
		unauthorized()
		return
	}
	scopes := strings.Fields(scope)
	names, _ := db.GetScopeClaims(scopes)
	out := buildClaims(acct, names)
	if contains(scopes, "groups") {
		groups, err := db.AccountAppGroups(acct.ID, app.ID)
		if err != nil {
			RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out["groups"] = groups // as they are now, not as they were when the token was issued
	}
	w.Header().Set("Cache-Control", "no-store")
	RespondWithJSON(w, http.StatusOK, out)
}

// parseAccessToken verifies an access token that Guardian issued: signature, expiry, issuer and the
// at+jwt type. An ID token is refused, even though it is signed with the same key.
func parseAccessToken(raw string) (jwt.MapClaims, bool) {
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, signingKeys.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(Issuer), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return nil, false
	}
	if typ, _ := tok.Header["typ"].(string); typ != accessTokenType {
		return nil, false
	}
	return claims, true
}
