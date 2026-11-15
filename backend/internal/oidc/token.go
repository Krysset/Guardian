package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="guardian"`)
	}
	httpx.JSON(w, status, map[string]string{"error": code, "error_description": desc})
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
	if !slices.Contains(app.GrantTypes, grant) {
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

	sess, err := db.GetLiveSession(sessionID, httpx.SessionIdleTimeout)
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
	withGroups := slices.Contains(scopes, "groups")
	jti, err := auth.RandomToken(16)
	if err != nil {
		refuse(w, grant, http.StatusInternalServerError, "server_error", "")
		return false
	}

	accessClaims := jwt.MapClaims{
		"iss": httpx.Issuer, "sub": acct.ID, "aud": app.ClientID, "client_id": app.ClientID,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": jti,
		"scope": strings.Join(scopes, " "), "sid": sess.ID, "amr": sess.AMR,
	}
	idClaims := jwt.MapClaims{
		"iss": httpx.Issuer, "sub": acct.ID, "aud": app.ClientID,
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
	for k, v := range BuildClaims(acct, names) {
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
	httpx.JSON(w, http.StatusOK, resp)
	return true
}

// accessTokenType is the JWT "typ" of access tokens (RFC 9068). It is what keeps an ID token from being
// accepted as an access token, and the other way round.
const accessTokenType = "at+jwt"

// BuildClaims turns an account into OIDC claims, limited to the claim names the granted scopes allow.
func BuildClaims(a db.Account, allowed []string) map[string]any {
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
		db.Audit("token.revoked", "", app.ID, httpx.ClientIP(r), nil)
	}
	w.WriteHeader(http.StatusOK)
}
