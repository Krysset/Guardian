package oidc

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// Client tokens come from the client_credentials grant: an app gets a token for itself, to call
// Guardian's machine API without a user. Their audience is Guardian itself, so a user's access token
// (whose audience is the app) is never accepted where a client token is expected, and the other way round.

// clientTokenAudience is the audience of client tokens: they are for Guardian's own API.
func clientTokenAudience() string { return httpx.Issuer }

// issueClientToken answers a client_credentials request.
func issueClientToken(w http.ResponseWriter, app db.App) {
	const grant = "client_credentials"
	if app.ClientType != "confidential" {
		refuse(w, app.Name, grant, "public_client", http.StatusUnauthorized, "invalid_client", "Only apps with a secret can get tokens of their own")
		return
	}
	jti, err := auth.RandomToken(16)
	if err != nil {
		refuse(w, app.Name, grant, "server_error", http.StatusInternalServerError, "server_error", "")
		return
	}
	now := time.Now()
	ttl := time.Duration(app.AccessTokenTTL) * time.Second
	token, err := signingKeys.Sign(app.SigningAlg, jwt.MapClaims{
		"iss": httpx.Issuer, "sub": app.ClientID, "aud": clientTokenAudience(), "client_id": app.ClientID,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": jti,
	}, accessTokenType)
	if err != nil {
		refuse(w, app.Name, grant, "server_error", http.StatusInternalServerError, "server_error", "")
		return
	}
	tokensIssued.WithLabelValues(app.Name, grant).Inc()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"access_token": token, "token_type": "Bearer", "expires_in": int(ttl.Seconds()),
	})
}

// VerifyClientToken checks a Bearer Authorization header holding a client token: signature, expiry,
// issuer, audience and the at+jwt type, and that it was issued to an app for itself, never for a user.
// It returns the app's client id. Whether that app may still use the machine API is for the caller to
// check, against live data.
func VerifyClientToken(authorization string) (clientID string, ok bool) {
	if len(authorization) < 8 || !strings.EqualFold(authorization[:7], "bearer ") {
		return "", false
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(strings.TrimSpace(authorization[7:]), claims, signingKeys.Keyfunc,
		jwt.WithValidMethods(auth.Algorithms), jwt.WithIssuer(httpx.Issuer), jwt.WithAudience(clientTokenAudience()),
		jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return "", false
	}
	if typ, _ := tok.Header["typ"].(string); typ != accessTokenType {
		return "", false
	}
	clientID, _ = claims["client_id"].(string)
	if sub, _ := claims["sub"].(string); sub != clientID || clientID == "" || claims["sid"] != nil {
		return "", false
	}
	return clientID, true
}
