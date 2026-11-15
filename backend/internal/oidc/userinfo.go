package oidc

import (
	"net/http"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// userinfo returns the user's claims for a valid access token. Unlike an app, which checks the token's
// signature and expiry by itself, Guardian also checks live data here: the session must still be alive
// and the account active. So this is also where an app can ask "is this user still signed in?".
func userinfo(w http.ResponseWriter, r *http.Request) {
	unauthorized := func() {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.Error(w, http.StatusUnauthorized, "invalid_token")
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

	sess, err := db.GetLiveSession(sid, httpx.SessionIdleTimeout)
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
	out := BuildClaims(acct, names)
	if slices.Contains(scopes, "groups") {
		groups, err := db.AccountAppGroups(acct.ID, app.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out["groups"] = groups // as they are now, not as they were when the token was issued
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, out)
}

// parseAccessToken verifies an access token that Guardian issued: signature, expiry, issuer and the
// at+jwt type. An ID token is refused, even though it is signed with the same key.
func parseAccessToken(raw string) (jwt.MapClaims, bool) {
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, signingKeys.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(httpx.Issuer), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return nil, false
	}
	if typ, _ := tok.Header["typ"].(string); typ != accessTokenType {
		return nil, false
	}
	return claims, true
}
