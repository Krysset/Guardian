package oidc

import (
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	"guardian/internal/httpx"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// OIDC RP-initiated logout (/logout) and the back-channel logout fan-out.

// parseIDTokenHint accepts an ID token we issued, even if it has expired (that is what the spec wants).
func parseIDTokenHint(hint string) (jwt.MapClaims, bool) {
	if hint == "" {
		return nil, false
	}
	tok, err := jwt.Parse(hint, signingKeys.Keyfunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	if err != nil || !tok.Valid {
		return nil, false
	}
	if typ, _ := tok.Header["typ"].(string); typ != "" && typ != "JWT" {
		return nil, false // reject access tokens / logout tokens used as hints
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || claims["iss"] != httpx.Issuer {
		return nil, false
	}
	return claims, true
}

// resolvePostLogoutRedirect returns uri only if it is registered for the client identified by the hint / client_id.
func resolvePostLogoutRedirect(hint, clientID, uri string) string {
	if uri == "" {
		return ""
	}
	cid := clientID
	if claims, ok := parseIDTokenHint(hint); ok {
		if aud, err := claims.GetAudience(); err == nil && len(aud) > 0 {
			if cid != "" && cid != aud[0] {
				return ""
			}
			cid = aud[0]
		}
	}
	if cid == "" {
		return ""
	}
	app, err := db.GetAppByClientID(cid)
	if err != nil || !slices.Contains(app.PostLogoutRedirectURIs, uri) {
		return ""
	}
	return uri
}

func finishLogout(w http.ResponseWriter, r *http.Request, redirectURI, state string) {
	if redirectURI == "" {
		web.Message(w, http.StatusOK, "Signed out", "You have been signed out of Guardian and all connected apps.")
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		web.Message(w, http.StatusOK, "Signed out", "You have been signed out.")
		return
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func performLogout(w http.ResponseWriter, r *http.Request, sess db.Session) {
	targets, err := db.RevokeSession(sess.ID)
	if err != nil {
		slog.Error("failed to revoke a session", "error", err)
	}
	httpx.ClearSessionCookie(w)
	for _, t := range targets {
		go sendBackchannelLogout(t, sess.AccountID, sess.ID)
	}
	db.Audit("logout", sess.AccountID, "", httpx.ClientIP(r), map[string]any{"apps_notified": len(targets)})
}

func logoutPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hint, clientID, uri, state := q.Get("id_token_hint"), q.Get("client_id"), q.Get("post_logout_redirect_uri"), q.Get("state")
	redirectURI := resolvePostLogoutRedirect(hint, clientID, uri)

	sess, loggedIn := httpx.SessionFromRequest(r)
	if !loggedIn {
		finishLogout(w, r, redirectURI, state)
		return
	}
	// A valid ID token for THIS user proves the request comes from an app they use: skip the confirmation.
	if claims, ok := parseIDTokenHint(hint); ok {
		if sub, _ := claims["sub"].(string); sub == sess.AccountID {
			performLogout(w, r, sess)
			finishLogout(w, r, redirectURI, state)
			return
		}
	}
	web.Render(w, http.StatusOK, "logout", web.Page{
		Title: "Sign out", Message: "Sign out of Guardian? You will be signed out of all connected apps.",
		CSRF: httpx.CSRFToken(w, r), IDTokenHint: hint, ClientID: clientID, PostLogoutRedirectURI: uri, State: state,
	})
}

func logoutSubmit(w http.ResponseWriter, r *http.Request) {
	if !httpx.CSRFValid(r) {
		web.Message(w, http.StatusForbidden, "Request rejected", "Your form expired. Reload the page and try again.")
		return
	}
	if sess, ok := httpx.SessionFromRequest(r); ok {
		performLogout(w, r, sess)
	}
	redirectURI := resolvePostLogoutRedirect(r.PostFormValue("id_token_hint"), r.PostFormValue("client_id"),
		r.PostFormValue("post_logout_redirect_uri"))
	finishLogout(w, r, redirectURI, r.PostFormValue("state"))
}

// SendLogoutNotices sends each back-channel logout in the background.
func SendLogoutNotices(notices []db.LogoutNotice) {
	for _, n := range notices {
		go sendBackchannelLogout(n.LogoutTarget, n.AccountID, n.SessionID)
	}
}

// sendBackchannelLogout implements OpenID Connect Back-Channel Logout 1.0: a signed logout_token
// is POSTed server-to-server to the app, which then ends its own session for that sid/sub.
// Delivery is best-effort with retries; it does not survive a Guardian restart.
func sendBackchannelLogout(t db.LogoutTarget, accountID, sessionID string) {
	jti, _ := auth.RandomToken(16)
	now := time.Now()
	token, err := signingKeys.Sign(jwt.MapClaims{
		"iss": httpx.Issuer, "aud": t.ClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": jti,
		"sub": accountID, "sid": sessionID,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}, "logout+jwt")
	if err != nil {
		slog.Error("failed to sign a logout token", "error", err)
		return
	}
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt*2) * time.Second)
		}
		resp, err := client.PostForm(t.URI, url.Values{"logout_token": {token}})
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
		}
	}
	slog.Warn("back-channel logout failed after retries", "uri", t.URI)
}
