package api

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"guardian/auth"
	db "guardian/database"
)

// Login throttling uses Postgres counters (shared by all replicas): failed attempts per username and per IP.
const (
	loginWindow     = 15 * time.Minute
	maxLoginPerUser = 10
	maxLoginPerIP   = 50
)

// ---- Login ------------------------------------------------------------------

func loginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	if sess, ok := sessionFromRequest(r); ok {
		if returnTo != "" {
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
		acct, _ := db.GetAccount(sess.AccountID)
		renderPage(w, http.StatusOK, "logout", page{
			Title: "Signed in", Message: "You are signed in as " + acct.Username + ".", CSRF: csrfToken(w, r),
		})
		return
	}
	renderPage(w, http.StatusOK, "login", page{Title: "Sign in", CSRF: csrfToken(w, r), ReturnTo: returnTo})
}

func loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	if !csrfValid(r) {
		renderMessage(w, http.StatusForbidden, "Request rejected", "Your form expired. Reload the page and try again.")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	returnTo := safeReturnTo(r.PostFormValue("return_to"))
	ip := clientIP(r)
	userKey := "login:user:" + strings.ToLower(username)
	ipKey := "login:ip:" + ip

	showError := func(status int, msg string) {
		renderPage(w, status, "login", page{Title: "Sign in", Error: msg, CSRF: csrfToken(w, r), ReturnTo: returnTo})
	}
	if len(username) == 0 || len(username) > 256 || len(password) == 0 || len(password) > 1024 {
		showError(http.StatusUnauthorized, "Invalid username or password.")
		return
	}
	userFails, _ := db.RateLimitCount(userKey, loginWindow)
	ipFails, _ := db.RateLimitCount(ipKey, loginWindow)
	if userFails >= maxLoginPerUser || ipFails >= maxLoginPerIP {
		rateLimited.WithLabelValues("login").Inc()
		showError(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}

	acct, hash, err := db.GetAccountByUsername(username)
	valid := false
	if err == nil && hash != "" && acct.Status == "active" {
		valid = auth.VerifyPassword(password, hash)
	} else {
		auth.DummyVerify(password) // same cost whether or not the user exists
	}
	if !valid {
		db.RateLimitHit(userKey, loginWindow)
		db.RateLimitHit(ipKey, loginWindow)
		loginsTotal.WithLabelValues("failure").Inc()
		db.Audit("login.failure", acct.ID, "", ip, map[string]any{"username": username})
		showError(http.StatusUnauthorized, "Invalid username or password.")
		return
	}

	db.RateLimitReset(userKey, loginWindow)
	loginsTotal.WithLabelValues("success").Inc()
	if _, err := startSession(w, r, acct.ID); err != nil {
		log.Println("Failed to start session:", err)
		renderMessage(w, http.StatusInternalServerError, "Something went wrong", "Please try again.")
		return
	}
	db.TouchLogin(acct.ID)
	db.Audit("login.success", acct.ID, "", ip, nil)

	dest := returnTo
	if dest == "" {
		dest = "/login"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ---- Logout (OIDC RP-initiated logout + back-channel fan-out) ----------------

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
	if !ok || claims["iss"] != Issuer {
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
	if err != nil || !contains(app.PostLogoutRedirectURIs, uri) {
		return ""
	}
	return uri
}

func finishLogout(w http.ResponseWriter, r *http.Request, redirectURI, state string) {
	if redirectURI == "" {
		renderMessage(w, http.StatusOK, "Signed out", "You have been signed out of Guardian and all connected apps.")
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		renderMessage(w, http.StatusOK, "Signed out", "You have been signed out.")
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
		log.Println("Failed to revoke session:", err)
	}
	clearSessionCookie(w)
	for _, t := range targets {
		go sendBackchannelLogout(t, sess.AccountID, sess.ID)
	}
	db.Audit("logout", sess.AccountID, "", clientIP(r), map[string]any{"apps_notified": len(targets)})
}

func logoutPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hint, clientID, uri, state := q.Get("id_token_hint"), q.Get("client_id"), q.Get("post_logout_redirect_uri"), q.Get("state")
	redirectURI := resolvePostLogoutRedirect(hint, clientID, uri)

	sess, loggedIn := sessionFromRequest(r)
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
	renderPage(w, http.StatusOK, "logout", page{
		Title: "Sign out", Message: "Sign out of Guardian? You will be signed out of all connected apps.",
		CSRF: csrfToken(w, r), IDTokenHint: hint, ClientID: clientID, PostLogoutRedirectURI: uri, State: state,
	})
}

func logoutSubmit(w http.ResponseWriter, r *http.Request) {
	if !csrfValid(r) {
		renderMessage(w, http.StatusForbidden, "Request rejected", "Your form expired. Reload the page and try again.")
		return
	}
	if sess, ok := sessionFromRequest(r); ok {
		performLogout(w, r, sess)
	}
	redirectURI := resolvePostLogoutRedirect(r.PostFormValue("id_token_hint"), r.PostFormValue("client_id"),
		r.PostFormValue("post_logout_redirect_uri"))
	finishLogout(w, r, redirectURI, r.PostFormValue("state"))
}

// sendBackchannelLogout implements OpenID Connect Back-Channel Logout 1.0: a signed logout_token
// is POSTed server-to-server to the app, which then ends its own session for that sid/sub.
// Delivery is best-effort with retries; it does not survive a Guardian restart.
func sendBackchannelLogout(t db.LogoutTarget, accountID, sessionID string) {
	jti, _ := auth.RandomToken(16)
	now := time.Now()
	token, err := signingKeys.Sign(jwt.MapClaims{
		"iss": Issuer, "aud": t.ClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": jti,
		"sub": accountID, "sid": sessionID,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}, "logout+jwt")
	if err != nil {
		log.Println("Failed to sign logout token:", err)
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
	log.Printf("Back-channel logout to %s failed after retries", t.URI)
}
