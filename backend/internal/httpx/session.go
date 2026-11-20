package httpx

import (
	"context"
	"crypto/subtle"
	"net/http"
	"slices"
	"time"

	"guardian/internal/auth"
	db "guardian/internal/store"
)

type contextKey string

const (
	ctxAccountID contextKey = "account_id"
	ctxSessionID contextKey = "session_id"
	ctxAuthTime  contextKey = "auth_time"
	ctxAMR       contextKey = "amr"
)

// ReauthWindow is how long after signing in, or confirming who they are again, a user may make protected
// changes: username, email, password, two-factor, recovery codes, sessions, connected apps and deleting the
// account. After it, those changes answer 403 reauth_required until POST /api/v1/me/reauth.
const ReauthWindow = 5 * time.Minute

// AccountID is the signed-in account of a request that passed Authenticate.
func AccountID(r *http.Request) string {
	v, _ := r.Context().Value(ctxAccountID).(string)
	return v
}

// SessionID is the session of a request that passed Authenticate.
func SessionID(r *http.Request) string {
	v, _ := r.Context().Value(ctxSessionID).(string)
	return v
}

// ---- Session cookie helpers -------------------------------------------------

// SessionFromRequest returns the live session of the request's session cookie, if any.
func SessionFromRequest(r *http.Request) (db.Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return db.Session{}, false
	}
	s, err := db.GetSessionByHash(auth.HashToken(c.Value), SessionIdleTimeout)
	if err != nil {
		return db.Session{}, false
	}
	return s, true
}

// StartSession always creates a fresh session (never reuses an id, so no session fixation).
func StartSession(w http.ResponseWriter, r *http.Request, accountID string, amr ...string) (db.Session, error) {
	token, err := auth.RandomToken(32)
	if err != nil {
		return db.Session{}, err
	}
	sess, err := db.CreateSession(accountID, auth.HashToken(token), ClientIP(r), r.UserAgent(), SessionMaxLifetime, amr...)
	if err != nil {
		return db.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/",
		Expires: sess.ExpiresAt, MaxAge: int(SessionMaxLifetime.Seconds()),
		HttpOnly: true, Secure: secureCookies,
		// Lax: the cookie must be sent when an app redirects the browser to /authorize.
		SameSite: http.SameSiteLaxMode,
	})
	return sess, nil
}

// ClearSessionCookie removes the session cookie from the browser.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
	})
}

// ---- CSRF (double-submit cookie) for the HTML forms --------------------------

// CSRFToken returns the form token, setting the CSRF cookie the first time.
func CSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	t, _ := auth.RandomToken(32)
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: t, Path: "/",
		HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
	})
	return t
}

// CSRFValid reports whether a posted form carries the token of its CSRF cookie.
func CSRFValid(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || len(c.Value) < 32 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) == 1
}

// ---- Middleware for the JSON API --------------------------------------------

// Authenticate requires a valid SSO session cookie and puts the account id in the request context.
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := SessionFromRequest(r)
		if !ok {
			Error(w, http.StatusUnauthorized, "Sign in first")
			return
		}
		ctx := context.WithValue(r.Context(), ctxAccountID, sess.AccountID)
		ctx = context.WithValue(ctx, ctxSessionID, sess.ID)
		ctx = context.WithValue(ctx, ctxAuthTime, sess.AuthTime)
		ctx = context.WithValue(ctx, ctxAMR, sess.AMR)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RecentlyAuthenticated reports whether the request's session proved who its user is within ReauthWindow.
func RecentlyAuthenticated(r *http.Request) bool {
	t, ok := r.Context().Value(ctxAuthTime).(time.Time)
	return ok && time.Since(t) < ReauthWindow
}

// RequireReauth answers 403 reauth_required, and returns false, unless the session proved who its user is
// within ReauthWindow. Handlers of protected changes call it before changing anything.
func RequireReauth(w http.ResponseWriter, r *http.Request) bool {
	if RecentlyAuthenticated(r) {
		return true
	}
	ErrorCode(w, http.StatusForbidden, "reauth_required",
		"Confirm it is you first: send your password to POST /api/v1/me/reauth, then try again")
	return false
}

// PassedMFA reports whether the request's session signed in, or stepped up, with two-factor.
func PassedMFA(r *http.Request) bool {
	amr, _ := r.Context().Value(ctxAMR).([]string)
	return slices.Contains(amr, "otp")
}

// RequireMFASession answers 403 mfa_required, and returns false, unless the session passed two-factor.
// Administrators and group owners must use two-factor; a session from before they set it up (or before
// they became one) cannot use their rights until they sign in again.
func RequireMFASession(w http.ResponseWriter, r *http.Request) bool {
	if PassedMFA(r) {
		return true
	}
	ErrorCode(w, http.StatusForbidden, "mfa_required", "Sign in again with two-factor to do this")
	return false
}

// RequireAdmin requires a signed-in member of the built-in guardian-admins group.
func RequireAdmin(next http.Handler) http.Handler {
	return Authenticate(AdminOnly(next))
}

// AdminOnly is RequireAdmin for routes that Authenticate already protects.
func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, err := db.IsAdmin(AccountID(r))
		if err != nil {
			Error(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !ok {
			Error(w, http.StatusForbidden, "Your account may not do this")
			return
		}
		if !RequireMFASession(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSameOrigin blocks cross-site browser requests to the JSON API (CSRF defence, together with the
// SameSite=Lax session cookie). Browsers always send Origin on cross-origin and on POST requests; only
// origins listed in ISSUER_URL / ALLOWED_ORIGINS may change state. Requests without an Origin header
// (curl, service code) are not browser-driven and cannot ride a victim's cookie.
func RequireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if origin := r.Header.Get("Origin"); origin != "" && !allowedOrigins[origin] {
				Error(w, http.StatusForbidden, "Cross-origin request blocked")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- Short-lived cookies for multi-step flows -------------------------------

// FlowCookieName is the cookie's name: name, with the __Host- prefix when cookies are Secure.
func FlowCookieName(name string) string {
	if secureCookies {
		return "__Host-" + name
	}
	return name
}

// SetFlowCookie sets a short-lived cookie that ties a step of a flow (such as a sign-up waiting for its
// email confirmation) to this browser.
func SetFlowCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: FlowCookieName(name), Value: value, Path: "/", MaxAge: int(maxAge.Seconds()),
		HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
	})
}

// FlowCookie returns the value of a flow cookie, or "".
func FlowCookie(r *http.Request, name string) string {
	if c, err := r.Cookie(FlowCookieName(name)); err == nil {
		return c.Value
	}
	return ""
}

// ClearFlowCookie removes a flow cookie.
func ClearFlowCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: FlowCookieName(name), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
	})
}
