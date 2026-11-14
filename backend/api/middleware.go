package api

import (
	"context"
	"crypto/subtle"
	"net/http"

	"guardian/auth"
	db "guardian/database"
)

type contextKey string

const (
	ctxAccountID contextKey = "account_id"
	ctxSessionID contextKey = "session_id"
)

func accountID(r *http.Request) string {
	v, _ := r.Context().Value(ctxAccountID).(string)
	return v
}

// ---- Session cookie helpers -------------------------------------------------

func sessionFromRequest(r *http.Request) (db.Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return db.Session{}, false
	}
	s, err := db.GetSessionByHash(auth.HashToken(c.Value))
	if err != nil {
		return db.Session{}, false
	}
	return s, true
}

// startSession always creates a fresh session (never reuses an id, so no session fixation).
func startSession(w http.ResponseWriter, r *http.Request, accountID string) (db.Session, error) {
	token, err := auth.RandomToken(32)
	if err != nil {
		return db.Session{}, err
	}
	sess, err := db.CreateSession(accountID, auth.HashToken(token), clientIP(r), r.UserAgent(), SessionTTL)
	if err != nil {
		return db.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/",
		Expires: sess.ExpiresAt, MaxAge: int(SessionTTL.Seconds()),
		HttpOnly: true, Secure: secureCookies,
		// Lax: the cookie must be sent when an app redirects the browser to /authorize.
		SameSite: http.SameSiteLaxMode,
	})
	return sess, nil
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
	})
}

// ---- CSRF (double-submit cookie) for the HTML forms --------------------------

func csrfToken(w http.ResponseWriter, r *http.Request) string {
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

func csrfValid(r *http.Request) bool {
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
		sess, ok := sessionFromRequest(r)
		if !ok {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), ctxAccountID, sess.AccountID)
		ctx = context.WithValue(ctx, ctxSessionID, sess.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OnlyAdmin requires the built-in "admin" role.
func OnlyAdmin(next http.Handler) http.Handler {
	return Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, err := db.AccountHasRole(accountID(r), "admin")
		if err != nil {
			RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !ok {
			RespondWithError(w, http.StatusForbidden, "Forbidden")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequirePermission requires one specific permission in one app, e.g. RequirePermission("guardian", "apps.manage").
func RequirePermission(appName, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, err := db.AccountHasPermission(accountID(r), appName, permission)
			if err != nil {
				RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if !ok {
				RespondWithError(w, http.StatusForbidden, "Forbidden")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
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
				RespondWithError(w, http.StatusForbidden, "Cross-origin request blocked")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
