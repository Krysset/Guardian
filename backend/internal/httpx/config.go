// Package httpx holds what the HTTP packages (oidc, web, api, internalapi) share: the settings they read,
// JSON responses, request helpers, the session cookie and CSRF protection, and request metrics.
package httpx

import (
	"strings"
	"time"

	"guardian/internal/config"
)

var (
	// Issuer is the public base URL of this service, e.g. https://auth.example.com (no trailing slash).
	Issuer string

	// SessionIdleTimeout ends a sign-in session that has not been used for this long;
	// SessionMaxLifetime ends it this long after sign-in, however active it is.
	SessionIdleTimeout = 7 * 24 * time.Hour
	SessionMaxLifetime = 30 * 24 * time.Hour

	secureCookies     bool
	sessionCookieName = "guardian_session"
	csrfCookieName    = "guardian_csrf"

	// trustedProxyHops is how many reverse proxies (ingress, load balancer) in front of Guardian append to
	// X-Forwarded-For. 0 = ignore the header and use the TCP peer address.
	trustedProxyHops int

	// allowedOrigins are the browser origins allowed to send state-changing requests to /api.
	allowedOrigins = map[string]bool{}
)

// Configure must be called once at startup, before serving. The configuration is already validated.
func Configure(cfg config.Config) {
	Issuer = cfg.IssuerURL
	SessionIdleTimeout = cfg.SessionIdleTimeout
	SessionMaxLifetime = cfg.SessionMaxLifetime
	trustedProxyHops = cfg.TrustedProxyHops

	allowedOrigins = map[string]bool{Issuer: true}
	for _, o := range cfg.AllowedOrigins {
		allowedOrigins[o] = true
	}

	secureCookies = strings.HasPrefix(Issuer, "https://")
	sessionCookieName, csrfCookieName = "guardian_session", "guardian_csrf"
	if secureCookies {
		// __Host- prefix: browser enforces Secure, Path=/ and no Domain attribute.
		sessionCookieName = "__Host-guardian_session"
		csrfCookieName = "__Host-guardian_csrf"
	}
}
