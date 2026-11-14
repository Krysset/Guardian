package api

import (
	"strings"
	"time"

	"guardian/internal/auth"
	"guardian/internal/config"
)

var (
	// Issuer is the public base URL of this service, e.g. https://auth.example.com (no trailing slash).
	Issuer     string
	SessionTTL = 7 * 24 * time.Hour

	// IntrospectionURL is the cluster-internal URL services use to introspect tokens, e.g.
	// http://guardian-internal.guardian.svc:3002/introspect. Advertised in OIDC discovery when set,
	// so libraries that auto-discover it (Spring, oauth2-proxy, ...) need no extra configuration.
	IntrospectionURL string

	signingKeys       *auth.Keys
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
func Configure(cfg config.Config, keys *auth.Keys) {
	Issuer = cfg.IssuerURL
	SessionTTL = cfg.SessionTTL
	trustedProxyHops = cfg.TrustedProxyHops
	IntrospectionURL = cfg.IntrospectionURL

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
	signingKeys = keys
}
