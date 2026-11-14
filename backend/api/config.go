package api

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"guardian/auth"
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

// Configure must be called once at startup, before serving.
func Configure(keys *auth.Keys) error {
	Issuer = strings.TrimRight(os.Getenv("ISSUER_URL"), "/")
	if Issuer == "" {
		return errors.New("ISSUER_URL is not set (e.g. https://auth.example.com or http://localhost:3001 for dev)")
	}
	if v := os.Getenv("SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return fmt.Errorf("SESSION_TTL must be a Go duration like 168h: %v", err)
		}
		SessionTTL = d
	}
	if v := os.Getenv("TRUSTED_PROXY_HOPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return errors.New("TRUSTED_PROXY_HOPS must be a non-negative integer")
		}
		trustedProxyHops = n
	}
	allowedOrigins[Issuer] = true
	for _, o := range strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			allowedOrigins[o] = true
		}
	}
	IntrospectionURL = os.Getenv("INTROSPECTION_URL")
	secureCookies = strings.HasPrefix(Issuer, "https://")
	if secureCookies {
		// __Host- prefix: browser enforces Secure, Path=/ and no Domain attribute.
		sessionCookieName = "__Host-guardian_session"
		csrfCookieName = "__Host-guardian_csrf"
	}
	signingKeys = keys
	return nil
}
