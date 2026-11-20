package httpx

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ClientIP returns the caller's address. Behind an ingress/load balancer the TCP peer is the proxy, so
// with TRUSTED_PROXY_HOPS=n the address is taken n entries from the RIGHT of X-Forwarded-For (the entries
// appended by your own proxies; anything further left is client-supplied and spoofable).
func ClientIP(r *http.Request) string {
	if trustedProxyHops > 0 {
		parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		if n := len(parts); n >= trustedProxyHops {
			if ip := net.ParseIP(strings.TrimSpace(parts[n-trustedProxyHops])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil {
		return ""
	}
	return host
}

// SafeReturnTo only allows returning to our own /authorize endpoint or to a page of the management UI
// (/account and /admin, with their pages and query strings); anything else is dropped, which prevents open
// redirects.
func SafeReturnTo(p string) string {
	if strings.HasPrefix(p, "/authorize?") {
		return p
	}
	for _, area := range []string{"/account", "/admin"} {
		rest, ok := strings.CutPrefix(p, area)
		if !ok || (rest != "" && rest[0] != '/' && rest[0] != '?') {
			continue
		}
		// The path stays on this origin: no "//", no backslashes, no "..", only printable ASCII.
		path, _, _ := strings.Cut(rest, "?")
		if strings.Contains(path, "//") || strings.Contains(path, "..") || strings.ContainsAny(p, "\\#") {
			return ""
		}
		for _, c := range p {
			if c <= ' ' || c > '~' {
				return ""
			}
		}
		return p
	}
	return ""
}

// ValidRedirectURI: absolute, no fragment, https (http only for localhost development).
func ValidRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	return u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")
}
