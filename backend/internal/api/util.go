package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func contains(list []string, s string) bool { return slices.Contains(list, s) }

func subset(want, have []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

func without(list []string, s string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// decodeJSON reads a size-limited JSON body; on failure it writes the error response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return false
	}
	return true
}

// clientIP returns the caller's address. Behind an ingress/load balancer the TCP peer is the proxy, so
// with TRUSTED_PROXY_HOPS=n the address is taken n entries from the RIGHT of X-Forwarded-For (the entries
// appended by your own proxies; anything further left is client-supplied and spoofable).
func clientIP(r *http.Request) string {
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

// safeReturnTo only allows returning to our own /authorize endpoint (prevents open redirects).
func safeReturnTo(p string) string {
	if strings.HasPrefix(p, "/authorize?") {
		return p
	}
	return ""
}

// validRedirectURI: absolute, no fragment, https (http only for localhost development).
func validRedirectURI(raw string) bool {
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
