// Package oidc implements the OpenID Connect provider: discovery and keys, /authorize and consent,
// /token (authorization_code, refresh_token, client_credentials), /revoke, /userinfo, RP-initiated logout
// and back-channel logout. It decides from live data, at every token request, whether a user may
// (still) have tokens for an app.
package oidc

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"guardian/internal/auth"
	"guardian/internal/httpx"
)

// signingKeys sign and verify every token Guardian issues.
var signingKeys *auth.Keys

// SetKeys must be called once at startup, before serving.
func SetKeys(keys *auth.Keys) { signingKeys = keys }

// Token endpoint answers, and sign-ins to apps, per app. The app label is the app's name, which never
// changes; a client id nobody registered is "unknown", so made-up values never become labels. Refreshes
// are the steady load: one per signed-in user per app per token lifetime.
var (
	tokensIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "tokens_issued_total",
		Help: "Tokens issued by the token endpoint, by app and grant (authorization_code, refresh_token, client_credentials).",
	}, []string{"app", "grant"})
	tokenRefusals = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "token_refusals_total",
		Help: "Token requests not answered with tokens, by app, grant and reason. Expected: session_ended, " +
			"account_unavailable, access_lost. Worth a look: wrong_secret, unknown_client, unknown_refresh_token, " +
			"bad_code, pkce_failed. Guardian's fault: server_error.",
	}, []string{"app", "grant", "reason"})
	appSignins = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "app_signins_total",
		Help: "Sign-ins to an app: authorization codes given to it, with a sign-in or with single sign-on.",
	}, []string{"app"})
	appAccessDenied = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "app_access_denied_total",
		Help: "Sign-ins to an app refused because the account is not in any of the app's groups. Losing access " +
			"while signed in shows as guardian_token_refusals_total{reason=\"access_lost\"}.",
	}, []string{"app"})
)

// Mount registers the OIDC endpoints at the root of the router.
func Mount(r chi.Router) {
	r.Get("/.well-known/openid-configuration", discovery)
	r.Get("/jwks.json", jwks)
	r.Get("/authorize", authorize)
	r.Post("/consent", consentSubmit)
	r.Post("/token", tokenEndpoint)
	r.Post("/revoke", revokeEndpoint)
	r.Get("/userinfo", userinfo)
	r.Post("/userinfo", userinfo)
	r.Get("/logout", logoutPage)
	r.Post("/logout", logoutSubmit)
}

func discovery(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{
		"issuer":                                     httpx.Issuer,
		"authorization_endpoint":                     httpx.Issuer + "/authorize",
		"token_endpoint":                             httpx.Issuer + "/token",
		"userinfo_endpoint":                          httpx.Issuer + "/userinfo",
		"revocation_endpoint":                        httpx.Issuer + "/revoke",
		"jwks_uri":                                   httpx.Issuer + "/jwks.json",
		"end_session_endpoint":                       httpx.Issuer + "/logout",
		"response_types_supported":                   []string{"code"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                    []string{"public"},
		"id_token_signing_alg_values_supported":      []string{"RS256"},
		"scopes_supported":                           []string{"openid", "profile", "email", "groups", "offline_access"},
		"token_endpoint_auth_methods_supported":      []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":           []string{"S256"},
		"claims_supported": []string{"sub", "name", "given_name", "family_name", "preferred_username", "picture",
			"locale", "zoneinfo", "updated_at", "email", "email_verified", "groups", "sid", "auth_time", "amr"},
		"backchannel_logout_supported":         true,
		"backchannel_logout_session_supported": true,
	})
}

func jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// A new key is published an hour before it signs, so apps that cache this for 15 minutes always
	// know it in time.
	w.Header().Set("Cache-Control", "public, max-age=900")
	w.Write(signingKeys.JWKS())
}

// subset reports whether every value of want is in have.
func subset(want, have []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// without returns a copy of list without s.
func without(list []string, s string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// union returns a, followed by the values of b that a lacks.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
