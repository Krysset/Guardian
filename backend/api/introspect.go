package api

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"guardian/auth"
	db "guardian/database"
)

// GetInternalRouter serves the cluster-internal listener: token introspection for other services,
// Prometheus metrics and Kubernetes probes. It must never be exposed through the public ingress; a
// NetworkPolicy should restrict it to your services and Prometheus.
func GetInternalRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, Metrics("internal"))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { RespondWithSuccess(w) }) // liveness: process is up
	r.Get("/readyz", readyz)                                                                  // readiness: database reachable
	r.Handle("/metrics", promhttp.Handler())
	r.Post("/introspect", introspect)
	return r
}

func readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := db.GetDatabaseConnection().PingContext(ctx); err != nil {
		RespondWithError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	RespondWithSuccess(w)
}

// introspect implements RFC 7662. The caller authenticates as one of the registered (confidential) apps
// and gets, for the presented user access token:
//   - whether it is active RIGHT NOW (token live, account active, session not revoked, app enabled), and
//   - the permissions (and attributes of direct grants) the user holds in the CALLER's own app.
// Everything is read from Postgres on every call, so revoking a permission, logging out or disabling an
// account is visible to the very next call. Callers must therefore not cache the answer.
func introspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}
	app, ok := authenticateClient(r)
	if !ok || app.ClientType != "confidential" {
		introspections.WithLabelValues("unauthorized").Inc()
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	if token == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	info, err := db.IntrospectAccessToken(auth.HashToken(token), app.ID)
	if err == sql.ErrNoRows {
		introspections.WithLabelValues("inactive").Inc()
		RespondWithJSON(w, http.StatusOK, map[string]any{"active": false}) // RFC 7662: nothing else for inactive tokens
		return
	}
	if err != nil {
		introspections.WithLabelValues("error").Inc()
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	introspections.WithLabelValues("active").Inc()

	if info.Permissions == nil {
		info.Permissions = []string{}
	}
	resp := map[string]any{
		"active":      true,
		"sub":         info.AccountID,
		"client_id":   info.ClientID, // the app the token was issued to (may differ from the caller)
		"scope":       strings.Join(info.Scopes, " "),
		"token_type":  "Bearer",
		"iat":         info.IssuedAt.Unix(),
		"exp":         info.ExpiresAt.Unix(),
		"permissions": info.Permissions, // in the caller's app
	}
	if info.SessionID != "" {
		resp["sid"] = info.SessionID // matches the sid in back-channel logout tokens
	}
	if len(info.Attributes) > 0 && string(info.Attributes) != "{}" {
		resp["attributes"] = info.Attributes // permission name -> app-defined JSON
	}
	RespondWithJSON(w, http.StatusOK, resp)
}
