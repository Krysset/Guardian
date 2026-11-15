// Package server wires Guardian together: it opens the database, loads the signing keys, builds the two
// HTTP routers and runs them until the context is cancelled.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"guardian/internal/api"
	"guardian/internal/auth"
	"guardian/internal/config"
	"guardian/internal/httpx"
	"guardian/internal/internalapi"
	"guardian/internal/oidc"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// Migrate connects to the database, applies pending migrations and returns. It backs "guardian migrate",
// for deployments that run migrations as a separate job. Starting the server does the same thing first.
func Migrate(ctx context.Context, cfg config.Config) error {
	_, err := db.Open(ctx, cfg.DB)
	return err
}

// Run starts Guardian and blocks until ctx is cancelled or a listener fails.
func Run(ctx context.Context, cfg config.Config) error {
	// Connect and apply pending migrations up front. This waits for the database, until ctx is cancelled.
	if _, err := db.Open(ctx, cfg.DB); err != nil {
		return err
	}

	if err := auth.SetEncryptionKey(cfg.KeyEncryptionKey); err != nil {
		return err
	}
	keys, err := auth.LoadKeys()
	if err != nil {
		return fmt.Errorf("load signing keys: %w", err)
	}
	Configure(cfg, keys)
	if err := BootstrapAdmin(cfg.AdminInitialPassword); err != nil {
		return err
	}
	httpx.RegisterDBMetrics()
	db.StartMaintenance(ctx)

	// Two listeners: the public one goes through the ingress; the internal one (metrics and probes) is only exposed as a ClusterIP Service and protected by a NetworkPolicy.
	public := newServer(cfg.PublicAddr, PublicRouter())
	internal := newServer(cfg.InternalAddr, InternalRouter())

	errs := make(chan error, 2)
	go func() { errs <- public.ListenAndServe() }()
	go func() { errs <- internal.ListenAndServe() }()
	slog.Info("Guardian ready", "public", public.Addr, "internal", internal.Addr, "issuer", httpx.Issuer)

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("listener failed: %w", err)
		}
	}
	// Kubernetes sends SIGTERM on rollouts: finish in-flight requests before exiting.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	public.Shutdown(shutdownCtx)
	internal.Shutdown(shutdownCtx)
	return runErr
}

// Configure hands the validated configuration and the signing keys to the HTTP packages. It must be
// called once before serving; tests that build the routers call it too.
func Configure(cfg config.Config, keys *auth.Keys) {
	httpx.Configure(cfg)
	oidc.SetKeys(keys)
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// PublicRouter serves browsers and apps: hosted pages, the OIDC endpoints and /api/v1.
func PublicRouter() http.Handler {
	r := chi.NewRouter()
	// No request logger on purpose: it would log authorization codes found in query strings.
	r.Use(middleware.Recoverer, httpx.Metrics("public"))
	oidc.Mount(r) // /authorize /consent /token /revoke /userinfo /logout /jwks.json /.well-known/...
	web.Mount(r)  // /login
	r.Mount("/api/v1", api.Router())
	return r
}

// InternalRouter serves /metrics, /healthz and /readyz. It must only be reachable in the cluster.
func InternalRouter() http.Handler {
	return internalapi.Router()
}

// BootstrapAdmin gives the seeded admin account its first password (the schema script can't hash one).
// It uses the given password, or generates one and logs it once. It does nothing once the admin has a password.
func BootstrapAdmin(password string) error {
	generated := false
	if password == "" {
		p, err := auth.RandomToken(18)
		if err != nil {
			return err
		}
		password, generated = p, true
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	set, err := db.SetAdminPasswordIfUnset(hash)
	if err != nil {
		return fmt.Errorf("set the initial admin password: %w", err)
	}
	if set && generated {
		// Logged on purpose, once: there is no other way to learn a generated password.
		slog.Warn("initial admin password generated; it is shown only once, change it after signing in", "password", password)
	}
	return nil
}
