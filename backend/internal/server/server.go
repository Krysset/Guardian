// Package server wires Guardian together: it opens the database, loads the signing keys, builds the two
// HTTP routers and runs them until the context is cancelled.
package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"guardian/internal/api"
	"guardian/internal/auth"
	"guardian/internal/config"
	"guardian/internal/httpx"
	"guardian/internal/internalapi"
	"guardian/internal/mail"
	"guardian/internal/oidc"
	"guardian/internal/passkey"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// Migrate connects to the database, applies pending migrations and returns. It backs "guardian migrate",
// for deployments that run migrations as a separate job. Starting the server does the same thing first.
func Migrate(ctx context.Context, cfg config.Config) error {
	cfg.DB.Migrate = "startup" // this command is what applies them
	_, err := db.Open(ctx, cfg.DB)
	return err
}

// Run starts Guardian and blocks until ctx is cancelled or a listener fails.
func Run(ctx context.Context, cfg config.Config) error {
	// Connect and apply pending migrations up front. This waits for the database, until ctx is cancelled.
	if _, err := db.Open(ctx, cfg.DB); err != nil {
		return err
	}

	if err := UseKeyring(cfg); err != nil {
		return err
	}
	keys, err := auth.LoadKeys()
	if err != nil {
		return fmt.Errorf("load signing keys: %w", err)
	}
	schedule := auth.DefaultSchedule
	schedule.Lifetime = cfg.SigningKeyLifetime
	auth.MaintainKeys(keys, schedule, cfg.KeyringFile) // re-encrypts and sets the metrics at once
	auth.RunKeyMaintenance(ctx, keys, schedule, cfg.KeyringFile)
	Configure(cfg, keys)
	if m := cfg.Mail; m.Enabled() {
		mail.Configure(mail.SMTP{Host: m.Host, Port: m.Port, Username: m.Username, Password: m.Password,
			Security: m.Security, From: *m.From}, mail.Site{Name: m.From.Name, Host: issuerHost(cfg.IssuerURL)})
	} else {
		slog.Warn("email is off (no SMTP_HOST): sign-up has no email field and only administrators can reset passwords")
	}
	if err := BootstrapAdmin(cfg.AdminInitialPassword); err != nil {
		return err
	}
	httpx.RegisterDBMetrics(schedule.Lifetime)
	db.StartMaintenance(ctx)
	web.StartSummaries(ctx)

	// Two listeners: the public one goes through the ingress; the internal one (metrics and probes) is only exposed as a ClusterIP Service and protected by a NetworkPolicy.
	public := newServer(cfg.PublicAddr, PublicRouter())
	internal := newServer(cfg.InternalAddr, InternalRouter())

	errs := make(chan error, 2)
	go func() { errs <- public.ListenAndServe() }()
	go func() { errs <- internal.ListenAndServe() }()
	slog.Info("Guardian ready", "version", Version, "public", public.Addr, "internal", internal.Addr, "issuer", httpx.Issuer)

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("listener failed: %w", err)
		}
	}
	// Kubernetes sends SIGTERM on rollouts. In this order:
	//  1. readiness fails, and new requests keep being served for DrainDelay while load balancers and
	//     kube-proxy notice the pod is going (they take a few seconds);
	//  2. the listeners stop taking connections, and requests in flight get up to 15 seconds to finish;
	//  3. emails still queued get up to 10 seconds to go out (a reset link must not be lost).
	// The chart's terminationGracePeriodSeconds (45) covers all three.
	internalapi.Drain()
	if runErr == nil && DrainDelay > 0 {
		slog.Info("draining before shutdown", "delay", DrainDelay.String())
		time.Sleep(DrainDelay)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := public.Shutdown(shutdownCtx); err != nil {
		slog.Warn("requests were still running when the public listener stopped", "error", err)
	}
	internal.Shutdown(shutdownCtx)
	mailCtx, cancelMail := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelMail()
	if err := mail.Wait(mailCtx); err != nil {
		slog.Warn("emails were still queued at shutdown and are lost", "error", err)
	}
	slog.Info("stopped")
	return runErr
}

// DrainDelay is how long Guardian keeps serving after SIGTERM, with readiness failing, before it stops
// taking connections.
var DrainDelay = 5 * time.Second

// UseKeyring parses the configured keyring and makes it the encryption keyring. It refuses one that lacks
// a key the stored values need: Guardian would fail to decrypt its signing keys or authenticator apps.
func UseKeyring(cfg config.Config) error {
	ring, err := auth.ParseKeyring(cfg.Keyring)
	if err != nil {
		return fmt.Errorf("the encryption keyring: %w", err)
	}
	if err := auth.CheckKeyring(ring); err != nil {
		return err
	}
	auth.SetKeyring(ring)
	return nil
}

// Version is the release this binary was built from, set by the release build
// (-ldflags "-X guardian/internal/server.Version=1.2.3"); "dev" otherwise. /metrics shows it as
// guardian_build_info{version}.
var Version = "dev"

var buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "guardian", Name: "build_info", Help: "Always 1; the version label says which release is running.",
}, []string{"version"})

func init() { buildInfo.WithLabelValues(Version).Set(1) }

// Configure hands the validated configuration and the signing keys to the HTTP packages. It must be
// called once before serving; tests that build the routers call it too.
func Configure(cfg config.Config, keys *auth.Keys) {
	httpx.Configure(cfg)
	web.Configure(cfg)
	if err := passkey.Configure(cfg.IssuerURL, cfg.AllowedOrigins, "Guardian"); err != nil {
		slog.Error("security keys and passkeys are off", "error", err)
	}
	db.DeletionGrace = cfg.DeletionGrace
	db.AuditRetention = cfg.AuditRetention
	oidc.SetKeys(keys)
	web.SendLogoutNotices = oidc.SendLogoutNotices
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

// PublicRouter serves browsers and apps: sign-in pages, the OIDC endpoints and /api/v1.
func PublicRouter() http.Handler {
	r := chi.NewRouter()
	// No request logger on purpose: it would log authorization codes found in query strings.
	r.Use(middleware.Recoverer, httpx.Metrics("public"))
	oidc.Mount(r) // /authorize /consent /token /revoke /userinfo /logout /jwks.json /.well-known/...
	web.Mount(r)  // / /login /signup /password /static/
	r.Mount("/api/v1", api.Router())
	r.NotFound(web.NotFoundHandler)
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

func issuerHost(issuer string) string {
	if u, err := url.Parse(issuer); err == nil {
		return u.Host
	}
	return ""
}
