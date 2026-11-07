package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"

	api "guardian/api"
	"guardian/auth"
	db "guardian/database"
)

func main() {
	loadEnv()
	// Connect and run the schema script up front
	db.GetDatabaseConnection()

	keys, err := auth.LoadKeys()
	if err != nil {
		log.Fatalf("Failed to load signing keys: %v", err)
	}
	if err := api.Configure(keys); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	bootstrapAdmin()
	api.RegisterDBMetrics()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db.StartMaintenance(ctx)

	// Two listeners: the public one goes through the ingress; the internal one (introspection, metrics,
	// probes) is only exposed as a ClusterIP Service and protected by a NetworkPolicy.
	public := newServer(env("PUBLIC_ADDR", ":3001"), publicRouter())
	internal := newServer(env("INTERNAL_ADDR", ":3002"), api.GetInternalRouter())

	errs := make(chan error, 2)
	go func() { errs <- public.ListenAndServe() }()
	go func() { errs <- internal.ListenAndServe() }()
	log.Printf("Guardian ready: public %s, internal %s, issuer %s", public.Addr, internal.Addr, api.Issuer)

	exitCode := 0
	select {
	case <-ctx.Done():
		log.Println("Shutting down...")
	case err := <-errs:
		log.Printf("Server error: %v", err)
		exitCode = 1
	}
	// Kubernetes sends SIGTERM on rollouts: finish in-flight requests before exiting.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	public.Shutdown(shutdownCtx)
	internal.Shutdown(shutdownCtx)
	os.Exit(exitCode)
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

func publicRouter() http.Handler {
	r := chi.NewRouter()
	// No request logger on purpose: it would log authorization codes found in query strings.
	r.Use(middleware.Recoverer, api.Metrics("public"))
	api.MountOIDC(r) // /authorize /token /userinfo /login /logout /jwks.json /.well-known/...
	r.Mount("/api", apiRouter())
	return r
}

func apiRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(api.RequireSameOrigin)
	r.Mount("/account", api.GetAccountSubrouter())
	r.Mount("/service", api.GetAppSubrouter())
	r.Mount("/access", api.GetAccessSubrouter())
	return r
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// bootstrapAdmin gives the seeded admin account its first password (the schema script can't hash one).
// Uses ADMIN_INITIAL_PASSWORD, or generates one and logs it once. No-op once the admin has a password.
func bootstrapAdmin() {
	password := os.Getenv("ADMIN_INITIAL_PASSWORD")
	generated := false
	if password == "" {
		p, err := auth.RandomToken(18)
		if err != nil {
			log.Fatal(err)
		}
		password, generated = p, true
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		log.Fatal(err)
	}
	set, err := db.SetAdminPasswordIfUnset(hash)
	if err != nil {
		log.Fatalf("Failed to set initial admin password: %v", err)
	}
	if set && generated {
		log.Printf("Initial admin password (shown once, change it): %s", password)
	}
}

func loadEnv() {
	// .env is optional in containers where variables are injected directly
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file loaded:", err)
	}
}
