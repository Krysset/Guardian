// Package internalapi serves the cluster-internal listener: Prometheus metrics and Kubernetes probes.
package internalapi

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"guardian/internal/httpx"
	db "guardian/internal/store"
)

// Router serves the cluster-internal listener. It
// must never be exposed through the public ingress; a NetworkPolicy should restrict it to Prometheus
// and the kubelet.
func Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, httpx.Metrics("internal"))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { httpx.Success(w) }) // liveness: process is up
	r.Get("/readyz", readyz)                                                             // readiness: database reachable
	r.Handle("/metrics", promhttp.Handler())
	return r
}

// ping checks the database; tests replace it.
var ping = func(ctx context.Context) error { return db.GetDatabaseConnection().PingContext(ctx) }

// draining is set when the process has been told to stop: readiness then fails at once, so the load
// balancer stops sending new requests while those in flight finish.
var draining atomic.Bool

// Drain makes /readyz answer 503 from now on.
func Drain() { draining.Store(true) }

func readyz(w http.ResponseWriter, r *http.Request) {
	if draining.Load() {
		httpx.Error(w, http.StatusServiceUnavailable, "shutting down")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := ping(ctx); err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	httpx.Success(w)
}
