// Package internalapi serves the cluster-internal listener: Prometheus metrics and Kubernetes probes.
package internalapi

import (
	"context"
	"net/http"
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

func readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := db.GetDatabaseConnection().PingContext(ctx); err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	httpx.Success(w)
}
