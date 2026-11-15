package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	db "guardian/internal/store"
)

// GetInternalRouter serves the cluster-internal listener: Prometheus metrics and Kubernetes probes. It
// must never be exposed through the public ingress; a NetworkPolicy should restrict it to Prometheus
// and the kubelet.
func GetInternalRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, Metrics("internal"))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { RespondWithSuccess(w) }) // liveness: process is up
	r.Get("/readyz", readyz)                                                                  // readiness: database reachable
	r.Handle("/metrics", promhttp.Handler())
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
