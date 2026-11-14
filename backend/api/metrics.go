package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"

	db "guardian/database"
)

// Prometheus metrics, scraped from the INTERNAL listener (/metrics). They are what tells you whether the
// database needs help: watch guardian_http_request_duration_seconds{route="/introspect"} and the
// guardian_db_* pool gauges before adding any caching.
var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "http_requests_total", Help: "HTTP requests by listener, route pattern, method and status.",
	}, []string{"listener", "route", "method", "code"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "guardian", Name: "http_request_duration_seconds", Help: "HTTP request latency.",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	}, []string{"listener", "route", "method"})

	introspections = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "introspections_total", Help: "Token introspections by result.",
	}, []string{"result"}) // active | inactive | error | unauthorized

	loginsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "logins_total", Help: "Interactive login attempts by result.",
	}, []string{"result"}) // success | failure

	rateLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "rate_limited_total", Help: "Requests rejected by the rate limiter.",
	}, []string{"endpoint"}) // login | register
)

// RegisterDBMetrics exposes connection-pool stats (open, in use, idle, wait count/duration).
func RegisterDBMetrics() {
	prometheus.MustRegister(collectors.NewDBStatsCollector(db.GetDatabaseConnection(), "guardian"))
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Metrics records request count and latency per chi route pattern (bounded label cardinality).
func Metrics(listener string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			route := "unmatched"
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				route = rc.RoutePattern()
			}
			httpRequests.WithLabelValues(listener, route, r.Method, strconv.Itoa(rec.status)).Inc()
			httpDuration.WithLabelValues(listener, route, r.Method).Observe(time.Since(start).Seconds())
		})
	}
}
