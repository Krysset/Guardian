package httpx

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"

	db "guardian/internal/store"
)

// Prometheus metrics, scraped from the INTERNAL listener (/metrics). They are what tells you whether the
// database needs help: watch guardian_http_request_duration_seconds{route="/token"}, the token counters
// and the guardian_db_* pool gauges before adding any caching.
var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "http_requests_total", Help: "HTTP requests by listener, route pattern, method and status.",
	}, []string{"listener", "route", "method", "code"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "guardian", Name: "http_request_duration_seconds", Help: "HTTP request latency.",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	}, []string{"listener", "route", "method"})

	// RateLimited counts requests rejected by a rate limiter, by endpoint.
	RateLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "rate_limited_total", Help: "Requests rejected by the rate limiter.",
	}, []string{"endpoint"}) // login, register, reauth, mfa, mail, forgot, honeypot
)

// RegisterDBMetrics exposes connection-pool stats (open, in use, idle, wait count/duration) and the time of
// the last backup. Backups run in their own process (kubectl exec), so the time is read from the audit log
// at each scrape.
func RegisterDBMetrics() {
	prometheus.MustRegister(collectors.NewDBStatsCollector(db.GetDatabaseConnection(), "guardian"))
	prometheus.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "guardian", Name: "backup_last_success_timestamp_seconds",
		Help: "When the last backup was written (Unix time), from the audit log; 0 if there is none.",
	}, func() float64 {
		t, err := db.LastBackupTime()
		if err != nil || t.IsZero() {
			return 0
		}
		return float64(t.Unix())
	}))
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
