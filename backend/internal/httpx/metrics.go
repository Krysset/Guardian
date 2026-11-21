package httpx

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
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

	// csrfRefusals counts state-changing requests refused because they may come from another site.
	csrfRefusals = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "guardian", Name: "csrf_refusals_total",
		Help: "Requests refused as possibly cross-site: check=form (a sign-in page form without its hidden token; " +
			"a few come from old tabs) or check=origin (an API request from an origin that is not allowed).",
	}, []string{"check"})
)

func init() {
	for _, c := range []string{"form", "origin"} {
		csrfRefusals.WithLabelValues(c)
	}
}

// CountRefused records a request a rate limiter (or the honeypot) refused: in the metric, and in an hourly
// counter in the database, so the admin area's overview can show the last 24 hours across all replicas.
func CountRefused(endpoint string) {
	RateLimited.WithLabelValues(endpoint).Inc()
	if _, err := db.RateLimitHit(db.RefusedKeyPrefix+endpoint, time.Hour); err != nil {
		slog.Warn("failed to count a refused request", "error", err)
	}
}

// RegisterDBMetrics exposes connection-pool stats (open, in use, idle, wait count/duration), the time of
// the last backup, and the state of the installation (stateCollector). Backups run in their own process
// (kubectl exec), so the time is read from the audit log at each scrape. keyLifetime is how long a signing
// key signs (SIGNING_KEY_LIFETIME).
func RegisterDBMetrics(keyLifetime time.Duration) {
	prometheus.MustRegister(collectors.NewDBStatsCollector(db.GetDatabaseConnection(), "guardian"))
	prometheus.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "guardian", Name: "backup_last_success_timestamp_seconds",
		Help: "When the last backup was written (Unix time), from the audit log; 0 if there is none. " + sameOnEveryReplica,
	}, func() float64 {
		t, err := db.LastBackupTime()
		if err != nil || t.IsZero() {
			return 0
		}
		return float64(t.Unix())
	}))
	prometheus.MustRegister(&stateCollector{keyLifetime: keyLifetime})
}

// sameOnEveryReplica ends the help of every gauge read from the database: each replica reports the same
// value, so a dashboard must take max (or one replica), never sum.
const sameOnEveryReplica = "Read from the database: every replica reports the same value, so use max(), not sum()."

func stateDesc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc("guardian_"+name, help+" "+sameOnEveryReplica, labels, nil)
}

var (
	accountsDesc = stateDesc("accounts",
		"Accounts by status: active, pending (waiting for email confirmation), disabled, deleted (in the grace period before erasure).", "status")
	secondFactorDesc = stateDesc("accounts_second_factor",
		"Accounts that are not deleted, by the second factor they have: none, authenticator_app, security_key or both.", "factor")
	adminsNoMFADesc = stateDesc("admins_without_second_factor",
		"Active administrators with no authenticator app or security key yet; they must set one up at their next sign-in.")
	sessionsDesc = stateDesc("sessions",
		"Live sign-in sessions (one per signed-in browser), whatever apps they use. Not the sum of guardian_app_sessions.")
	appSessionsDesc = stateDesc("app_sessions",
		"Live sign-in sessions that have received tokens for the app. A session signed in to three apps counts once "+
			"for each of them, so summing over apps counts people several times; use guardian_sessions for the total.", "app")
	appsDesc         = stateDesc("apps", "Registered apps: enabled or disabled.", "state")
	groupsDesc       = stateDesc("groups", "Groups: shared (may be linked to any number of apps) or single_app (bound to one app).", "kind")
	keyActivatedDesc = stateDesc("signing_key_activated_timestamp_seconds",
		"When each algorithm's signing key in use started signing (Unix time).", "alg")
	keyRotationDesc = stateDesc("signing_key_rotation_due_timestamp_seconds",
		"When each algorithm's signing key in use is due to be replaced (Unix time). Rotation is automatic; time() "+
			"well past this means it is stuck.", "alg")
	stateUpDesc = prometheus.NewDesc("guardian_state_metrics_up",
		"1 if the database counts above could be read at the last scrape, 0 if not (they are then missing).", nil, nil)
)

// stateCollector reads the installation's counts from the database, at most every StateMetricsMaxAge, so
// several scrapers (or replicas behind one Service) do not each run the queries.
type stateCollector struct {
	keyLifetime time.Duration
	mu          sync.Mutex
	at          time.Time
	counts      db.MetricCounts
	err         error
}

// StateMetricsMaxAge is how long the counts are reused; tests set it to 0.
var StateMetricsMaxAge = 30 * time.Second

func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{accountsDesc, secondFactorDesc, adminsNoMFADesc, sessionsDesc, appSessionsDesc,
		appsDesc, groupsDesc, keyActivatedDesc, keyRotationDesc, stateUpDesc} {
		ch <- d
	}
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	if time.Since(c.at) >= StateMetricsMaxAge {
		c.counts, c.err = db.CountForMetrics(SessionIdleTimeout)
		c.at = time.Now()
		if c.err != nil {
			slog.Warn("failed to read the counts for /metrics", "error", c.err)
		}
	}
	counts, err := c.counts, c.err
	c.mu.Unlock()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(stateUpDesc, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(stateUpDesc, prometheus.GaugeValue, 1)
	gauges := func(d *prometheus.Desc, m map[string]int) {
		for k, v := range m {
			ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, float64(v), k)
		}
	}
	gauges(accountsDesc, counts.Accounts)
	gauges(secondFactorDesc, counts.SecondFactor)
	gauges(appSessionsDesc, counts.AppSessions)
	gauges(appsDesc, counts.Apps)
	gauges(groupsDesc, counts.Groups)
	ch <- prometheus.MustNewConstMetric(adminsNoMFADesc, prometheus.GaugeValue, float64(counts.AdminsWithoutSecondFactor))
	ch <- prometheus.MustNewConstMetric(sessionsDesc, prometheus.GaugeValue, float64(counts.Sessions))
	for alg, at := range counts.SigningKeyActivated {
		ch <- prometheus.MustNewConstMetric(keyActivatedDesc, prometheus.GaugeValue, float64(at.Unix()), alg)
		ch <- prometheus.MustNewConstMetric(keyRotationDesc, prometheus.GaugeValue, float64(at.Add(c.keyLifetime).Unix()), alg)
	}
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
