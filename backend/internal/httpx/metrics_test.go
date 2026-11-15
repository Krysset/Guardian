package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsMiddlewareRecordsRoutePatternAndStatus(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Metrics("unit"))
	r.Get("/things/{id}", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }) // implicit 200
	r.Get("/boom", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusInternalServerError) })

	for _, path := range []string{"/things/1", "/things/2", "/things/3", "/boom"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	if got := promtest.ToFloat64(httpRequests.WithLabelValues("unit", "/things/{id}", "GET", "200")); got != 3 {
		t.Errorf("/things/{id} 200 count = %v, want 3 (one series for all ids: bounded label cardinality)", got)
	}
	if got := promtest.ToFloat64(httpRequests.WithLabelValues("unit", "/boom", "GET", "500")); got != 1 {
		t.Errorf("/boom 500 count = %v, want 1", got)
	}
}
