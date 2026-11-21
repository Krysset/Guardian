package internalapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInternalRouterBasics(t *testing.T) {
	h := Router()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("/healthz = %d", rec.Code)
	}

	// introspection is gone, and the public API must not exist on this listener
	for _, c := range []struct{ method, path string }{{"POST", "/introspect"}, {"GET", "/authorize"}, {"POST", "/token"}, {"GET", "/login"}} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s on the internal listener = %d, want 404/405", c.method, c.path, rec.Code)
		}
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "guardian_") {
		t.Errorf("/metrics = %d, body lacks guardian_ metrics", rec.Code)
	}
}

// Readiness follows the database, and fails at once when Guardian starts shutting down; liveness does
// neither, so Kubernetes never restarts a pod because the database is away.
//
// Covers: P6
func TestReadinessFollowsTheDatabaseAndShutdown(t *testing.T) {
	h := Router()
	previous := ping
	t.Cleanup(func() { ping = previous; draining.Store(false) })
	probe := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code
	}
	ping = func(context.Context) error { return nil }
	if probe("/readyz") != 200 {
		t.Error("ready with a database")
	}
	ping = func(context.Context) error { return errors.New("connection refused") }
	if probe("/readyz") != http.StatusServiceUnavailable || probe("/healthz") != 200 {
		t.Error("without the database: readyz must fail and healthz must not")
	}
	ping = func(context.Context) error { return nil }
	Drain()
	if probe("/readyz") != http.StatusServiceUnavailable || probe("/healthz") != 200 {
		t.Error("while draining: readyz must fail and healthz must not")
	}
}
