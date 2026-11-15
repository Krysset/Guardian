package internalapi

import (
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
