package server

import (
	"net/http"
	"testing"
)

func TestNewServerSetsTimeouts(t *testing.T) {
	s := newServer(":0", http.NotFoundHandler())
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 {
		t.Errorf("timeouts missing (slowloris protection): %+v", s)
	}
}
