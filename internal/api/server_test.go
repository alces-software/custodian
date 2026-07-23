package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidKeyConstantTime(t *testing.T) {
	s := &Server{apiKeys: []string{"super-secret-key"}}
	if !s.validKey("super-secret-key") {
		t.Fatal("expected valid")
	}
	if s.validKey("wrong") {
		t.Fatal("expected invalid")
	}
	if s.validKey("super-secret-ke") {
		t.Fatal("expected invalid (short)")
	}
}

func TestHealthzNoAuth(t *testing.T) {
	s := &Server{}
	// minimal router piece
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	s.handleHealthz(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
}
