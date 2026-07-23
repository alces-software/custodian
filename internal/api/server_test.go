package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/markt/custodian/internal/authz"
	"github.com/markt/custodian/internal/domains"
)

func TestHealthzNoAuth(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	s.handleHealthz(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
}

func TestRequireAPIKey(t *testing.T) {
	cat, err := domains.NewCatalog([]domains.Entry{
		{Pattern: "example.com", Zone: "z"},
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := authz.NewRegistry([]authz.Client{
		{ID: "a", Key: "good-key-value", Role: authz.RoleAdmin},
	}, cat)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{authz: reg}
	h := s.requireAPIKey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := clientFrom(r.Context())
		if c == nil || c.ID != "a" {
			t.Fatalf("client %#v", c)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer good-key-value")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("with auth: %d", rr.Code)
	}
}
