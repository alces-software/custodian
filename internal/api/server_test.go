package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"alces/custodian/internal/authz"
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

func TestAccessKeyMeta(t *testing.T) {
	// compile-time sanity for role helpers used by handlers
	p := &authz.Principal{Role: authz.RoleRegistrar}
	if authz.CanIssueCertificates(p) {
		t.Fatal("registrar must not issue")
	}
	if !authz.CanRegisterAccessKey(p) {
		t.Fatal("registrar must register")
	}
}
