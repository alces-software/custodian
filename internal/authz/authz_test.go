package authz

import (
	"testing"

	"github.com/markt/custodian/internal/domains"
	"github.com/markt/custodian/internal/store"
)

func testCatalog(t *testing.T) *domains.Catalog {
	t.Helper()
	c, err := domains.NewCatalog([]domains.Entry{
		{Pattern: "*.example.com", Zone: "z1"},
		{Pattern: "example.com", Zone: "z1"},
		{Pattern: "*.other.com", Zone: "z2"},
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthenticateAndScope(t *testing.T) {
	cat := testCatalog(t)
	reg, err := NewRegistry([]Client{
		{ID: "admin", Key: "admin-secret-key", Role: RoleAdmin},
		// Under catalog *.example.com only single-label children match (pay.example.com, not a.pay.example.com).
		{ID: "pay", Key: "pay-secret-key!!", Role: RoleTenant, Patterns: []string{"pay.example.com"}},
	}, cat)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.HasAdmin() {
		t.Fatal("expected admin")
	}

	admin, err := reg.Authenticate("admin-secret-key")
	if err != nil || !admin.IsAdmin() {
		t.Fatalf("admin: %v %#v", err, admin)
	}
	pay, err := reg.Authenticate("pay-secret-key!!")
	if err != nil || pay.ID != "pay" {
		t.Fatalf("pay: %v %#v", err, pay)
	}
	if _, err := reg.Authenticate("nope"); err == nil {
		t.Fatal("expected invalid")
	}

	if !reg.CanAccessNames(pay, []string{"pay.example.com"}) {
		t.Fatal("pay should access pay.example.com")
	}
	if reg.CanAccessNames(pay, []string{"other.example.com"}) {
		t.Fatal("pay should not access other.example.com")
	}
	cert := &store.Certificate{CommonName: "evil.example.com"}
	if reg.CanAccessCert(pay, cert) {
		t.Fatal("pay should not access evil cert")
	}
	if !reg.CanAccessCert(admin, cert) {
		t.Fatal("admin should access catalog names")
	}
}

func TestTenantRequiresPatterns(t *testing.T) {
	cat := testCatalog(t)
	_, err := NewRegistry([]Client{
		{ID: "t", Key: "k", Role: RoleTenant},
	}, cat)
	if err == nil {
		t.Fatal("expected error")
	}
}
