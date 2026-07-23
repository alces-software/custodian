package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"

	"alces/custodian/internal/store"
)

func TestMatchKey(t *testing.T) {
	if !matchKey("abcdef", []string{"xyz", "abcdef"}) {
		t.Fatal("expected match")
	}
	if matchKey("nope", []string{"abcdef"}) {
		t.Fatal("expected no match")
	}
}

func TestCanAccessCert(t *testing.T) {
	id := uuid.New()
	cert := &store.Certificate{AccessKeyID: &id}
	admin := &Principal{Role: RoleAdmin}
	owner := &Principal{Role: RoleAccessKey, AccessKeyID: id}
	other := &Principal{Role: RoleAccessKey, AccessKeyID: uuid.New()}
	reg := &Principal{Role: RoleRegistrar}

	if !CanAccessCert(admin, cert) {
		t.Fatal("admin")
	}
	if !CanAccessCert(owner, cert) {
		t.Fatal("owner")
	}
	if CanAccessCert(other, cert) {
		t.Fatal("other")
	}
	if CanAccessCert(reg, cert) {
		t.Fatal("registrar")
	}
}

func TestHashMatchesStoreHelper(t *testing.T) {
	raw := "550e8400-e29b-41d4-a716-446655440000"
	sum := sha256.Sum256([]byte(raw))
	want := hex.EncodeToString(sum[:])
	if store.HashAccessKey(raw) != want {
		t.Fatal("hash mismatch")
	}
}

func TestRoleHelpers(t *testing.T) {
	admin := &Principal{Role: RoleAdmin}
	reg := &Principal{Role: RoleRegistrar}
	if !CanRegisterAccessKey(admin) || !CanRegisterAccessKey(reg) {
		t.Fatal("register")
	}
	if !CanManageAccessKeys(admin) || CanManageAccessKeys(reg) {
		t.Fatal("manage")
	}
	if !CanBulkRenew(admin) || CanBulkRenew(reg) {
		t.Fatal("renew")
	}
	if !CanIssueCertificates(admin) || CanIssueCertificates(reg) {
		t.Fatal("issue")
	}
}
