// =============================================================================
// Copyright (C) 2026-present Alces Software Ltd.
//
// This file is part of Custodian.
//
// This program and the accompanying materials are made available under
// the terms of the Eclipse Public License 2.0 which is available at
// <https://www.eclipse.org/legal/epl-2.0>, or alternative license
// terms made available by Alces Software Ltd - please direct inquiries
// about licensing to licensing@alces-flight.com.
//
// Custodian is distributed in the hope that it will be useful, but
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
// IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
// OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
// PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
// details.
//
// You should have received a copy of the Eclipse Public License 2.0
// along with Custodian. If not, see:
//
//  https://opensource.org/licenses/EPL-2.0
//
// For more information on Custodian, please visit:
// https://github.com/alces-software/custodian
// ==============================================================================

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
