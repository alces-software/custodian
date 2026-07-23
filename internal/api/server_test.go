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
