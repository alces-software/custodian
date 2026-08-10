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

package clihost

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestServeBinary(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("fake-cli-binary")
	if err := os.WriteFile(filepath.Join(dir, "custodian"), payload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "custodian-linux-amd64"), payload, 0o755); err != nil {
		t.Fatal(err)
	}

	h := New(dir)
	r := chi.NewRouter()
	h.Mount(r)

	// index
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cli", nil)
	req.Host = "custodian.example"
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index status %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "custodian-linux-amd64") {
		t.Fatalf("index body: %s", body)
	}

	// download
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/cli/custodian", nil)
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("download status %d", rr.Code)
	}
	got, _ := io.ReadAll(rr.Body)
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch")
	}
	if !strings.Contains(rr.Header().Get("Content-Disposition"), "custodian") {
		t.Fatalf("disposition %q", rr.Header().Get("Content-Disposition"))
	}

	// path traversal
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/cli/../clihost.go", nil)
	r.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected rejection of traversal")
	}
}

func TestDisabled(t *testing.T) {
	h := New("")
	r := chi.NewRouter()
	h.Mount(r)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cli/custodian", nil)
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d", rr.Code)
	}
}
