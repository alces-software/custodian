// =============================================================================
// Copyright (C) 2026 Alces Software Ltd.
//
// This file is part of Custodian CLI.
//
// This program and the accompanying materials are made available under
// the terms of the Eclipse Public License 2.0 which is available at
// <https://www.eclipse.org/legal/epl-2.0>, or alternative license
// terms made available by Alces Software Ltd - please direct inquiries
// about licensing to licensing@alces-flight.com.
//
// Custodian CLI is distributed in the hope that it will be useful, but
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
// IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
// OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
// PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
// details.
//
// You should have received a copy of the Eclipse Public License 2.0
// along with Custodian CLI. If not, see:
//
//  https://opensource.org/licenses/EPL-2.0
//
// For more information on Custodian CLI, please visit:
// https://github.com/alces-software/custodian-cli
// ==============================================================================

package client_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"alces/custodian-cli/internal/client"
)

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("healthz should not send auth")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "", 0)
	st, err := c.Healthz(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "ok" {
		t.Fatalf("got %+v", st)
	}
}

func TestListCertificates_AuthAndDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{"code": "unauthorized", "message": "invalid API key"},
			})
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{
				{
					"id": "abc", "common_name": "app.example.com", "sans": []string{},
					"status": "active", "created_at": now, "updated_at": now,
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "secret", 0)
	list, err := c.ListCertificates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Certificates) != 1 || list.Certificates[0].CommonName != "app.example.com" {
		t.Fatalf("got %+v", list)
	}
}

func TestAPIError_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "unauthorized", "message": "invalid API key"},
		})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "bad", 0)
	_, err := c.ListCertificates(t.Context())
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("want APIError, got %T %v", err, err)
	}
	if apiErr.Code != "unauthorized" || apiErr.StatusCode != 401 {
		t.Fatalf("got %+v", apiErr)
	}
	if apiErr.Error() != "unauthorized: invalid API key" {
		t.Fatalf("Error() = %q", apiErr.Error())
	}
}

func TestIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/certificates" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		var body client.IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.CommonName != "app.example.com" || !body.Force {
			t.Fatalf("body %+v", body)
		}
		w.WriteHeader(http.StatusCreated)
		now := time.Now().UTC().Format(time.RFC3339)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "id1", "common_name": body.CommonName, "sans": body.SANs, "status": "active",
			"created_at": now, "updated_at": now,
		})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "k", 0)
	cert, err := c.Issue(t.Context(), client.IssueRequest{
		CommonName: "app.example.com",
		SANs:       []string{"www.app.example.com"},
		Force:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.ID != "id1" {
		t.Fatalf("got %+v", cert)
	}
}

func TestGetCertificate_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "not_found", "message": "certificate not found"},
		})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "k", 0)
	_, err := c.GetCertificate(t.Context(), "missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBundleJSONAndPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") == "pem" {
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = io.WriteString(w, "-----BEGIN KEY-----\n")
			return
		}
		_ = json.NewEncoder(w).Encode(client.Bundle{
			ID: "id1", CommonName: "a.com", PrivateKeyPEM: "KEY",
			CertificatePEM: "CERT", FullchainPEM: "FULL",
		})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "k", 0)
	b, err := c.GetBundle(t.Context(), "id1")
	if err != nil {
		t.Fatal(err)
	}
	if b.PrivateKeyPEM != "KEY" {
		t.Fatalf("got %+v", b)
	}
	raw, err := c.GetBundlePEM(t.Context(), "id1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "BEGIN KEY") {
		t.Fatalf("got %q", raw)
	}
}

func TestRenewOne_Delete_RenewDue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC().Format(time.RFC3339)
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/renew") && strings.Contains(r.URL.Path, "/certificates/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "id1", "common_name": "a.com", "status": "active",
				"created_at": now, "updated_at": now,
			})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/renew":
			_ = json.NewEncoder(w).Encode(client.RenewResult{
				Renewed: []client.RenewItem{{ID: "1", CommonName: "a.com"}},
				Skipped: []client.RenewItem{},
				Failed:  []client.FailedItem{},
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "k", 0)
	if _, err := c.RenewOne(t.Context(), "id1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteCertificate(t.Context(), "id1"); err != nil {
		t.Fatal(err)
	}
	res, err := c.RenewDue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renewed) != 1 {
		t.Fatalf("got %+v", res)
	}
}

func TestReadyz(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			t.Fatalf("path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "", 0)
	st, err := c.Readyz(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "ready" {
		t.Fatalf("got %+v", st)
	}
}

func TestAccessKeys(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer registrar" {
			t.Fatalf("auth %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/access-keys":
			var body client.RegisterAccessKeyRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.AccessKey == "" {
				t.Fatal("missing access_key")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "ak1", "description": body.Description, "created": true,
				"created_at": now, "created_by": "registrar", "cert_count": 0,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/access-keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_keys": []map[string]any{
					{"id": "ak1", "description": "app", "created_at": now, "created_by": "admin", "cert_count": 2},
				},
			})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/access-keys/"):
			var body client.UpdateAccessKeyRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Description == nil || *body.Description != "renamed" {
				t.Fatalf("body %+v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "ak1", "description": *body.Description, "created_at": now, "created_by": "admin", "cert_count": 2,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/access-keys/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "ak1", "description": "app", "created_at": now, "created_by": "admin", "cert_count": 2,
			})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "registrar", 0)
	ak, err := c.RegisterAccessKey(t.Context(), client.RegisterAccessKeyRequest{
		AccessKey: "11111111-2222-4333-8444-555555555555", Description: "app",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ak.Created || ak.ID != "ak1" {
		t.Fatalf("got %+v", ak)
	}
	list, err := c.ListAccessKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.AccessKeys) != 1 {
		t.Fatalf("got %+v", list)
	}
	got, err := c.GetAccessKey(t.Context(), "ak1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Description != "app" {
		t.Fatalf("got %+v", got)
	}
	updated, err := c.UpdateAccessKeyDescription(t.Context(), "ak1", "renamed")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Description != "renamed" {
		t.Fatalf("got %+v", updated)
	}
	if err := c.RevokeAccessKey(t.Context(), "ak1"); err != nil {
		t.Fatal(err)
	}
}

func TestIssue_WithAccessKeyOnBehalf(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body client.IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.AccessKeyID != "ak-uuid" {
			t.Fatalf("body %+v", body)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "c1", "common_name": body.CommonName, "status": "active",
			"access_key_id": body.AccessKeyID, "dns_zone": "example-com",
			"created_at": now, "updated_at": now, "sans": body.SANs,
		})
	}))
	t.Cleanup(srv.Close)

	c := client.New(srv.URL, "admin", 0)
	cert, err := c.Issue(t.Context(), client.IssueRequest{
		CommonName:  "app.example.com",
		AccessKeyID: "ak-uuid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.AccessKeyID != "ak-uuid" || cert.DNSZone != "example-com" {
		t.Fatalf("got %+v", cert)
	}
}
