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

package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestLoadLegacy(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("API_KEYS", "secret1, secret2")
	t.Setenv("ALLOWED_DOMAINS", "*.example.com,example.com")
	t.Setenv("CLOUDDNS_ZONE", "example-com")
	t.Setenv("DATABASE_URL", "postgres://localhost/custodian")
	t.Setenv("LE_EMAIL", "ops@example.com")
	t.Setenv("DATA_ENCRYPTION_KEY", key)
	t.Setenv("LE_DIRECTORY", "staging")
	t.Setenv("PORT", "9090")
	os.Unsetenv("ADMIN_API_KEYS")
	os.Unsetenv("DOMAIN_CATALOG")
	os.Unsetenv("API_CLIENTS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != "9090" {
		t.Errorf("Port = %q", cfg.Port)
	}
	if len(cfg.AdminAPIKeys) != 2 {
		t.Errorf("AdminAPIKeys = %#v", cfg.AdminAPIKeys)
	}
	if !cfg.IsStaging() {
		t.Error("expected staging")
	}
	_, zone, err := cfg.Catalog.Resolve("foo.example.com")
	if err != nil || zone != "example-com" {
		t.Fatalf("zone=%q err=%v", zone, err)
	}
}

func TestLoadAdminAndCatalog(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	catalog, _ := json.Marshal([]map[string]string{
		{"pattern": "*.example.com", "zone": "z1"},
		{"pattern": "example.com", "zone": "z1"},
	})
	t.Setenv("DOMAIN_CATALOG", string(catalog))
	t.Setenv("ADMIN_API_KEYS", "admin-secret-key")
	t.Setenv("REGISTRAR_API_KEYS", "reg-secret-key")
	t.Setenv("DATABASE_URL", "postgres://localhost/c")
	t.Setenv("LE_EMAIL", "a@b.co")
	t.Setenv("DATA_ENCRYPTION_KEY", key)
	t.Setenv("LE_DIRECTORY", "production")
	os.Unsetenv("API_KEYS")
	os.Unsetenv("ALLOWED_DOMAINS")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LEDirectory != DirectoryProduction {
		t.Errorf("got %q", cfg.LEDirectory)
	}
	if len(cfg.RegistrarAPIKeys) != 1 {
		t.Fatal("registrar")
	}
}

func TestLoadMissingAdmin(t *testing.T) {
	os.Clearenv()
	t.Setenv("ALLOWED_DOMAINS", "example.com")
	t.Setenv("CLOUDDNS_ZONE", "z")
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("LE_EMAIL", "a@b.co")
	t.Setenv("DATA_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	if _, err := Load(); err == nil {
		t.Fatal("expected error")
	}
}
