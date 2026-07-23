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
	os.Unsetenv("DOMAIN_CATALOG")
	os.Unsetenv("API_CLIENTS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != "9090" {
		t.Errorf("Port = %q", cfg.Port)
	}
	if !cfg.Authz.HasAdmin() {
		t.Error("expected admin from legacy keys")
	}
	if !cfg.IsStaging() {
		t.Error("expected staging")
	}
	_, zone, err := cfg.Catalog.Resolve("foo.example.com")
	if err != nil || zone != "example-com" {
		t.Fatalf("zone=%q err=%v", zone, err)
	}
}

func TestLoadScopedClientsAndCatalog(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	catalog, _ := json.Marshal([]map[string]string{
		{"pattern": "*.example.com", "zone": "z1"},
		{"pattern": "example.com", "zone": "z1"},
	})
	clients, _ := json.Marshal([]map[string]any{
		{"id": "admin", "key": "admin-key-here", "role": "admin"},
		{"id": "app", "key": "app-key-here!!", "role": "tenant", "patterns": []string{"app.example.com"}},
	})
	t.Setenv("DOMAIN_CATALOG", string(catalog))
	t.Setenv("API_CLIENTS", string(clients))
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
	c, err := cfg.Authz.Authenticate("app-key-here!!")
	if err != nil || c.ID != "app" {
		t.Fatalf("%v %#v", err, c)
	}
}

func TestLoadMissingAPIKeys(t *testing.T) {
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

func TestLoadBadEncryptionKeyLength(t *testing.T) {
	t.Setenv("API_KEYS", "k")
	t.Setenv("ALLOWED_DOMAINS", "example.com")
	t.Setenv("CLOUDDNS_ZONE", "z")
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("LE_EMAIL", "a@b.co")
	t.Setenv("DATA_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	os.Unsetenv("DOMAIN_CATALOG")
	os.Unsetenv("API_CLIENTS")

	if _, err := Load(); err == nil {
		t.Fatal("expected error for short key")
	}
}
