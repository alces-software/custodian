package config

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestLoadSuccess(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("API_KEYS", "secret1, secret2")
	t.Setenv("ALLOWED_DOMAINS", "*.example.com,example.com")
	t.Setenv("DATABASE_URL", "postgres://localhost/custodian")
	t.Setenv("LE_EMAIL", "ops@example.com")
	t.Setenv("DATA_ENCRYPTION_KEY", key)
	t.Setenv("LE_DIRECTORY", "staging")
	t.Setenv("PORT", "9090")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != "9090" {
		t.Errorf("Port = %q", cfg.Port)
	}
	if len(cfg.APIKeys) != 2 || cfg.APIKeys[0] != "secret1" {
		t.Errorf("APIKeys = %#v", cfg.APIKeys)
	}
	if cfg.LEDirectory != DirectoryStaging {
		t.Errorf("LEDirectory = %q", cfg.LEDirectory)
	}
	if !cfg.IsStaging() {
		t.Error("expected staging")
	}
}

func TestLoadProductionDirectory(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("API_KEYS", "k")
	t.Setenv("ALLOWED_DOMAINS", "example.com")
	t.Setenv("DATABASE_URL", "postgres://localhost/c")
	t.Setenv("LE_EMAIL", "a@b.co")
	t.Setenv("DATA_ENCRYPTION_KEY", key)
	t.Setenv("LE_DIRECTORY", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LEDirectory != DirectoryProduction {
		t.Errorf("got %q", cfg.LEDirectory)
	}
}

func TestLoadMissingAPIKeys(t *testing.T) {
	os.Clearenv()
	t.Setenv("ALLOWED_DOMAINS", "example.com")
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
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("LE_EMAIL", "a@b.co")
	t.Setenv("DATA_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))

	if _, err := Load(); err == nil {
		t.Fatal("expected error for short key")
	}
}
