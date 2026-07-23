package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Directory aliases for Let's Encrypt.
const (
	DirectoryStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	DirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

// Config holds runtime configuration loaded from the environment.
type Config struct {
	Port                   string
	DatabaseURL            string
	APIKeys                []string
	AllowedDomains         []string
	LEEmail                string
	LEDirectory            string
	DataEncryptionKey      []byte
	GCPProject             string
	CloudDNSZone           string
	GCPServiceAccountJSON  string
	DNSPropagationTimeout  time.Duration
	RenewBeforeDays        int
	LogLevel               string
	MaxSANs                int
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Port:                  envOr("PORT", "8080"),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		LEEmail:               os.Getenv("LE_EMAIL"),
		GCPProject:            firstNonEmpty(os.Getenv("GCE_PROJECT"), os.Getenv("GCP_PROJECT")),
		CloudDNSZone:          os.Getenv("CLOUDDNS_ZONE"),
		GCPServiceAccountJSON: os.Getenv("GCP_SERVICE_ACCOUNT_JSON"),
		LogLevel:              envOr("LOG_LEVEL", "info"),
		MaxSANs:               envInt("MAX_SANS", 10),
		RenewBeforeDays:       envInt("RENEW_BEFORE_DAYS", 30),
	}

	keys := splitCSV(os.Getenv("API_KEYS"))
	if len(keys) == 0 {
		return nil, fmt.Errorf("API_KEYS is required (comma-separated bearer tokens)")
	}
	cfg.APIKeys = keys

	domains := splitCSV(os.Getenv("ALLOWED_DOMAINS"))
	if len(domains) == 0 {
		return nil, fmt.Errorf("ALLOWED_DOMAINS is required (comma-separated patterns)")
	}
	cfg.AllowedDomains = domains

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.LEEmail == "" {
		return nil, fmt.Errorf("LE_EMAIL is required")
	}

	dir := strings.TrimSpace(os.Getenv("LE_DIRECTORY"))
	switch strings.ToLower(dir) {
	case "", "staging":
		cfg.LEDirectory = DirectoryStaging
	case "production", "prod":
		cfg.LEDirectory = DirectoryProduction
	default:
		cfg.LEDirectory = dir
	}

	encKey := os.Getenv("DATA_ENCRYPTION_KEY")
	if encKey == "" {
		return nil, fmt.Errorf("DATA_ENCRYPTION_KEY is required (base64-encoded 32 bytes)")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("DATA_ENCRYPTION_KEY must be base64: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("DATA_ENCRYPTION_KEY must decode to 32 bytes, got %d", len(keyBytes))
	}
	cfg.DataEncryptionKey = keyBytes

	timeoutSec := envInt("DNS_PROPAGATION_TIMEOUT_SEC", 120)
	cfg.DNSPropagationTimeout = time.Duration(timeoutSec) * time.Second

	if cfg.RenewBeforeDays < 1 {
		return nil, fmt.Errorf("RENEW_BEFORE_DAYS must be >= 1")
	}

	return cfg, nil
}

// IsStaging reports whether the ACME directory is Let's Encrypt staging.
func (c *Config) IsStaging() bool {
	return c.LEDirectory == DirectoryStaging || strings.Contains(c.LEDirectory, "staging")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
