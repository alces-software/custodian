package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/markt/custodian/internal/authz"
	"github.com/markt/custodian/internal/domains"
)

// Directory aliases for Let's Encrypt.
const (
	DirectoryStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	DirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

// catalogJSONEntry is the JSON shape for DOMAIN_CATALOG.
type catalogJSONEntry struct {
	Pattern string `json:"pattern"`
	Zone    string `json:"zone"`
}

// clientJSON is the JSON shape for API_CLIENTS.
type clientJSON struct {
	ID       string   `json:"id"`
	Key      string   `json:"key"`
	Role     string   `json:"role"`
	Patterns []string `json:"patterns"`
}

// Config holds runtime configuration loaded from the environment.
type Config struct {
	Port                  string
	DatabaseURL           string
	Catalog               *domains.Catalog
	Authz                 *authz.Registry
	LEEmail               string
	LEDirectory           string
	DataEncryptionKey     []byte
	GCPProject            string
	GCPServiceAccountJSON string
	DNSPropagationTimeout time.Duration
	RenewBeforeDays       int
	LogLevel              string
	MaxSANs               int
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Port:                  envOr("PORT", "8080"),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		LEEmail:               os.Getenv("LE_EMAIL"),
		GCPProject:            firstNonEmpty(os.Getenv("GCE_PROJECT"), os.Getenv("GCP_PROJECT")),
		GCPServiceAccountJSON: os.Getenv("GCP_SERVICE_ACCOUNT_JSON"),
		LogLevel:              envOr("LOG_LEVEL", "info"),
		MaxSANs:               envInt("MAX_SANS", 10),
		RenewBeforeDays:       envInt("RENEW_BEFORE_DAYS", 30),
	}

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

	entries, err := loadDomainCatalog(cfg.MaxSANs)
	if err != nil {
		return nil, err
	}
	catalog, err := domains.NewCatalog(entries, cfg.MaxSANs)
	if err != nil {
		return nil, fmt.Errorf("domain catalog: %w", err)
	}
	cfg.Catalog = catalog

	clients, err := loadAPIClients()
	if err != nil {
		return nil, err
	}
	reg, err := authz.NewRegistry(clients, catalog)
	if err != nil {
		return nil, fmt.Errorf("API clients: %w", err)
	}
	cfg.Authz = reg

	return cfg, nil
}

func loadDomainCatalog(maxSANs int) ([]domains.Entry, error) {
	_ = maxSANs
	raw := firstNonEmpty(os.Getenv("DOMAIN_CATALOG"), readFileEnv("DOMAIN_CATALOG_FILE"))
	if raw != "" {
		var list []catalogJSONEntry
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return nil, fmt.Errorf("DOMAIN_CATALOG JSON: %w", err)
		}
		out := make([]domains.Entry, 0, len(list))
		for _, e := range list {
			out = append(out, domains.Entry{Pattern: e.Pattern, Zone: e.Zone})
		}
		return out, nil
	}

	// Legacy: ALLOWED_DOMAINS + CLOUDDNS_ZONE
	domainsCSV := splitCSV(os.Getenv("ALLOWED_DOMAINS"))
	zone := strings.TrimSpace(os.Getenv("CLOUDDNS_ZONE"))
	if len(domainsCSV) == 0 {
		return nil, fmt.Errorf("DOMAIN_CATALOG (or legacy ALLOWED_DOMAINS) is required")
	}
	if zone == "" {
		return nil, fmt.Errorf("legacy ALLOWED_DOMAINS requires CLOUDDNS_ZONE (or use DOMAIN_CATALOG with per-pattern zones)")
	}
	out := make([]domains.Entry, 0, len(domainsCSV))
	for _, p := range domainsCSV {
		out = append(out, domains.Entry{Pattern: p, Zone: zone})
	}
	return out, nil
}

func loadAPIClients() ([]authz.Client, error) {
	raw := firstNonEmpty(os.Getenv("API_CLIENTS"), readFileEnv("API_CLIENTS_FILE"))
	if raw != "" {
		var list []clientJSON
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return nil, fmt.Errorf("API_CLIENTS JSON: %w", err)
		}
		out := make([]authz.Client, 0, len(list))
		for _, c := range list {
			out = append(out, authz.Client{
				ID:       c.ID,
				Key:      c.Key,
				Role:     c.Role,
				Patterns: c.Patterns,
			})
		}
		return out, nil
	}

	// Legacy: API_KEYS → admin clients
	keys := splitCSV(os.Getenv("API_KEYS"))
	if len(keys) == 0 {
		return nil, fmt.Errorf("API_CLIENTS (or legacy API_KEYS) is required")
	}
	out := make([]authz.Client, 0, len(keys))
	for i, k := range keys {
		out = append(out, authz.Client{
			ID:   fmt.Sprintf("legacy-admin-%d", i+1),
			Key:  k,
			Role: authz.RoleAdmin,
		})
	}
	return out, nil
}

func readFileEnv(envKey string) string {
	path := strings.TrimSpace(os.Getenv(envKey))
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
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
