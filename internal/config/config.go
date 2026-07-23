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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"alces/custodian/internal/domains"
)

// Directory aliases for Let's Encrypt.
const (
	DirectoryStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	DirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

type catalogJSONEntry struct {
	Pattern string `json:"pattern"`
	Zone    string `json:"zone"`
}

// Config holds runtime configuration loaded from the environment.
type Config struct {
	Port                  string
	DatabaseURL           string
	Catalog               *domains.Catalog
	AdminAPIKeys          []string
	RegistrarAPIKeys      []string
	LEEmail               string
	LEDirectory           string
	DataEncryptionKey     []byte
	GCPProject            string
	GCPServiceAccountJSON string
	DNSPropagationTimeout time.Duration
	RenewBeforeDays       int
	LogLevel              string
	MaxSANs               int
	WarnAPIClientsSet     bool
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
		WarnAPIClientsSet:     os.Getenv("API_CLIENTS") != "" || os.Getenv("API_CLIENTS_FILE") != "",
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

	entries, err := loadDomainCatalog()
	if err != nil {
		return nil, err
	}
	catalog, err := domains.NewCatalog(entries, cfg.MaxSANs)
	if err != nil {
		return nil, fmt.Errorf("domain catalog: %w", err)
	}
	cfg.Catalog = catalog

	// Admin keys: ADMIN_API_KEYS preferred; legacy API_KEYS
	cfg.AdminAPIKeys = splitCSV(firstNonEmpty(os.Getenv("ADMIN_API_KEYS"), os.Getenv("API_KEYS")))
	if len(cfg.AdminAPIKeys) == 0 {
		return nil, fmt.Errorf("ADMIN_API_KEYS (or legacy API_KEYS) is required")
	}
	cfg.RegistrarAPIKeys = splitCSV(os.Getenv("REGISTRAR_API_KEYS"))

	return cfg, nil
}

func loadDomainCatalog() ([]domains.Entry, error) {
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
