package authz

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/markt/custodian/internal/domains"
	"github.com/markt/custodian/internal/store"
)

// Roles.
const (
	RoleAdmin  = "admin"
	RoleTenant = "tenant"
)

// Client is an authenticated API principal.
type Client struct {
	ID       string
	Key      string
	Role     string
	Patterns []string // domain patterns this client may access
}

// IsAdmin reports whether the client has the admin role.
func (c *Client) IsAdmin() bool {
	return c != nil && c.Role == RoleAdmin
}

// Registry maps API keys to clients.
type Registry struct {
	clients []*Client
	catalog *domains.Catalog
}

// NewRegistry validates and builds a registry.
func NewRegistry(clients []Client, catalog *domains.Catalog) (*Registry, error) {
	if catalog == nil {
		return nil, fmt.Errorf("catalog is required")
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("at least one API client is required")
	}
	out := make([]*Client, 0, len(clients))
	ids := map[string]struct{}{}
	keys := map[string]struct{}{}
	for i := range clients {
		c := clients[i]
		c.ID = strings.TrimSpace(c.ID)
		c.Key = strings.TrimSpace(c.Key)
		c.Role = strings.ToLower(strings.TrimSpace(c.Role))
		if c.ID == "" {
			return nil, fmt.Errorf("client id is required")
		}
		if c.Key == "" {
			return nil, fmt.Errorf("client %q: key is required", c.ID)
		}
		if _, ok := ids[c.ID]; ok {
			return nil, fmt.Errorf("duplicate client id %q", c.ID)
		}
		if _, ok := keys[c.Key]; ok {
			return nil, fmt.Errorf("duplicate API key for client %q", c.ID)
		}
		switch c.Role {
		case RoleAdmin:
			if len(c.Patterns) == 0 {
				c.Patterns = catalog.Patterns()
			}
		case RoleTenant, "":
			c.Role = RoleTenant
			if len(c.Patterns) == 0 {
				return nil, fmt.Errorf("client %q: tenant requires patterns", c.ID)
			}
		default:
			return nil, fmt.Errorf("client %q: unknown role %q", c.ID, c.Role)
		}
		cleanPatterns := make([]string, 0, len(c.Patterns))
		for _, p := range c.Patterns {
			p = strings.TrimSpace(strings.ToLower(p))
			if p == "" {
				continue
			}
			if !catalogPatternOrNameAllowed(catalog, p) {
				return nil, fmt.Errorf("client %q: pattern %q is outside the domain catalog", c.ID, p)
			}
			cleanPatterns = append(cleanPatterns, p)
		}
		if len(cleanPatterns) == 0 {
			return nil, fmt.Errorf("client %q: no valid patterns", c.ID)
		}
		c.Patterns = cleanPatterns
		ids[c.ID] = struct{}{}
		keys[c.Key] = struct{}{}
		cp := c
		out = append(out, &cp)
	}
	return &Registry{clients: out, catalog: catalog}, nil
}

func catalogPatternOrNameAllowed(catalog *domains.Catalog, p string) bool {
	for _, e := range catalog.Entries() {
		if e.Pattern == p {
			return true
		}
	}
	// Concrete hostname under the catalog.
	if catalog.Allowed(p) {
		return true
	}
	// Wildcard scope (e.g. *.pay.example.com): valid if a sample name under it is allowlisted.
	if strings.HasPrefix(p, "*.") {
		sample := "scopecheck." + strings.TrimPrefix(p, "*.")
		return catalog.Allowed(sample)
	}
	return false
}

// Authenticate validates a bearer token and returns the client.
func (r *Registry) Authenticate(token string) (*Client, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	var match *Client
	for _, c := range r.clients {
		kb := []byte(c.Key)
		tb := []byte(token)
		if len(tb) != len(kb) {
			continue
		}
		if subtle.ConstantTimeCompare(tb, kb) == 1 {
			match = c
		}
	}
	if match == nil {
		return nil, fmt.Errorf("invalid API key")
	}
	return match, nil
}

// CanAccessNames reports whether the client may act on all given names.
func (r *Registry) CanAccessNames(c *Client, names []string) bool {
	if c == nil || len(names) == 0 {
		return false
	}
	for _, n := range names {
		if !r.catalog.Allowed(n) {
			return false
		}
	}
	if c.IsAdmin() {
		return true
	}
	return domains.PatternsCoverAll(c.Patterns, names)
}

// CertNames returns CN + SANs for a certificate.
func CertNames(cert *store.Certificate) []string {
	if cert == nil {
		return nil
	}
	names := make([]string, 0, 1+len(cert.SANs))
	names = append(names, cert.CommonName)
	names = append(names, cert.SANs...)
	return names
}

// CanAccessCert reports whether the client may access the certificate.
func (r *Registry) CanAccessCert(c *Client, cert *store.Certificate) bool {
	return r.CanAccessNames(c, CertNames(cert))
}

// HasAdmin returns true if any client is an admin.
func (r *Registry) HasAdmin() bool {
	for _, c := range r.clients {
		if c.IsAdmin() {
			return true
		}
	}
	return false
}
