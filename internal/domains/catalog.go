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

package domains

import (
	"fmt"
	"net"
	"strings"
)

// Entry is one allowlisted pattern and its Cloud DNS managed zone.
type Entry struct {
	Pattern string
	Zone    string
}

// Catalog is the global set of allowed domain patterns with zone mapping.
type Catalog struct {
	entries []Entry
	maxSANs int
}

// NewCatalog builds a catalog from entries.
func NewCatalog(entries []Entry, maxSANs int) (*Catalog, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("domain catalog requires at least one entry")
	}
	if maxSANs <= 0 {
		maxSANs = 10
	}
	clean := make([]Entry, 0, len(entries))
	seen := map[string]struct{}{}
	for _, e := range entries {
		p := normalize(e.Pattern)
		z := strings.TrimSpace(e.Zone)
		if p == "" {
			return nil, fmt.Errorf("empty domain pattern")
		}
		if z == "" {
			return nil, fmt.Errorf("pattern %q requires a non-empty zone", p)
		}
		if err := validatePattern(p); err != nil {
			return nil, err
		}
		if _, ok := seen[p]; ok {
			return nil, fmt.Errorf("duplicate domain pattern %q", p)
		}
		seen[p] = struct{}{}
		clean = append(clean, Entry{Pattern: p, Zone: z})
	}
	return &Catalog{entries: clean, maxSANs: maxSANs}, nil
}

// Entries returns a copy of catalog entries.
func (c *Catalog) Entries() []Entry {
	out := make([]Entry, len(c.entries))
	copy(out, c.entries)
	return out
}

// Patterns returns just the patterns (for admin authz scope).
func (c *Catalog) Patterns() []string {
	out := make([]string, len(c.entries))
	for i, e := range c.entries {
		out[i] = e.Pattern
	}
	return out
}

// Allowed reports whether name matches any catalog pattern.
func (c *Catalog) Allowed(name string) bool {
	_, _, err := c.Resolve(name)
	return err == nil
}

// Resolve finds the most specific matching pattern and its zone for name.
func (c *Catalog) Resolve(name string) (pattern, zone string, err error) {
	name = normalize(name)
	if name == "" || (!validHostname(name) && !isWildcardName(name)) {
		return "", "", fmt.Errorf("invalid hostname %q", name)
	}
	var best *Entry
	bestScore := -1
	for i := range c.entries {
		e := &c.entries[i]
		if !match(e.Pattern, name) {
			continue
		}
		score := specificity(e.Pattern)
		if score > bestScore {
			bestScore = score
			best = e
		}
	}
	if best == nil {
		return "", "", fmt.Errorf("name %q is not in the domain catalog", name)
	}
	return best.Pattern, best.Zone, nil
}

// NameSet is a validated certificate name set with a single DNS zone.
type NameSet struct {
	Names []string // CN first, then unique SANs
	Zone  string
}

// ValidateNames checks CN/SANs against the catalog, enforces SAN limit,
// and requires all names to resolve to the same Cloud DNS zone.
func (c *Catalog) ValidateNames(cn string, sans []string) (*NameSet, error) {
	cn = normalize(cn)
	if cn == "" {
		return nil, fmt.Errorf("common_name is required")
	}
	if !validHostname(cn) && !isWildcardName(cn) {
		return nil, fmt.Errorf("invalid common_name %q", cn)
	}
	_, zone, err := c.Resolve(cn)
	if err != nil {
		return nil, fmt.Errorf("common_name %q is not allowlisted", cn)
	}

	seen := map[string]struct{}{cn: {}}
	names := []string{cn}
	for _, s := range sans {
		s = normalize(s)
		if s == "" {
			continue
		}
		if !validHostname(s) && !isWildcardName(s) {
			return nil, fmt.Errorf("invalid SAN %q", s)
		}
		_, z, err := c.Resolve(s)
		if err != nil {
			return nil, fmt.Errorf("SAN %q is not allowlisted", s)
		}
		if z != zone {
			return nil, fmt.Errorf("names span multiple Cloud DNS zones (%q vs %q); use separate certificates", zone, z)
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		names = append(names, s)
	}
	if len(names)-1 > c.maxSANs {
		return nil, fmt.Errorf("too many SANs: %d > max %d", len(names)-1, c.maxSANs)
	}
	return &NameSet{Names: names, Zone: zone}, nil
}

// PatternCovers reports whether scopePattern allows targetName
// (exact, single-label *, or multi-label ** wildcards).
func PatternCovers(scopePattern, targetName string) bool {
	return match(normalize(scopePattern), normalize(targetName))
}

// PatternsCoverAll reports whether every name is covered by at least one scope pattern.
func PatternsCoverAll(scopePatterns []string, names []string) bool {
	for _, n := range names {
		ok := false
		for _, p := range scopePatterns {
			if PatternCovers(p, n) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// specificity scores patterns so more specific wins.
// Exact > single-label * > multi-label **; longer bases beat shorter.
func specificity(pattern string) int {
	p := normalize(pattern)
	score := len(p) * 10
	switch {
	case strings.HasPrefix(p, "**."):
		score -= 50 // multi-label: least specific wildcard
	case strings.HasPrefix(p, "*."):
		score -= 5
	default:
		score += 1000
	}
	return score
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

func validatePattern(p string) error {
	// Multi-label: **.example.com
	if strings.HasPrefix(p, "**.") {
		rest := strings.TrimPrefix(p, "**.")
		if rest == "" || strings.Contains(rest, "*") {
			return fmt.Errorf("invalid multi-label wildcard pattern %q", p)
		}
		if !validHostname(rest) {
			return fmt.Errorf("invalid multi-label wildcard pattern %q", p)
		}
		return nil
	}
	// Single-label: *.example.com
	if strings.HasPrefix(p, "*.") {
		rest := strings.TrimPrefix(p, "*.")
		if rest == "" || strings.Contains(rest, "*") {
			return fmt.Errorf("invalid wildcard pattern %q", p)
		}
		if !validHostname(rest) {
			return fmt.Errorf("invalid wildcard pattern %q", p)
		}
		return nil
	}
	if strings.Contains(p, "*") {
		return fmt.Errorf("unsupported wildcard form %q (use *.base or **.base)", p)
	}
	if !validHostname(p) {
		return fmt.Errorf("invalid pattern %q", p)
	}
	return nil
}

func match(pattern, name string) bool {
	if pattern == name {
		return true
	}
	// Multi-label first (**.) so we don't confuse with other forms.
	if strings.HasPrefix(pattern, "**.") {
		rest := strings.TrimPrefix(pattern, "**.")
		suffix := "." + rest
		if !strings.HasSuffix(name, suffix) {
			return false
		}
		prefix := strings.TrimSuffix(name, suffix)
		// Require at least one label under the base (not the apex itself).
		if prefix == "" || strings.HasPrefix(prefix, ".") || strings.HasSuffix(prefix, ".") || strings.Contains(prefix, "..") {
			return false
		}
		// Every label in the prefix must be a valid DNS label.
		for _, label := range strings.Split(prefix, ".") {
			if !validDNSLabel(label) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".apps.example.com"
		if !strings.HasSuffix(name, suffix) {
			return false
		}
		prefix := strings.TrimSuffix(name, suffix)
		// Single label only.
		if prefix == "" || strings.Contains(prefix, ".") {
			return false
		}
		return validDNSLabel(prefix)
	}
	return false
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func isWildcardName(name string) bool {
	return strings.HasPrefix(name, "*.") && validHostname(strings.TrimPrefix(name, "*."))
}

func validHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if ip := net.ParseIP(name); ip != nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}
