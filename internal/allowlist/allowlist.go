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

package allowlist

import (
	"fmt"
	"net"
	"strings"
)

// List validates hostnames against configured patterns.
type List struct {
	patterns []string
	maxSANs  int
}

// New builds a List from domain patterns.
// Patterns are exact hostnames or single-label wildcards like *.apps.example.com.
func New(patterns []string, maxSANs int) (*List, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("allowlist requires at least one pattern")
	}
	if maxSANs < 0 {
		return nil, fmt.Errorf("maxSANs must be >= 0")
	}
	clean := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = normalize(p)
		if p == "" {
			return nil, fmt.Errorf("empty allowlist pattern")
		}
		if err := validatePattern(p); err != nil {
			return nil, err
		}
		clean = append(clean, p)
	}
	if maxSANs == 0 {
		maxSANs = 10
	}
	return &List{patterns: clean, maxSANs: maxSANs}, nil
}

// Allowed reports whether name matches the allowlist.
func (l *List) Allowed(name string) bool {
	name = normalize(name)
	if name == "" || !validHostname(name) {
		return false
	}
	for _, p := range l.patterns {
		if match(p, name) {
			return true
		}
	}
	return false
}

// ValidateNames checks CN and SANs against the allowlist and size limits.
// CN is included in the returned unique name set for ACME.
func (l *List) ValidateNames(cn string, sans []string) ([]string, error) {
	cn = normalize(cn)
	if cn == "" {
		return nil, fmt.Errorf("common_name is required")
	}
	if !validHostname(cn) && !isWildcardName(cn) {
		return nil, fmt.Errorf("invalid common_name %q", cn)
	}
	if !l.Allowed(cn) {
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
		if !l.Allowed(s) {
			return nil, fmt.Errorf("SAN %q is not allowlisted", s)
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		names = append(names, s)
	}
	// names[0] is CN; remaining are SANs for limit check
	if len(names)-1 > l.maxSANs {
		return nil, fmt.Errorf("too many SANs: %d > max %d", len(names)-1, l.maxSANs)
	}
	return names, nil
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

func validatePattern(p string) error {
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
		return fmt.Errorf("only single-label prefix wildcards are supported: %q", p)
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
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".apps.example.com"
		if !strings.HasSuffix(name, suffix) {
			return false
		}
		// single label before suffix: "foo" + ".apps.example.com"
		prefix := strings.TrimSuffix(name, suffix)
		if prefix == "" || strings.Contains(prefix, ".") {
			return false
		}
		return true
	}
	return false
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
	// allow wildcards only at start handled elsewhere
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		// require at least domain.tld
		return false
	}
	for _, label := range labels {
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
	}
	return true
}
