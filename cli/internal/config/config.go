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

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Options are inputs from CLI flags (empty string means not set).
type Options struct {
	ConfigPath string
	Profile    string
	URL        string
	AuthKey    string
}

// Resolved is the effective connection config.
type Resolved struct {
	URL     string
	AuthKey string
}

// File is the on-disk YAML shape.
type File struct {
	URL      string             `yaml:"url"`
	AuthKey  string             `yaml:"auth_key"`
	Profiles map[string]Profile `yaml:"profiles"`
}

// Profile is a named connection.
type Profile struct {
	URL     string `yaml:"url"`
	AuthKey string `yaml:"auth_key"`
}

// executablePath is os.Executable; overridden in tests via SetExecutablePathForTest.
var executablePath = os.Executable

// SetExecutablePathForTest overrides binary path discovery (tests only).
func SetExecutablePathForTest(t interface{ Cleanup(func()) }, path string) {
	prev := executablePath
	executablePath = func() (string, error) { return path, nil }
	t.Cleanup(func() { executablePath = prev })
}

// UserConfigPath returns the XDG / home config path
// ($XDG_CONFIG_HOME/custodian/config.yaml or ~/.config/custodian/config.yaml).
func UserConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "custodian", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(home, ".config", "custodian", "config.yaml")
}

// DefaultConfigPath is an alias for UserConfigPath (historical name).
func DefaultConfigPath() string {
	return UserConfigPath()
}

// InstallConfigPath returns ../etc/config.yaml relative to the binary
// (after resolving symlinks). Suitable for standalone / network-share installs.
func InstallConfigPath() (string, error) {
	exe, err := executablePath()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	return filepath.Clean(filepath.Join(dir, "..", "etc", "config.yaml")), nil
}

// FindConfigPath picks which config file to load when --config is unset.
// Preference: existing user/XDG config, else existing install ../etc/config.yaml,
// else the user path (may not exist — then only flags/env apply).
func FindConfigPath() string {
	user := UserConfigPath()
	if fileExists(user) {
		return user
	}
	if install, err := InstallConfigPath(); err == nil && fileExists(install) {
		return install
	}
	return user
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// Resolve merges flags > env > file (profile or root defaults).
// When ConfigPath is empty, uses FindConfigPath().
func Resolve(opt Options) (Resolved, error) {
	path := opt.ConfigPath
	if path == "" {
		path = FindConfigPath()
	}

	var fileURL, fileKey string
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return Resolved{}, fmt.Errorf("read config %s: %w", path, err)
		}
	} else {
		var f File
		if err := yaml.Unmarshal(data, &f); err != nil {
			return Resolved{}, fmt.Errorf("parse config %s: %w", path, err)
		}
		if opt.Profile != "" {
			p, ok := f.Profiles[opt.Profile]
			if !ok {
				return Resolved{}, fmt.Errorf("unknown profile %q in %s", opt.Profile, path)
			}
			fileURL, fileKey = p.URL, p.AuthKey
		} else {
			fileURL, fileKey = f.URL, f.AuthKey
		}
	}

	url := firstNonEmpty(opt.URL, strings.TrimSpace(os.Getenv("CUSTODIAN_URL")), fileURL)
	key := firstNonEmpty(opt.AuthKey, strings.TrimSpace(os.Getenv("CUSTODIAN_AUTH_KEY")), fileKey)

	return Resolved{
		URL:     strings.TrimRight(url, "/"),
		AuthKey: key,
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// RequireAuth ensures URL and auth key are present.
func (r Resolved) RequireAuth() error {
	if r.URL == "" {
		return fmt.Errorf("missing server URL: set --url, CUSTODIAN_URL, or config file")
	}
	if r.AuthKey == "" {
		return fmt.Errorf("missing auth key: set --auth-key, CUSTODIAN_AUTH_KEY, or config file")
	}
	return nil
}

// RequireURL ensures base URL is present (for unauthenticated health).
func (r Resolved) RequireURL() error {
	if r.URL == "" {
		return fmt.Errorf("missing server URL: set --url, CUSTODIAN_URL, or config file")
	}
	return nil
}
