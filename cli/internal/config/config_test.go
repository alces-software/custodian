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

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"alces/custodian-cli/internal/config"
)

func TestResolve_FlagsBeatEnvBeatFile(t *testing.T) {
	path := writeConfig(t, "url: https://from-file\nauth_key: file-key\n")
	t.Setenv("CUSTODIAN_URL", "https://from-env")
	t.Setenv("CUSTODIAN_AUTH_KEY", "env-key")

	got, err := config.Resolve(config.Options{
		ConfigPath: path,
		URL:        "https://from-flag",
		AuthKey:    "flag-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://from-flag" || got.AuthKey != "flag-key" {
		t.Fatalf("got %+v", got)
	}
}

func TestResolve_EnvBeatsFile(t *testing.T) {
	path := writeConfig(t, "url: https://from-file\nauth_key: file-key\n")
	t.Setenv("CUSTODIAN_URL", "https://from-env")
	t.Setenv("CUSTODIAN_AUTH_KEY", "env-key")

	got, err := config.Resolve(config.Options{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://from-env" || got.AuthKey != "env-key" {
		t.Fatalf("got %+v", got)
	}
}

func TestResolve_ProfileIgnoresRoot(t *testing.T) {
	yaml := `
url: https://root
auth_key: root-key
profiles:
  staging:
    url: https://staging
    auth_key: staging-key
`
	path := writeConfig(t, yaml)
	t.Setenv("CUSTODIAN_URL", "")
	t.Setenv("CUSTODIAN_AUTH_KEY", "")

	got, err := config.Resolve(config.Options{ConfigPath: path, Profile: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://staging" || got.AuthKey != "staging-key" {
		t.Fatalf("got %+v", got)
	}
}

func TestResolve_UnknownProfile(t *testing.T) {
	path := writeConfig(t, "profiles:\n  a:\n    url: https://a\n    auth_key: k\n")
	_, err := config.Resolve(config.Options{ConfigPath: path, Profile: "missing"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolve_MissingFileOK(t *testing.T) {
	t.Setenv("CUSTODIAN_URL", "https://only-env")
	t.Setenv("CUSTODIAN_AUTH_KEY", "only-env-key")
	got, err := config.Resolve(config.Options{
		ConfigPath: filepath.Join(t.TempDir(), "nope.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://only-env" || got.AuthKey != "only-env-key" {
		t.Fatalf("got %+v", got)
	}
}

func TestResolve_TrimsTrailingSlash(t *testing.T) {
	t.Setenv("CUSTODIAN_URL", "https://example.com/")
	t.Setenv("CUSTODIAN_AUTH_KEY", "k")
	got, err := config.Resolve(config.Options{
		ConfigPath: filepath.Join(t.TempDir(), "nope.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://example.com" {
		t.Fatalf("got %q", got.URL)
	}
}

func TestResolved_RequireAuth(t *testing.T) {
	if err := (config.Resolved{}).RequireAuth(); err == nil {
		t.Fatal("expected error")
	}
	if err := (config.Resolved{URL: "https://x", AuthKey: "k"}).RequireAuth(); err != nil {
		t.Fatal(err)
	}
}

func TestFindConfigPath_PrefersUserOverInstall(t *testing.T) {
	root := t.TempDir()
	xdg := filepath.Join(root, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	userPath := filepath.Join(xdg, "custodian", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte("url: https://user\nauth_key: u\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Install layout: bin/custodian + etc/config.yaml
	binDir := filepath.Join(root, "opt", "bin")
	etcDir := filepath.Join(root, "opt", "etc")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(binDir, "custodian")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	installPath := filepath.Join(etcDir, "config.yaml")
	if err := os.WriteFile(installPath, []byte("url: https://install\nauth_key: i\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.SetExecutablePathForTest(t, fakeBin)

	if got := config.FindConfigPath(); got != userPath {
		t.Fatalf("FindConfigPath = %q, want user %q", got, userPath)
	}
}

func TestFindConfigPath_FallsBackToInstall(t *testing.T) {
	root := t.TempDir()
	xdg := filepath.Join(root, "xdg-empty")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	binDir := filepath.Join(root, "share", "bin")
	etcDir := filepath.Join(root, "share", "etc")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(binDir, "custodian")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	installPath := filepath.Join(etcDir, "config.yaml")
	if err := os.WriteFile(installPath, []byte("url: https://install\nauth_key: i\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.SetExecutablePathForTest(t, fakeBin)

	if got := config.FindConfigPath(); !samePath(got, installPath) {
		t.Fatalf("FindConfigPath = %q, want install %q", got, installPath)
	}

	// Resolve should load install config when no path given.
	t.Setenv("CUSTODIAN_URL", "")
	t.Setenv("CUSTODIAN_AUTH_KEY", "")
	got, err := config.Resolve(config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://install" || got.AuthKey != "i" {
		t.Fatalf("got %+v", got)
	}
}

func TestInstallConfigPath(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(binDir, "custodian")
	if err := os.WriteFile(fakeBin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	config.SetExecutablePathForTest(t, fakeBin)

	got, err := config.InstallConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	// Eval root so macOS /var vs /private/var matches EvalSymlinks on the binary.
	evalRoot := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		evalRoot = r
	}
	want := filepath.Clean(filepath.Join(evalRoot, "etc", "config.yaml"))
	if filepath.Clean(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// samePath compares paths after EvalSymlinks when possible (macOS /var → /private/var).
func samePath(a, b string) bool {
	eval := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(r)
		}
		// Path may not exist yet: resolve existing prefix.
		dir := filepath.Dir(p)
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Clean(filepath.Join(r, filepath.Base(p)))
		}
		return filepath.Clean(p)
	}
	return eval(a) == eval(b)
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
