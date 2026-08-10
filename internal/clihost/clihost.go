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

package clihost

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Host serves prebuilt CLI binaries from a directory (no auth).
type Host struct {
	Dir string
}

// New returns a Host for dir. Empty dir disables hosting (404).
func New(dir string) *Host {
	return &Host{Dir: strings.TrimSpace(dir)}
}

// Enabled reports whether a directory is configured.
func (h *Host) Enabled() bool {
	return h != nil && h.Dir != ""
}

// Mount registers public GET routes under /cli on r.
// Expected layout (built into the image):
//
//	custodian                 → linux/amd64 (default wget target)
//	custodian-linux-amd64
//	custodian-linux-arm64
//	custodian-darwin-amd64
//	custodian-darwin-arm64
//	SHA256SUMS               → optional checksums file
func (h *Host) Mount(mux interface {
	Get(pattern string, handlerFn http.HandlerFunc)
}) {
	if !h.Enabled() {
		mux.Get("/cli", h.disabled)
		mux.Get("/cli/*", h.disabled)
		return
	}
	mux.Get("/cli", h.handleIndex)
	mux.Get("/cli/", h.handleIndex)
	mux.Get("/cli/*", h.handleFile)
}

func (h *Host) disabled(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "CLI binaries not available on this server", http.StatusNotFound)
}

func (h *Host) handleIndex(w http.ResponseWriter, r *http.Request) {
	entries, err := h.list()
	if err != nil {
		http.Error(w, "CLI directory unavailable", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	base := strings.TrimRight(r.URL.Path, "/")
	if base == "" {
		base = "/cli"
	}
	fmt.Fprintf(w, "# Custodian CLI downloads\n")
	fmt.Fprintf(w, "# wget -O custodian %s/custodian && chmod +x custodian\n\n", absoluteCLIBase(r))
	for _, name := range entries {
		fmt.Fprintf(w, "%s/%s\n", absoluteCLIBase(r), name)
	}
}

func absoluteCLIBase(r *http.Request) string {
	// Prefer forwarded proto/host behind Dokku/nginx
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return fmt.Sprintf("%s://%s/cli", proto, host)
}

func (h *Host) handleFile(w http.ResponseWriter, r *http.Request) {
	// chi wildcard: /cli/* → path after /cli/
	name := strings.TrimPrefix(r.URL.Path, "/cli/")
	name = path.Clean("/" + name)
	name = strings.TrimPrefix(name, "/")
	if name == "" || name == "." {
		h.handleIndex(w, r)
		return
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	full := filepath.Join(h.Dir, name)
	// Ensure resolved path stays under Dir
	dirAbs, err := filepath.Abs(h.Dir)
	if err != nil {
		http.Error(w, "CLI directory unavailable", http.StatusNotFound)
		return
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil || !strings.HasPrefix(fullAbs, dirAbs+string(os.PathSeparator)) && fullAbs != dirAbs {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	fi, err := os.Stat(fullAbs)
	if err != nil || fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	f, err := os.Open(fullAbs)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, f)
}

func (h *Host) list() ([]string, error) {
	ents, err := os.ReadDir(h.Dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
