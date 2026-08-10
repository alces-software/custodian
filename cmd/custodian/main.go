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

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"alces/custodian/internal/acme"
	"alces/custodian/internal/api"
	"alces/custodian/internal/authz"
	"alces/custodian/internal/clihost"
	"alces/custodian/internal/config"
	"alces/custodian/internal/crypto"
	"alces/custodian/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: custodian <serve|version>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serveCmd(os.Args[2:])
	case "version":
		fmt.Println("custodian 0.3.0")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	log := newLogger(cfg.LogLevel)
	ctx := context.Background()

	if cfg.WarnAPIClientsSet {
		log.Warn("API_CLIENTS is deprecated and ignored; use client-held access keys via POST /v1/access-keys")
	}

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	box, err := crypto.NewBox(cfg.DataEncryptionKey)
	if err != nil {
		log.Error("crypto", "err", err)
		os.Exit(1)
	}

	authn, err := authz.NewAuthenticator(cfg.AdminAPIKeys, cfg.RegistrarAPIKeys, st)
	if err != nil {
		log.Error("auth", "err", err)
		os.Exit(1)
	}
	if !authn.HasRegistrar() {
		log.Warn("REGISTRAR_API_KEYS is empty; only admin can register access keys")
	}

	issuer := acme.NewIssuer(acme.Config{
		Email:                 cfg.LEEmail,
		DirectoryURL:          cfg.LEDirectory,
		GCPProject:            cfg.GCPProject,
		GCPServiceAccountJSON: cfg.GCPServiceAccountJSON,
		DNSPropagationTimeout: cfg.DNSPropagationTimeout,
	}, st, box)

	svc := acme.NewService(st, issuer, box, cfg.Catalog, cfg.RenewBeforeDays)
	cliHost := clihost.New(cfg.CLIBinariesDir)
	if cliHost.Enabled() {
		if st, err := os.Stat(cfg.CLIBinariesDir); err != nil || !st.IsDir() {
			log.Warn("CLI_BINARIES_DIR not found; /cli downloads disabled", "dir", cfg.CLIBinariesDir, "err", err)
			cliHost = clihost.New("")
		}
	}
	srv := api.New(st, svc, authn, cliHost, log)

	addr := ":" + cfg.Port
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}

	patterns := cfg.Catalog.Patterns()
	go func() {
		log.Info("listening",
			"addr", addr,
			"le_directory", cfg.LEDirectory,
			"staging", cfg.IsStaging(),
			"catalog_patterns", strings.Join(patterns, ","),
			"has_registrar", authn.HasRegistrar(),
			"cli_binaries", cfg.CLIBinariesDir,
			"cli_downloads", cliHost.Enabled(),
		)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
