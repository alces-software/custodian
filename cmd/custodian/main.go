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

	"github.com/markt/custodian/internal/acme"
	"github.com/markt/custodian/internal/allowlist"
	"github.com/markt/custodian/internal/api"
	"github.com/markt/custodian/internal/config"
	"github.com/markt/custodian/internal/crypto"
	"github.com/markt/custodian/internal/store"
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
		fmt.Println("custodian 0.1.0")
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

	allow, err := allowlist.New(cfg.AllowedDomains, cfg.MaxSANs)
	if err != nil {
		log.Error("allowlist", "err", err)
		os.Exit(1)
	}

	issuer := acme.NewIssuer(acme.Config{
		Email:                 cfg.LEEmail,
		DirectoryURL:          cfg.LEDirectory,
		GCPProject:            cfg.GCPProject,
		CloudDNSZone:          cfg.CloudDNSZone,
		GCPServiceAccountJSON: cfg.GCPServiceAccountJSON,
		DNSPropagationTimeout: cfg.DNSPropagationTimeout,
	}, st, box)

	svc := acme.NewService(st, issuer, box, allow, cfg.RenewBeforeDays)
	srv := api.New(st, svc, cfg.APIKeys, log)

	addr := ":" + cfg.Port
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// ACME can take several minutes for DNS propagation
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("listening",
			"addr", addr,
			"le_directory", cfg.LEDirectory,
			"staging", cfg.IsStaging(),
			"allowed_domains", strings.Join(cfg.AllowedDomains, ","),
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
