// Command scanner-mikebom is the Harbor Pluggable Scanner Adapter that wraps the
// mikebom SBOM CLI. This file is an M2 scaffold stub: it builds, starts an HTTP
// server exposing liveness/readiness probes and a placeholder metadata endpoint,
// and proves the runtime contract (non-root uid, read-only root filesystem,
// writable work dir). The real adapter (config, queue, store, mikebom wrapper,
// scan controller, contract-tested API) lands in M3.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// Stamped at build time by the Taskfile ldflags (-X main.version=... etc.).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("scanner-mikebom %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("fatal", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	addr := envOr("SCANNER_API_ADDR", ":8080")
	home := os.Getenv("HOME")
	workDir := envOr("SCANNER_MIKEBOM_WORK_DIR", filepath.Join(home, "work"))

	slog.Info("starting scanner-mikebom",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("built_at", date),
		slog.Int("uid", os.Getuid()),
		slog.Int("gid", os.Getgid()),
		slog.String("home", home),
		slog.String("work_dir", workDir),
	)

	// Prove the work dir is writable (per-job scratch lives here; K8s mounts an
	// emptyDir, compose a tmpfs, at this path under a read-only root filesystem).
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fmt.Errorf("creating work dir %q: %w", workDir, err)
	}
	sentinel := filepath.Join(workDir, ".write-probe")
	if err := os.WriteFile(sentinel, []byte("ok\n"), 0o600); err != nil {
		return fmt.Errorf("work dir %q not writable: %w", workDir, err)
	}
	_ = os.Remove(sentinel)
	slog.Info("work dir writable", slog.String("work_dir", workDir))

	// Confirm the root filesystem is read-only (defense-in-depth expectation).
	rootWritable := os.WriteFile("/.rootfs-write-probe", []byte("x"), 0o600) == nil
	if rootWritable {
		_ = os.Remove("/.rootfs-write-probe")
		slog.Warn("root filesystem is writable; expected read-only in production")
	} else {
		slog.Info("root filesystem is read-only")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/probe/healthy", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/probe/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/metadata", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.scanner.adapter.metadata+json; version=1.0")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"scanner":    map[string]string{"name": "mikebom", "vendor": "Kusari", "version": version},
			"properties": map[string]string{"org.label-schema.version": version},
		})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", slog.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		slog.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func logLevel() slog.Level {
	switch os.Getenv("SCANNER_LOG_LEVEL") {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "warn", "WARN":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
