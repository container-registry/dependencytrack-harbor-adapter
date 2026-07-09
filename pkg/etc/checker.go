package etc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Versioner is satisfied by the mikebom wrapper; the checker uses it to prove the
// binary is exec-able at startup.
type Versioner interface {
	Version(ctx context.Context) (string, error)
}

// Pinger is satisfied by a Redis client; the checker uses it to prove Redis is
// reachable when the store backend is redis.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Check fails fast on an unusable environment: work dir must be writable, the
// mikebom binary must be exec-able (captures its version once), and Redis must be
// reachable when the store backend is redis.
func Check(ctx context.Context, config Config, versioner Versioner, pinger Pinger) error {
	slog.Debug("Current process", slog.Int("pid", os.Getpid()))
	slog.Debug("Current user",
		slog.Int("uid", os.Getuid()),
		slog.Int("gid", os.Getegid()),
		slog.String("home_dir", os.Getenv("HOME")),
	)

	if config.Mikebom.WorkDir == "" {
		return fmt.Errorf("mikebom work dir must not be blank")
	}
	if err := ensureDirWritable(config.Mikebom.WorkDir); err != nil {
		return fmt.Errorf("work dir not usable: %w", err)
	}

	if versioner != nil {
		version, err := versioner.Version(ctx)
		if err != nil {
			return fmt.Errorf("mikebom binary not exec-able (%s): %w", config.Mikebom.Binary, err)
		}
		slog.Info("mikebom binary is exec-able", slog.String("version", version))
	}

	if config.API.IsTLSEnabled() {
		if !fileExists(config.API.TLSCertificate) {
			return fmt.Errorf("TLS certificate file does not exist: %s", config.API.TLSCertificate)
		}
		if !fileExists(config.API.TLSKey) {
			return fmt.Errorf("TLS private key file does not exist: %s", config.API.TLSKey)
		}
		for _, path := range config.API.ClientCAs {
			if !fileExists(path) {
				return fmt.Errorf("ClientCA file does not exist: %s", path)
			}
		}
	}

	if strings.EqualFold(config.Store.Backend, "redis") && pinger != nil {
		if err := pinger.Ping(ctx); err != nil {
			return fmt.Errorf("redis not reachable: %w", err)
		}
		slog.Info("redis is reachable")
	}

	return nil
}

// SweepStaleWorkDirs removes leftover per-job scratch dirs (scan-*) at startup so
// a crash/restart does not accumulate disk (plan m6, D-6).
func SweepStaleWorkDirs(workDir string) error {
	entries, err := os.ReadDir(workDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "scan-") {
			p := filepath.Join(workDir, e.Name())
			slog.Info("Sweeping stale work dir", slog.String("path", p))
			if err := os.RemoveAll(p); err != nil {
				slog.Warn("Failed to sweep stale work dir", slog.String("path", p), slog.String("err", err.Error()))
			}
		}
	}
	return nil
}

func ensureDirWritable(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("creating %q: %w", path, err)
	}
	probe := filepath.Join(path, ".write-probe")
	if err := os.WriteFile(probe, []byte("ok\n"), 0o600); err != nil {
		return fmt.Errorf("%q not writable: %w", path, err)
	}
	_ = os.Remove(probe)
	return nil
}

func fileExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && !info.IsDir()
}
