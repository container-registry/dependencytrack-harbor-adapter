package etc

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Versioner is satisfied by the syft wrapper; the checker uses it to prove the
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
// syft binary must be exec-able (captures its version once), Dependency-Track
// must accept the API key, and Redis must be reachable when the store backend is
// redis.
func Check(ctx context.Context, config Config, versioner Versioner, pinger Pinger, dtrack Pinger) error {
	slog.Debug("Current process", slog.Int("pid", os.Getpid()))
	slog.Debug("Current user",
		slog.Int("uid", os.Getuid()),
		slog.Int("gid", os.Getegid()),
		slog.String("home_dir", os.Getenv("HOME")),
	)

	if config.Syft.WorkDir == "" {
		return fmt.Errorf("syft work dir must not be blank")
	}
	if err := ensureDirWritable(config.Syft.WorkDir); err != nil {
		return fmt.Errorf("work dir not usable: %w", err)
	}

	// syft fails on an unreadable CA bundle only once a scan is in flight, where
	// it surfaces as a failed Harbor scan rather than as a broken deployment.
	// Check the path at startup instead.
	if config.Syft.RegistryCACert != "" {
		if err := checkCertBundle(config.Syft.RegistryCACert); err != nil {
			return fmt.Errorf("registry CA certificate %s: %w", config.Syft.RegistryCACert, err)
		}
	}
	if config.Syft.InsecureSkipVerify {
		slog.Warn("TLS verification is DISABLED for registry pulls (SCANNER_SYFT_INSECURE_TLS_SKIP_VERIFY); " +
			"use SCANNER_SYFT_REGISTRY_CA_CERT in production")
	}
	if config.DTrack.InsecureSkipVerify {
		slog.Warn("TLS verification is DISABLED for Dependency-Track (SCANNER_DTRACK_INSECURE_TLS_SKIP_VERIFY)")
	}

	if versioner != nil {
		version, err := versioner.Version(ctx)
		if err != nil {
			return fmt.Errorf("syft binary not exec-able (%s): %w", config.Syft.Binary, err)
		}
		slog.Info("syft binary is exec-able", slog.String("version", version))
	}

	// An unreachable Dependency-Track or a key without BOM_UPLOAD is a
	// misconfiguration that would otherwise only show up as a per-scan upload
	// failure, long after the deployment looked healthy.
	if config.DTrack.URL != "" && dtrack != nil {
		if err := dtrack.Ping(ctx); err != nil {
			return fmt.Errorf("dependency-track not reachable at %s: %w", config.DTrack.URL, err)
		}
		slog.Info("dependency-track is reachable", slog.String("url", config.DTrack.URL))
	} else if config.DTrack.URL == "" {
		slog.Warn("SCANNER_DTRACK_URL is unset; SBOMs will be returned to Harbor but not uploaded to Dependency-Track")
	}

	if config.API.IsTLSEnabled() {
		if err := checkReadable(config.API.TLSCertificate); err != nil {
			return fmt.Errorf("TLS certificate %s: %w", config.API.TLSCertificate, err)
		}
		if err := checkReadable(config.API.TLSKey); err != nil {
			return fmt.Errorf("TLS private key %s: %w", config.API.TLSKey, err)
		}
		for _, path := range config.API.ClientCAs {
			if err := checkCertBundle(path); err != nil {
				return fmt.Errorf("client CA %s: %w", path, err)
			}
		}
	}

	if config.Store.Backend == StoreBackendRedis && pinger != nil {
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

// checkReadable opens the file rather than stat-ing it. A stat passes on a file
// the process cannot read -- the usual case being a Secret mounted with the
// wrong mode or fsGroup -- and the failure then surfaced on the first scan or on
// the TLS handshake instead of at startup.
func checkReadable(name string) error {
	info, err := os.Stat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("is a directory, not a file")
	}
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	return f.Close()
}

// checkCertBundle additionally parses the bundle. An unparseable CA file yields
// an empty pool, and an empty pool with RequireAndVerifyClientCert rejects every
// client certificate -- a total outage that presents as a per-client TLS error.
func checkCertBundle(name string) error {
	if err := checkReadable(name); err != nil {
		return err
	}
	pem, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return fmt.Errorf("contains no usable certificate")
	}
	return nil
}
