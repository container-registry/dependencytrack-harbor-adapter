// Package etc holds the adapter configuration (all env, SCANNER_ prefix) and a
// startup checker that fails fast on an unusable environment.
package etc

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
)

// Recognized values for SCANNER_STORE_BACKEND, in their canonical (normalized)
// form. Anything else is rejected at startup rather than silently taking the
// Redis path.
const (
	StoreBackendRedis  = "redis"
	StoreBackendMemory = "memory"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API        API
	Waybill    Waybill
	Store      Store
	RedisStore RedisStore
	JobQueue   JobQueue
	RedisPool  RedisPool
}

type Waybill struct {
	Binary       string        `env:"SCANNER_WAYBILL_BINARY" envDefault:"/usr/local/bin/waybill"`
	WorkDir      string        `env:"SCANNER_WAYBILL_WORK_DIR" envDefault:"/home/scanner/work"`
	Timeout      time.Duration `env:"SCANNER_WAYBILL_TIMEOUT" envDefault:"5m0s"`
	OCICacheSize int           `env:"SCANNER_WAYBILL_OCI_CACHE_SIZE" envDefault:"0"`
	// Enrichment, when true, drops the --offline flag so waybill's deps.dev /
	// ClearlyDefined enrichment can run. Default false = offline (egress
	// control). See docs/spike-m1.md: WAYBILL_OFFLINE=1 alone does NOT disable
	// enrichment; only the --offline CLI flag does.
	Enrichment    bool     `env:"SCANNER_WAYBILL_ENRICHMENT" envDefault:"false"`
	ImagePlatform string   `env:"SCANNER_WAYBILL_IMAGE_PLATFORM"`
	ExtraArgs     []string `env:"SCANNER_WAYBILL_EXTRA_ARGS" envSeparator:" "`

	// RegistryCACerts are PEM bundles added to waybill's webpki trust for the
	// registry pull (--registry-ca-cert). Required for a Harbor fronted by a
	// private CA; the paths are checked for existence at startup.
	RegistryCACerts []string `env:"SCANNER_WAYBILL_REGISTRY_CA_CERTS" envSeparator:","`
	// InsecureSkipVerify disables TLS chain/hostname/expiry verification for the
	// registry pull (--insecure-tls-skip-verify). Dev and CI only; prefer
	// RegistryCACerts in production.
	InsecureSkipVerify bool `env:"SCANNER_WAYBILL_INSECURE_TLS_SKIP_VERIFY" envDefault:"false"`
}

type API struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ClientCAs      []string      `env:"SCANNER_API_SERVER_CLIENT_CAS"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_SERVER_IDLE_TIMEOUT" envDefault:"60s"`
	MetricsEnabled bool          `env:"SCANNER_API_SERVER_METRICS_ENABLED" envDefault:"true"`
	APIKey         string        `env:"SCANNER_API_AUTH_API_KEY"`
}

func (c *API) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

type Store struct {
	// Backend selects the persistence backend: "redis" (production default) or
	// "memory" (dev/tests only).
	Backend string `env:"SCANNER_STORE_BACKEND" envDefault:"redis"`
}

type RedisStore struct {
	Namespace  string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.waybill:data-store"`
	ScanJobTTL time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

type JobQueue struct {
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.waybill:job-queue"`
	WorkerConcurrency int    `env:"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY" envDefault:"1"`
}

type RedisPool struct {
	URL               string        `env:"SCANNER_REDIS_URL" envDefault:"redis://localhost:6379"`
	MaxActive         int           `env:"SCANNER_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	MaxIdle           int           `env:"SCANNER_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	IdleTimeout       time.Duration `env:"SCANNER_REDIS_POOL_IDLE_TIMEOUT" envDefault:"5m"`
	ConnectionTimeout time.Duration `env:"SCANNER_REDIS_POOL_CONNECTION_TIMEOUT" envDefault:"1s"`
	ReadTimeout       time.Duration `env:"SCANNER_REDIS_POOL_READ_TIMEOUT" envDefault:"1s"`
	WriteTimeout      time.Duration `env:"SCANNER_REDIS_POOL_WRITE_TIMEOUT" envDefault:"1s"`
}

// LockTTL derives the distributed job-lock TTL from the scan timeout rather than
// copying a fixed constant: the lock must outlive the longest possible scan plus
// a backstop (plan m5).
func (c Config) LockTTL() time.Duration {
	return c.Waybill.Timeout + 30*time.Second
}

func LogLevel() slog.Level {
	if value, ok := os.LookupEnv("SCANNER_LOG_LEVEL"); ok {
		switch strings.ToLower(value) {
		case "error":
			return slog.LevelError
		case "warn", "warning":
			return slog.LevelWarn
		case "info":
			return slog.LevelInfo
		case "trace", "debug":
			return slog.LevelDebug
		}
		return slog.LevelInfo
	}
	return slog.LevelInfo
}

func GetConfig() (Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return cfg, err
	}
	cfg.Store.Backend = strings.ToLower(strings.TrimSpace(cfg.Store.Backend))
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// validate rejects settings that would otherwise fail silently and late rather
// than loudly at startup:
//
//   - an unknown store backend would take the Redis code path while skipping the
//     checker's Redis ping;
//   - an empty Redis namespace produces raw keys (":scan-job:...") and a
//     ":jobs:scan_artifact" channel that collide with anything else sharing the
//     database;
//   - a zero ScanJobTTL means "no expiry" to go-redis, so every scan job would
//     persist forever, and a negative one makes Redis reject every store write.
func (c Config) validate() error {
	switch c.Store.Backend {
	case StoreBackendRedis, StoreBackendMemory:
	default:
		return fmt.Errorf("SCANNER_STORE_BACKEND must be %q or %q, got %q",
			StoreBackendRedis, StoreBackendMemory, c.Store.Backend)
	}
	if c.Store.Backend == StoreBackendMemory {
		return nil
	}
	if strings.TrimSpace(c.RedisStore.Namespace) == "" {
		return fmt.Errorf("SCANNER_STORE_REDIS_NAMESPACE must not be empty")
	}
	if strings.TrimSpace(c.JobQueue.Namespace) == "" {
		return fmt.Errorf("SCANNER_JOB_QUEUE_REDIS_NAMESPACE must not be empty")
	}
	if c.RedisStore.ScanJobTTL <= 0 {
		return fmt.Errorf("SCANNER_STORE_REDIS_SCAN_JOB_TTL must be positive, got %s", c.RedisStore.ScanJobTTL)
	}
	if c.JobQueue.WorkerConcurrency < 1 {
		return fmt.Errorf("SCANNER_JOB_QUEUE_WORKER_CONCURRENCY must be at least 1, got %d", c.JobQueue.WorkerConcurrency)
	}
	return nil
}
