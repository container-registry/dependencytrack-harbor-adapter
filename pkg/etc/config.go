// Package etc holds the adapter configuration (all env, SCANNER_ prefix) and a
// startup checker that fails fast on an unusable environment.
package etc

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API        API
	Mikebom    Mikebom
	Store      Store
	RedisStore RedisStore
	JobQueue   JobQueue
	RedisPool  RedisPool
}

type Mikebom struct {
	Binary       string        `env:"SCANNER_MIKEBOM_BINARY" envDefault:"/usr/local/bin/mikebom"`
	WorkDir      string        `env:"SCANNER_MIKEBOM_WORK_DIR" envDefault:"/home/scanner/work"`
	Timeout      time.Duration `env:"SCANNER_MIKEBOM_TIMEOUT" envDefault:"5m0s"`
	OCICacheSize int           `env:"SCANNER_MIKEBOM_OCI_CACHE_SIZE" envDefault:"0"`
	// Enrichment, when true, drops the --offline flag so mikebom's deps.dev /
	// ClearlyDefined enrichment can run. Default false = offline (egress
	// control). See docs/spike-m1.md: MIKEBOM_OFFLINE=1 alone does NOT disable
	// enrichment; only the --offline CLI flag does.
	Enrichment    bool     `env:"SCANNER_MIKEBOM_ENRICHMENT" envDefault:"false"`
	ImagePlatform string   `env:"SCANNER_MIKEBOM_IMAGE_PLATFORM"`
	ExtraArgs     []string `env:"SCANNER_MIKEBOM_EXTRA_ARGS" envSeparator:" "`
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
	Namespace  string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.mikebom:data-store"`
	ScanJobTTL time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

type JobQueue struct {
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.mikebom:job-queue"`
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
	return c.Mikebom.Timeout + 30*time.Second
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
	return cfg, nil
}
