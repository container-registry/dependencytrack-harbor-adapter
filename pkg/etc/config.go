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
	Syft       Syft
	DTrack     DTrack
	Store      Store
	RedisStore RedisStore
	JobQueue   JobQueue
	RedisPool  RedisPool
}

// Syft configures the SBOM generator subprocess. It is used on the fallback
// path, when the artifact has no Harbor-generated SBOM to reuse.
type Syft struct {
	Binary  string        `env:"SCANNER_SYFT_BINARY" envDefault:"/usr/local/bin/syft"`
	WorkDir string        `env:"SCANNER_SYFT_WORK_DIR" envDefault:"/home/scanner/work"`
	Timeout time.Duration `env:"SCANNER_SYFT_TIMEOUT" envDefault:"5m0s"`

	// Platform overrides the platform resolved from a multi-arch index. Harbor
	// addresses a child manifest by digest, so this is normally unnecessary.
	Platform  string   `env:"SCANNER_SYFT_IMAGE_PLATFORM"`
	ExtraArgs []string `env:"SCANNER_SYFT_EXTRA_ARGS" envSeparator:" "`

	// RegistryCACert is a PEM bundle (or a directory of them) trusted for the
	// registry pull. Required for a Harbor fronted by a private CA. The path is
	// checked for existence at startup.
	RegistryCACert string `env:"SCANNER_SYFT_REGISTRY_CA_CERT"`
	// InsecureSkipVerify disables TLS verification for the registry pull. Dev and
	// CI only; prefer RegistryCACert in production.
	InsecureSkipVerify bool `env:"SCANNER_SYFT_INSECURE_TLS_SKIP_VERIFY" envDefault:"false"`

	// MaxImageSize rejects an artifact whose compressed layers exceed it, before
	// the pull starts. 0 disables the check.
	//
	// This is a memory guard. An OOM kills the container rather than the job, so
	// without a cap one oversized artifact takes every in-flight scan down with
	// it. The cap and the container memory limit have to be set together.
	//
	// Note this guard only applies to the generation path. The accessory fast
	// path reads a few tens of KB and never pulls the image, which is exactly
	// why it is tried first.
	MaxImageSize int64 `env:"SCANNER_SYFT_MAX_IMAGE_SIZE" envDefault:"1073741824"`
}

// DTrack configures the Dependency-Track upload.
type DTrack struct {
	// URL is the Dependency-Track API server root. Empty disables the upload
	// entirely, which turns the adapter into a plain SBOM generator; that is a
	// legitimate way to run it while credentials are being provisioned, so it is
	// a warning at startup rather than an error.
	URL string `env:"SCANNER_DTRACK_URL"`
	// APIKey is a team API key with BOM_UPLOAD, plus PROJECT_CREATION_UPLOAD or
	// PORTFOLIO_MANAGEMENT_CREATE so autoCreate can create projects.
	APIKey string `env:"SCANNER_DTRACK_API_KEY"`
	// Timeout bounds a single upload.
	Timeout time.Duration `env:"SCANNER_DTRACK_TIMEOUT" envDefault:"60s"`
	// InsecureSkipVerify disables TLS verification when talking to
	// Dependency-Track. Dev and CI only.
	InsecureSkipVerify bool `env:"SCANNER_DTRACK_INSECURE_TLS_SKIP_VERIFY" envDefault:"false"`

	// ProjectTags are attached to every project this adapter creates, so a
	// Dependency-Track operator can tell them from ones a build pipeline pushed.
	ProjectTags []string `env:"SCANNER_DTRACK_PROJECT_TAGS" envSeparator:"," envDefault:"harbor"`
	// NestUnderHarborProject files each repository under a parent project named
	// after its Harbor project, so the Dependency-Track portfolio mirrors
	// Harbor's project structure.
	NestUnderHarborProject bool `env:"SCANNER_DTRACK_NEST_UNDER_HARBOR_PROJECT" envDefault:"true"`

	// FailScanOnUploadError decides what a failed upload does to the Harbor scan.
	//
	// Default false: the SBOM is Harbor's deliverable and it is already
	// generated, so discarding it because a third system was unreachable makes
	// the adapter less useful than it can be. The failure is logged and counted.
	// Set true when the Dependency-Track feed is the point of the deployment and
	// a silent gap in the portfolio is worse than a visible failed scan.
	FailScanOnUploadError bool `env:"SCANNER_DTRACK_FAIL_SCAN_ON_UPLOAD_ERROR" envDefault:"false"`
}

// Accessory holds the fast-path settings.
type Accessory struct{}

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
	Namespace  string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.dependencytrack:data-store"`
	ScanJobTTL time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

type JobQueue struct {
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.dependencytrack:job-queue"`
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
	return c.Syft.Timeout + 30*time.Second
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
	// A non-positive scan timeout leaves the syft subprocess unbounded and
	// collapses LockTTL to 30s, which is shorter than any real scan.
	if c.Syft.Timeout <= 0 {
		return fmt.Errorf("SCANNER_SYFT_TIMEOUT must be positive, got %s", c.Syft.Timeout)
	}
	// Partial TLS is a typo in one of two secrets, and IsTLSEnabled requires
	// both, so the old behavior was to silently serve plaintext -- the failure
	// mode a deployment can least afford to have go unnoticed.
	if (c.API.TLSCertificate == "") != (c.API.TLSKey == "") {
		return fmt.Errorf("SCANNER_API_SERVER_TLS_CERTIFICATE and SCANNER_API_SERVER_TLS_KEY must be set together " +
			"(only one is set; the server would silently start without TLS)")
	}
	if len(c.API.ClientCAs) > 0 && !c.API.IsTLSEnabled() {
		return fmt.Errorf("SCANNER_API_SERVER_CLIENT_CAS requires TLS " +
			"(SCANNER_API_SERVER_TLS_CERTIFICATE and SCANNER_API_SERVER_TLS_KEY); client certificates are never verified without it)")
	}
	// A non-positive server timeout means "no timeout" to net/http, so a typo
	// silently removes the slow-client protection instead of tightening it.
	for name, d := range map[string]time.Duration{
		"SCANNER_API_SERVER_READ_TIMEOUT":  c.API.ReadTimeout,
		"SCANNER_API_SERVER_WRITE_TIMEOUT": c.API.WriteTimeout,
		"SCANNER_API_SERVER_IDLE_TIMEOUT":  c.API.IdleTimeout,
	} {
		if d <= 0 {
			return fmt.Errorf("%s must be positive, got %s", name, d)
		}
	}
	if c.Syft.MaxImageSize < 0 {
		return fmt.Errorf("SCANNER_SYFT_MAX_IMAGE_SIZE must not be negative, got %d", c.Syft.MaxImageSize)
	}
	if c.DTrack.Timeout <= 0 {
		return fmt.Errorf("SCANNER_DTRACK_TIMEOUT must be positive, got %s", c.DTrack.Timeout)
	}
	// A URL without a key uploads nothing and 401s on every scan; a key without
	// a URL is a secret mounted for a feature that is off. Both are typos in a
	// deployment that believes it is feeding Dependency-Track.
	if (c.DTrack.URL == "") != (c.DTrack.APIKey == "") {
		return fmt.Errorf("SCANNER_DTRACK_URL and SCANNER_DTRACK_API_KEY must be set together " +
			"(only one is set; BOM uploads would be silently disabled or rejected)")
	}
	switch c.Store.Backend {
	case StoreBackendRedis, StoreBackendMemory:
	default:
		return fmt.Errorf("SCANNER_STORE_BACKEND must be %q or %q, got %q",
			StoreBackendRedis, StoreBackendMemory, c.Store.Backend)
	}
	// Checked before the memory-backend return: the in-process queue starts
	// exactly WorkerConcurrency consumers, so a value of 0 there produced an
	// adapter that accepted scans and had nobody to run them.
	if c.JobQueue.WorkerConcurrency < 1 {
		return fmt.Errorf("SCANNER_JOB_QUEUE_WORKER_CONCURRENCY must be at least 1, got %d", c.JobQueue.WorkerConcurrency)
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
	return nil
}
