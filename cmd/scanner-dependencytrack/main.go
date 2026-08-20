// Command scanner-dependencytrack is the Harbor Pluggable Scanner Adapter that
// feeds Dependency-Track. It serves the Scanner Adapter API v1: for each
// artifact it reuses the SBOM Harbor already generated when there is one, or
// generates one with syft, returns the SPDX 2.3 document to Harbor, and uploads
// the same inventory to Dependency-Track as CycloneDX.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/accessory"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/dtrack"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api"
	v1 "github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api/v1"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/imageprobe"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/metrics"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/memory"
	predis "github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/redis"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/queue"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/redisx"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/scan"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/syft"
)

// Stamped at build time by the Taskfile ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	scannerName   = "Dependency-Track"
	scannerVendor = "container-registry.com"
)

// accessoryTimeout bounds the SBOM accessory lookup. It is deliberately a small
// fraction of the scan timeout: the lookup is an optimization, and time spent
// waiting on a stalled registry here is taken directly out of the budget the
// fallback generation still needs.
const accessoryTimeout = 30 * time.Second

// queueDepthTimeout bounds the LLEN behind the queue_depth gauge. It runs on the
// Prometheus scrape goroutine, so it must not outlive a scrape; the Redis pool's
// own read timeout defaults to 1s.
const queueDepthTimeout = 2 * time.Second

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("scanner-dependencytrack %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: etc.LogLevel()}))
	slog.SetDefault(logger)

	info := etc.BuildInfo{Version: version, Commit: commit, Date: date}
	if err := run(context.Background(), info); err != nil {
		slog.Error("fatal", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// redisPinger adapts *redis.Client to etc.Pinger.
type redisPinger struct{ rdb *redis.Client }

func (p redisPinger) Ping(ctx context.Context) error { return p.rdb.Ping(ctx).Err() }

func run(ctx context.Context, info etc.BuildInfo) error {
	slog.Info("Starting scanner-dependencytrack",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("built_at", info.Date),
		slog.Int("uid", os.Getuid()),
	)

	config, err := etc.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	wrapper := syft.NewWrapper(config.Syft)

	// scanner.version is the syft CLI version, exec'd once at startup rather than
	// read from an env var, so what Harbor displays is what will actually run.
	versionCtx, cancelVersion := context.WithTimeout(ctx, 15*time.Second)
	syftVersion, err := wrapper.Version(versionCtx)
	cancelVersion()
	if err != nil {
		return fmt.Errorf("determining syft version: %w", err)
	}
	scanner := harbor.Scanner{Name: scannerName, Vendor: scannerVendor, Version: syftVersion}
	slog.Info("syft", slog.String("version", syftVersion))

	var uploader dtrack.Client
	if config.DTrack.URL != "" {
		uploader = dtrack.NewClient(dtrack.Config{
			BaseURL:       config.DTrack.URL,
			APIKey:        config.DTrack.APIKey,
			Timeout:       config.DTrack.Timeout,
			SkipTLSVerify: config.DTrack.InsecureSkipVerify,
		})
	}

	var (
		store  persistence.Store
		rdb    *redis.Client
		pinger etc.Pinger
	)
	// etc.GetConfig has already normalized and validated Store.Backend, so this
	// comparison and the checker's Redis ping agree on the same value. Before
	// normalization a typo or a case variant ("Memory") silently took the Redis
	// path while skipping the fail-fast connectivity check.
	useRedis := config.Store.Backend == etc.StoreBackendRedis
	if useRedis {
		rdb, err = redisx.NewClient(config.RedisPool)
		if err != nil {
			return fmt.Errorf("constructing redis client: %w", err)
		}
		store = predis.NewStore(config.RedisStore, rdb)
		pinger = redisPinger{rdb: rdb}
	} else {
		store = memory.NewStore()
	}

	// nil versioner: the exec-ability check the checker would do is exactly the
	// call just made above, and running syft version twice at startup buys
	// nothing.
	var dtrackPinger etc.Pinger
	if uploader != nil {
		dtrackPinger = uploader
	}
	if err = etc.Check(ctx, config, nil, pinger, dtrackPinger); err != nil {
		return fmt.Errorf("checking config: %w", err)
	}
	if err = etc.SweepStaleWorkDirs(config.Syft.WorkDir); err != nil {
		slog.Warn("Failed to sweep stale work dirs", slog.String("err", err.Error()))
	}

	prober, err := imageprobe.New(config.Syft)
	if err != nil {
		return fmt.Errorf("constructing image prober: %w", err)
	}
	if config.Syft.MaxImageSize <= 0 {
		slog.Warn("Pre-pull artifact size cap is disabled: an oversized image can OOM this container " +
			"and take every in-flight scan with it. Set SCANNER_SYFT_MAX_IMAGE_SIZE.")
	}
	controller := scan.NewController(store, wrapper, scanner, config.Syft.WorkDir, scan.Options{
		Fetcher:                accessory.NewFetcher(accessoryTimeout),
		Uploader:               uploader,
		Prober:                 prober,
		MaxImageSize:           config.Syft.MaxImageSize,
		FailOnUploadError:      config.DTrack.FailScanOnUploadError,
		ProjectTags:            config.DTrack.ProjectTags,
		NestUnderHarborProject: config.DTrack.NestUnderHarborProject,
		SkipTLSVerify:          config.Syft.InsecureSkipVerify,
	})

	// The enqueuer and the worker are always built as a pair. Previously the
	// worker was conditional while the enqueuer was not, so the memory backend
	// produced an adapter that started, reported healthy, and had no consumer at
	// all -- and whose enqueuer dereferenced a nil Redis client on the first scan.
	var (
		enqueuer queue.Enqueuer
		worker   queue.Worker
	)
	if useRedis {
		enqueuer = queue.NewEnqueuer(config.JobQueue, rdb, store)
		worker = queue.NewWorker(config.JobQueue, config.LockTTL(), rdb, controller)
	} else {
		slog.Warn("Store backend is memory: scan jobs and reports are held in this process only. " +
			"Nothing survives a restart and a second replica shares no state. Use SCANNER_STORE_BACKEND=redis in production.")
		enqueuer, worker = queue.NewInProcessQueue(config.JobQueue, config.LockTTL(), store, controller)
	}

	metrics.MustRegisterQueueDepth(func() float64 {
		dctx, dcancel := context.WithTimeout(ctx, queueDepthTimeout)
		defer dcancel()
		n, derr := worker.Depth(dctx)
		if derr != nil {
			// NaN, not 0: an unreadable Redis must not render as an empty queue.
			return math.NaN()
		}
		return float64(n)
	})

	ready := func(rctx context.Context) error {
		if pinger != nil {
			return pinger.Ping(rctx)
		}
		return nil
	}

	apiHandler := v1.NewAPIHandler(info, config, scanner, enqueuer, store, ready)
	apiServer, err := api.NewServer(config.API, apiHandler)
	if err != nil {
		return fmt.Errorf("new api server: %w", err)
	}

	worker.Start(ctx)

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		slog.Info("Trapped os signal", slog.String("signal", captured.String()))

		apiServer.Shutdown()
		if worker != nil {
			worker.Stop()
		}
		if rdb != nil {
			_ = rdb.Close()
		}
		close(shutdownComplete)
	}()

	// A non-nil serve error is fatal (bind failure, bad TLS material) and must
	// propagate out of run; a nil one means Shutdown closed the listener, so the
	// only thing left is to wait for the signal handler to finish cleanup.
	if err := <-apiServer.ListenAndServe(); err != nil {
		return fmt.Errorf("api server: %w", err)
	}
	<-shutdownComplete
	return nil
}
