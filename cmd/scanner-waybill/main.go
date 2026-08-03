// Command scanner-waybill is the Harbor Pluggable Scanner Adapter that wraps the
// waybill SBOM CLI. It serves the Scanner Adapter API v1: waybill pulls the
// artifact from the Harbor-managed registry and the adapter returns the SPDX 2.3
// document it produces in a Harbor report envelope.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	v1 "github.com/container-registry/waybill-harbor-adapter/pkg/http/api/v1"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence/memory"
	predis "github.com/container-registry/waybill-harbor-adapter/pkg/persistence/redis"
	"github.com/container-registry/waybill-harbor-adapter/pkg/queue"
	"github.com/container-registry/waybill-harbor-adapter/pkg/redisx"
	"github.com/container-registry/waybill-harbor-adapter/pkg/scan"
	"github.com/container-registry/waybill-harbor-adapter/pkg/waybill"
)

// Stamped at build time by the Taskfile ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	scannerName   = "waybill"
	scannerVendor = "Kusari"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("scanner-waybill %s (commit %s, built %s)\n", version, commit, date)
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
	slog.Info("Starting scanner-waybill",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("built_at", info.Date),
		slog.Int("uid", os.Getuid()),
	)

	config, err := etc.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	wrapper := waybill.NewWrapper(config.Waybill)

	// scanner.version is the waybill CLI version, exec'd once at startup, never
	// from env (plan D-4).
	versionCtx, cancelVersion := context.WithTimeout(ctx, 15*time.Second)
	waybillVersion, err := wrapper.Version(versionCtx)
	cancelVersion()
	if err != nil {
		return fmt.Errorf("determining waybill version: %w", err)
	}
	scanner := harbor.Scanner{Name: scannerName, Vendor: scannerVendor, Version: waybillVersion}
	slog.Info("waybill scanner", slog.String("version", waybillVersion))

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

	if err = etc.Check(ctx, config, wrapper, pinger); err != nil {
		return fmt.Errorf("checking config: %w", err)
	}
	if err = etc.SweepStaleWorkDirs(config.Waybill.WorkDir); err != nil {
		slog.Warn("Failed to sweep stale work dirs", slog.String("err", err.Error()))
	}

	controller := scan.NewController(store, wrapper, scanner, config.Waybill.WorkDir)

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

	apiServer.ListenAndServe()
	<-shutdownComplete
	return nil
}
