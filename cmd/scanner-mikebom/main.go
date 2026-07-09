// Command scanner-mikebom is the Harbor Pluggable Scanner Adapter that wraps the
// mikebom SBOM CLI. It serves the Scanner Adapter API v1: the adapter pulls the
// artifact itself (go-containerregistry), hands mikebom a docker-save tarball,
// and returns the SPDX 2.3 document in a Harbor report envelope.
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

	"github.com/container-registry/mikebom-harbor-adapter/pkg/etc"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/harbor"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/http/api"
	v1 "github.com/container-registry/mikebom-harbor-adapter/pkg/http/api/v1"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/mikebom"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence/memory"
	predis "github.com/container-registry/mikebom-harbor-adapter/pkg/persistence/redis"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/queue"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/redisx"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/registry"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/scan"
)

// Stamped at build time by the Taskfile ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	scannerName   = "mikebom"
	scannerVendor = "Kusari"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("scanner-mikebom %s (commit %s, built %s)\n", version, commit, date)
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
	slog.Info("Starting scanner-mikebom",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("built_at", info.Date),
		slog.Int("uid", os.Getuid()),
	)

	config, err := etc.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	wrapper := mikebom.NewWrapper(config.Mikebom)

	// scanner.version is the mikebom CLI version, exec'd once at startup, never
	// from env (plan D-4).
	versionCtx, cancelVersion := context.WithTimeout(ctx, 15*time.Second)
	mikebomVersion, err := wrapper.Version(versionCtx)
	cancelVersion()
	if err != nil {
		return fmt.Errorf("determining mikebom version: %w", err)
	}
	scanner := harbor.Scanner{Name: scannerName, Vendor: scannerVendor, Version: mikebomVersion}
	slog.Info("mikebom scanner", slog.String("version", mikebomVersion))

	var (
		store  persistence.Store
		rdb    *redis.Client
		pinger etc.Pinger
	)
	useRedis := config.Store.Backend != "memory"
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
	if err = etc.SweepStaleWorkDirs(config.Mikebom.WorkDir); err != nil {
		slog.Warn("Failed to sweep stale work dirs", slog.String("err", err.Error()))
	}

	puller := registry.NewPuller()
	controller := scan.NewController(store, puller, wrapper, scanner, config.Mikebom.WorkDir)
	enqueuer := queue.NewEnqueuer(config.JobQueue, rdb, store)

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

	var worker queue.Worker
	if useRedis {
		worker = queue.NewWorker(config.JobQueue, config.LockTTL(), rdb, controller)
		worker.Start(ctx)
	}

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
