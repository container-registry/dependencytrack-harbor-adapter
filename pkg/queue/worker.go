package queue

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/etc"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/scan"
)

type Worker interface {
	Start(ctx context.Context)
	Stop()
}

type worker struct {
	namespace   string
	concurrency int
	// lockTTL guards a job so a second worker won't process it. Derived from the
	// scan timeout (config.LockTTL), not a copied 5m constant (plan m5).
	lockTTL time.Duration

	rdb    *redis.Client
	pubsub *redis.PubSub

	controller scan.Controller
}

func NewWorker(config etc.JobQueue, lockTTL time.Duration, rdb *redis.Client, controller scan.Controller) Worker {
	return &worker{
		namespace:   config.Namespace,
		concurrency: config.WorkerConcurrency,
		lockTTL:     lockTTL,
		rdb:         rdb,
		controller:  controller,
	}
}

func (w *worker) Start(ctx context.Context) {
	w.pubsub = w.rdb.Subscribe(ctx, redisJobChannel(w.namespace))
	ch := w.pubsub.Channel()

	for i := 0; i < w.concurrency; i++ {
		go w.subscribe(ctx, ch)
	}
}

func (w *worker) Stop() {
	slog.Debug("Job queue shutdown started")
	if w.pubsub != nil {
		_ = w.pubsub.Close()
	}
	slog.Debug("Job queue shutdown completed")
}

func (w *worker) subscribe(ctx context.Context, ch <-chan *redis.Message) {
	for msg := range ch {
		chLog := slog.With(slog.String("channel", msg.Channel))
		chLog.Debug("Message subscribed")
		if err := w.scanArtifact(ctx, msg); err != nil {
			chLog.Error("Failed to scan artifact", slog.String("err", err.Error()))
			continue
		}
	}
}

func (w *worker) scanArtifact(ctx context.Context, msg *redis.Message) error {
	var j Job
	if err := json.Unmarshal([]byte(msg.Payload), &j); err != nil {
		return xerrors.Errorf("unmarshaling scan request: %w", err)
	}

	nx, err := w.rdb.SetNX(ctx, redisLockKey(w.namespace, j.ID()), "", w.lockTTL).Result()
	if err != nil {
		return xerrors.Errorf("redis lock: %w", err)
	} else if !nx {
		slog.Debug("Skip the locked job", slog.String("scan_job_id", j.Key.ID))
		return nil
	}

	slog.Debug("Executing enqueued scan job", slog.String("scan_job_id", j.Key.ID))
	return w.runJob(ctx, j)
}

// runJob bounds the whole job (registry pull + mikebom scan) by a deadline. Start
// receives context.Background() from main, and controller.Scan -> puller.PullToTarball
// had no timeout on the pull path: go-containerregistry's default transport sets only
// dial/TLS timeouts, so a tarpit or half-open registry could trickle bytes and block
// the pull forever, permanently consuming this worker goroutine (default concurrency
// 1 => all scanning halts until process restart, job stuck Pending until the 1h TTL).
// The deadline is the lock TTL: the job may run for as long as the lock protects it,
// and no longer. crane honors the ctx via crane.WithContext, so the pull is now bounded.
func (w *worker) runJob(ctx context.Context, j Job) error {
	jobCtx, cancel := context.WithTimeout(ctx, w.lockTTL)
	defer cancel()
	return w.controller.Scan(jobCtx, j.Key, j.Args.ScanRequest)
}

func redisLockKey(namespace, jobID string) string {
	return redisJobChannel(namespace) + ":lock:" + jobID
}
