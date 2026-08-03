package queue

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/scan"
)

// popTimeout is how long a worker blocks on BLPOP before looping. It only sets
// how quickly an idle worker notices Stop() / ctx cancellation; the queue itself
// is push-driven, so a longer value costs nothing but responsiveness at shutdown.
const popTimeout = 5 * time.Second

// stopTimeout bounds Stop(). A worker in the middle of a scan does not return to
// the consume loop until runJob finishes, which can take the full LockTTL
// (5m30s by default). The signal handler calls Stop() directly, so waiting for
// that unconditionally would stall SIGTERM until the orchestrator escalates to
// SIGKILL. Past this deadline Stop() returns and lets the process exit; the
// abandoned job stays Pending until its TTL, which is the same outcome as the
// SIGKILL it would otherwise wait for.
const stopTimeout = 10 * time.Second

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

	rdb *redis.Client

	stopOnce sync.Once
	stop     chan struct{}
	done     sync.WaitGroup
	// cancel aborts the context handed to in-flight scans, so Stop() tears down
	// the waybill subprocess rather than waiting out its timeout.
	cancel context.CancelFunc

	controller scan.Controller
}

func NewWorker(config etc.JobQueue, lockTTL time.Duration, rdb *redis.Client, controller scan.Controller) Worker {
	return &worker{
		namespace:   config.Namespace,
		concurrency: config.WorkerConcurrency,
		lockTTL:     lockTTL,
		rdb:         rdb,
		stop:        make(chan struct{}),
		controller:  controller,
	}
}

// Start runs `concurrency` consumers, each blocking on its own BLPOP against the
// shared job list.
//
// This is deliberately a Redis list, not Pub/Sub. Pub/Sub drops a job whenever
// there is no subscriber at publish time (a restart window, or a worker that has
// not finished subscribing), and go-redis's PubSub.Channel() buffers only 100
// messages and discards anything it cannot deliver within a minute — while
// scanArtifact holds the reader loop for the whole scan. In both cases the store
// record stays Queued and Harbor 302-polls a job no worker will ever pick up,
// until the TTL expires. A list has neither failure mode: RPUSH persists, and
// BLPOP hands each entry to exactly one consumer whenever one shows up.
func (w *worker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	for i := 0; i < w.concurrency; i++ {
		w.done.Add(1)
		go func() {
			defer w.done.Done()
			w.consume(ctx)
		}()
	}
}

func (w *worker) Stop() {
	slog.Debug("Job queue shutdown started")
	w.stopOnce.Do(func() {
		close(w.stop)
		if w.cancel != nil {
			w.cancel()
		}
	})

	drained := make(chan struct{})
	go func() {
		w.done.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		slog.Debug("Job queue shutdown completed")
	case <-time.After(stopTimeout):
		slog.Warn("Job queue shutdown timed out; abandoning in-flight scans",
			slog.Duration("timeout", stopTimeout))
	}
}

func (w *worker) consume(ctx context.Context) {
	key := redisJobList(w.namespace)
	for {
		select {
		case <-w.stop:
			return
		case <-ctx.Done():
			return
		default:
		}

		res, err := w.rdb.BLPop(ctx, popTimeout, key).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue // BLPOP timed out with an empty list: normal idle.
			}
			if ctx.Err() != nil {
				return
			}
			// Redis unreachable or the command failed. Back off for one poll
			// interval rather than spinning on the error.
			slog.Error("Failed to dequeue scan job", slog.String("err", err.Error()))
			select {
			case <-w.stop:
				return
			case <-ctx.Done():
				return
			case <-time.After(popTimeout):
			}
			continue
		}
		// BLPOP returns [key, value].
		if len(res) != 2 {
			slog.Error("Unexpected BLPOP response", slog.Int("len", len(res)))
			continue
		}
		if err := w.scanArtifact(ctx, res[1]); err != nil {
			slog.Error("Failed to scan artifact", slog.String("err", err.Error()))
		}
	}
}

func (w *worker) scanArtifact(ctx context.Context, payload string) error {
	var j Job
	if err := json.Unmarshal([]byte(payload), &j); err != nil {
		return xerrors.Errorf("unmarshaling scan request: %w", err)
	}

	// The lock is no longer what keeps two workers off one job — BLPOP already
	// delivers each entry once. It stays as the guard against a duplicate
	// enqueue of the same job key landing on two workers concurrently.
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

// runJob bounds the whole job (waybill's registry pull plus its scan) by a
// deadline. Start receives context.Background() from main, so without this the
// job would be unbounded: a tarpit or half-open registry can trickle bytes for
// as long as it likes, permanently consuming this worker goroutine (default
// concurrency 1 => all scanning halts until process restart, job stuck Pending
// until the 1h TTL). The deadline is the lock TTL: the job may run for as long as
// the lock protects it, and no longer. The context reaches the waybill subprocess
// through exec.CommandContext, which kills it when the deadline fires.
func (w *worker) runJob(ctx context.Context, j Job) error {
	jobCtx, cancel := context.WithTimeout(ctx, w.lockTTL)
	defer cancel()
	return w.controller.Scan(jobCtx, j.Key, j.Args.ScanRequest)
}

func redisLockKey(namespace, jobID string) string {
	return redisJobList(namespace) + ":lock:" + jobID
}
