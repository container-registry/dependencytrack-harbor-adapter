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

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/metrics"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/scan"
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
	// Depth reports how many jobs are waiting to be picked up. It backs the
	// queue_depth gauge and runs on the Prometheus scrape goroutine, so
	// implementations must respect the caller's context deadline.
	Depth(ctx context.Context) (int64, error)
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
	// the syft subprocess rather than waiting out its timeout.
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

// Start runs `concurrency` consumers, each blocking on its own BLMOVE against
// the shared job list.
//
// This is deliberately a Redis list, not Pub/Sub. Pub/Sub drops a job whenever
// there is no subscriber at publish time (a restart window, or a worker that has
// not finished subscribing), and go-redis's PubSub.Channel() buffers only 100
// messages and discards anything it cannot deliver within a minute — while
// scanArtifact holds the reader loop for the whole scan. In both cases the store
// record stays Queued and Harbor 302-polls a job no worker will ever pick up,
// until the TTL expires. A list has neither failure mode: RPUSH persists, and
// BLMOVE hands each entry to exactly one consumer whenever one shows up.
//
// BLMOVE rather than BLPOP: BLPOP deletes the only queued copy at dequeue, so a
// worker crash (OOM kill, SIGKILL) between dequeue and completion lost the job
// with the store record stuck Queued until its TTL. BLMOVE parks the payload on
// a processing list instead; it is removed on completion and anything still
// there at the next Start is requeued.
func (w *worker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	w.requeueOrphans(ctx)
	for i := 0; i < w.concurrency; i++ {
		w.done.Add(1)
		go func() {
			defer w.done.Done()
			w.consume(ctx)
		}()
	}
}

// requeueOrphans moves payloads a previous run left on the processing list back
// onto the job list. With one adapter instance (the shipped deployment) anything
// found here is an orphan by definition. With several replicas this can requeue
// a job another replica is still scanning; the SetNX job lock keeps it from
// running twice concurrently and the terminal store writes are idempotent, so
// the cost is a duplicate scan, never a wrong result.
func (w *worker) requeueOrphans(ctx context.Context) {
	src, dst := redisProcessingList(w.namespace), redisJobList(w.namespace)
	moved := 0
	for {
		// RIGHT->LEFT preserves FIFO order: the tail of the processing list lands
		// at the head of the job list first, so after the loop the oldest orphan
		// is at the head.
		_, err := w.rdb.LMove(ctx, src, dst, "RIGHT", "LEFT").Result()
		if err != nil {
			if !errors.Is(err, redis.Nil) {
				slog.Error("Failed to requeue in-flight scan jobs from a previous run",
					slog.String("err", err.Error()))
			}
			break
		}
		moved++
	}
	if moved > 0 {
		slog.Info("Requeued scan jobs a previous run left in-flight", slog.Int("count", moved))
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
	procKey := redisProcessingList(w.namespace)
	for {
		select {
		case <-w.stop:
			return
		case <-ctx.Done():
			return
		default:
		}

		payload, err := w.rdb.BLMove(ctx, key, procKey, "LEFT", "RIGHT", popTimeout).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue // BLMOVE timed out with an empty list: normal idle.
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
		if err := w.scanArtifact(ctx, payload); err != nil {
			slog.Error("Failed to scan artifact", slog.String("err", err.Error()))
		}
		w.ack(ctx, procKey, payload)
	}
}

// ackTimeout bounds the processing-list removal after a job completes. It runs
// detached from ctx: at shutdown the consume context is already canceled, and a
// job that DID complete (Scan writes its terminal status on a detached context
// too) must still be acknowledged, or the next Start would requeue and re-run it.
const ackTimeout = 5 * time.Second

func (w *worker) ack(ctx context.Context, procKey, payload string) {
	ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer cancel()
	// Payloads are unique in practice (job key + EnqueuedAt), so LREM 1 removes
	// exactly this job's parked copy. If the removal fails the payload is
	// requeued at the next Start; the SetNX lock and idempotent store writes make
	// that a duplicate scan at worst, which is the right direction to fail in.
	if err := w.rdb.LRem(ackCtx, procKey, 1, payload).Err(); err != nil {
		slog.Warn("Failed to acknowledge completed scan job; it may be requeued on restart",
			slog.String("err", err.Error()))
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

// runJob bounds the whole job (syft's registry pull plus its scan) by a
// deadline. Start receives context.Background() from main, so without this the
// job would be unbounded: a tarpit or half-open registry can trickle bytes for
// as long as it likes, permanently consuming this worker goroutine (default
// concurrency 1 => all scanning halts until process restart, job stuck Pending
// until the 1h TTL). The deadline is the lock TTL: the job may run for as long as
// the lock protects it, and no longer. The context reaches the syft subprocess
// through exec.CommandContext, which kills it when the deadline fires.
func (w *worker) runJob(ctx context.Context, j Job) error {
	observeQueueWait(j)
	jobCtx, cancel := context.WithTimeout(ctx, w.lockTTL)
	defer cancel()
	return w.controller.Scan(jobCtx, j.Key, j.Args.ScanRequest)
}

func (w *worker) Depth(ctx context.Context) (int64, error) {
	return w.rdb.LLen(ctx, redisJobList(w.namespace)).Result()
}

// observeQueueWait skips the zero value so jobs enqueued before this field
// existed (still on a list across an upgrade) do not report a wait measured
// from the epoch.
func observeQueueWait(j Job) {
	if j.EnqueuedAt.IsZero() {
		return
	}
	metrics.QueueWaitSeconds.Observe(time.Since(j.EnqueuedAt).Seconds())
}

func redisLockKey(namespace, jobID string) string {
	return redisJobList(namespace) + ":lock:" + jobID
}

// redisProcessingList holds payloads between dequeue and completion, so a
// worker crash mid-scan leaves the job recoverable (see Start).
func redisProcessingList(namespace string) string {
	return redisJobList(namespace) + ":processing"
}
