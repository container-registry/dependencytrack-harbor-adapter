package queue

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/scan"
)

// inProcessBacklog caps the channel between the HTTP handler and the workers.
// Past it Enqueue fails rather than blocking the handler past Harbor's 5s client
// timeout: a 500 that Harbor records against the scan beats a request that hangs
// and a job Harbor believes was accepted.
const inProcessBacklog = 64

// NewInProcessQueue builds the enqueuer/worker pair for SCANNER_STORE_BACKEND=memory,
// where there is no Redis to hold either the queue or the job records.
//
// It exists because the alternative is worse: the Redis enqueuer dereferences a
// client that is nil under the memory backend, so POST /api/v1/scan panicked
// mid-request. An adapter that starts, reports healthy, and cannot run a single
// scan is the failure mode this replaces.
//
// This is a single-process, non-durable mode for local development: nothing
// survives a restart, and two replicas share no state, so Harbor's report poll
// must reach the same process that ran the scan. Production wants Redis.
func NewInProcessQueue(
	config etc.JobQueue,
	lockTTL time.Duration,
	store persistence.Store,
	controller scan.Controller,
) (Enqueuer, Worker) {
	jobs := make(chan []byte, inProcessBacklog)

	enq := &enqueuer{
		namespace: config.Namespace,
		store:     store,
		dispatch: func(ctx context.Context, payload []byte) error {
			select {
			case jobs <- payload:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			default:
				return xerrors.Errorf("in-process job queue is full (%d pending); "+
					"use SCANNER_STORE_BACKEND=redis for anything beyond local development", inProcessBacklog)
			}
		},
	}

	return enq, &inProcessWorker{
		concurrency: config.WorkerConcurrency,
		lockTTL:     lockTTL,
		jobs:        jobs,
		controller:  controller,
	}
}

type inProcessWorker struct {
	concurrency int
	lockTTL     time.Duration
	jobs        chan []byte
	controller  scan.Controller

	stopOnce sync.Once
	cancel   context.CancelFunc
	done     sync.WaitGroup
}

func (w *inProcessWorker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	for i := 0; i < w.concurrency; i++ {
		w.done.Add(1)
		go func() {
			defer w.done.Done()
			w.consume(ctx)
		}()
	}
}

// Stop mirrors the Redis worker: cancel in-flight scans, then bound the drain so
// SIGTERM is not held for the full LockTTL by a scan in progress.
func (w *inProcessWorker) Stop() {
	slog.Debug("In-process job queue shutdown started")
	w.stopOnce.Do(func() {
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
		slog.Debug("In-process job queue shutdown completed")
	case <-time.After(stopTimeout):
		slog.Warn("In-process job queue shutdown timed out; abandoning in-flight scans",
			slog.Duration("timeout", stopTimeout))
	}
}

func (w *inProcessWorker) Depth(_ context.Context) (int64, error) {
	return int64(len(w.jobs)), nil
}

func (w *inProcessWorker) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-w.jobs:
			if err := w.runPayload(ctx, payload); err != nil {
				slog.Error("Failed to scan artifact", slog.String("err", err.Error()))
			}
		}
	}
}

// runPayload deliberately omits the SetNX lock the Redis worker carries: a
// channel delivers each payload to exactly one goroutine, and there is no second
// replica to race with.
func (w *inProcessWorker) runPayload(ctx context.Context, payload []byte) error {
	var j Job
	if err := json.Unmarshal(payload, &j); err != nil {
		return xerrors.Errorf("unmarshaling scan request: %w", err)
	}
	slog.Debug("Executing enqueued scan job", slog.String("scan_job_id", j.Key.ID))
	observeQueueWait(j)
	jobCtx, cancel := context.WithTimeout(ctx, w.lockTTL)
	defer cancel()
	return w.controller.Scan(jobCtx, j.Key, j.Args.ScanRequest)
}
