// Package queue is the Redis job queue (enqueuer + worker) with a SetNX
// distributed lock, ported from harbor-scanner-trivy. The lock TTL is derived
// from the scan timeout rather than a copied constant (plan m5).
//
// Transport is a Redis list (RPUSH / BLMOVE + processing list), not Pub/Sub:
// see worker.Start for the two ways Pub/Sub silently loses an accepted job and
// for the crash-recovery path.
package queue

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/metrics"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
)

const scanArtifactJobName = "scan_artifact"

// undispatchedWriteTimeout bounds the cleanup write for a job that could not be
// queued. It runs detached from the request context, so it needs its own bound.
const undispatchedWriteTimeout = 5 * time.Second

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type enqueuer struct {
	namespace string
	store     persistence.Store
	// dispatch hands the marshaled job to the transport. Redis-backed deployments
	// RPUSH it onto the shared list; the in-process backend passes it down a
	// channel. Everything above this line -- validation, job-key fan-out, the
	// Queued store record -- is identical either way.
	dispatch func(ctx context.Context, payload []byte) error
}

type Job struct {
	Name string
	Key  job.ScanJobKey
	Args Args
	// EnqueuedAt travels with the payload so the worker can report how long the
	// job waited. Queue wait is what distinguishes "scans are slow" from "the
	// worker pool is too small for the rate Harbor dispatches at".
	EnqueuedAt time.Time `json:",omitempty"`
}

func (s *Job) ID() string {
	return s.Key.String()
}

type Args struct {
	ScanRequest *harbor.ScanRequest `json:",omitempty"`
}

func NewEnqueuer(config etc.JobQueue, rdb *redis.Client, store persistence.Store) Enqueuer {
	list := redisJobList(config.Namespace)
	return &enqueuer{
		namespace: config.Namespace,
		store:     store,
		dispatch: func(ctx context.Context, payload []byte) error {
			// RPUSH appends at the tail and the workers BLMOVE from the head:
			// opposite ends, so the queue is FIFO. (Same-end push/pop would be
			// a LIFO stack, and a steady arrival rate would starve the oldest
			// scans indefinitely.) Unlike Publish this does not need a live
			// subscriber: the entry sits in the list until a worker takes it, so
			// a job accepted while no worker is listening still runs.
			return rdb.RPush(ctx, list, payload).Err()
		},
	}
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	if len(request.Capabilities) == 0 {
		return "", xerrors.Errorf("no capabilities provided")
	}

	jobID, err := makeIdentifier()
	if err != nil {
		return "", err
	}

	created := 0

	for _, c := range request.Capabilities {
		for _, mediaType := range lo.FromPtr(c.Parameters).SBOMMediaTypes {
			for _, produces := range c.ProducesMIMETypes {
				var m api.MIMEType
				if err := m.Parse(produces); err != nil {
					// Non-SBOM produces MIME: not something this adapter can
					// serve. Validation already gates this; skip defensively.
					slog.Warn("Skipping unsupported produces mime type",
						slog.String("mime_type", produces), slog.String("err", err.Error()))
					continue
				}
				jobKey := job.ScanJobKey{
					ID:        jobID,
					MIMEType:  m,
					MediaType: mediaType,
				}
				j := Job{
					Name:       scanArtifactJobName,
					Key:        jobKey,
					Args:       Args{ScanRequest: &request},
					EnqueuedAt: time.Now().UTC(),
				}
				scanJob := job.ScanJob{Key: jobKey, Status: job.Queued}
				if err := e.enqueue(ctx, j, scanJob); err != nil {
					return "", xerrors.Errorf("enqueuing scan job: %w", err)
				}
				created++
			}
		}
	}

	// Every produces-MIME was unsupported, so the loops above ran zero times.
	// Returning an ID here handed Harbor a 202 for a job that does not exist,
	// and Harbor then polled it until the TTL before giving up.
	if created == 0 {
		metrics.EnqueueFailuresTotal.Inc()
		return "", xerrors.Errorf("no scan job created: no supported produces mime type in the request")
	}

	return jobID, nil
}

func (e *enqueuer) enqueue(ctx context.Context, j Job, scanJob job.ScanJob) error {
	logger := slog.With(slog.String("job_id", j.Key.ID), slog.String("mime_type", j.Key.MIMEType.String()))
	logger.Debug("Enqueueing scan job")

	if err := e.store.Create(ctx, scanJob); err != nil {
		metrics.EnqueueFailuresTotal.Inc()
		return xerrors.Errorf("creating scan job %w", err)
	}

	b, err := json.Marshal(j)
	if err != nil {
		metrics.EnqueueFailuresTotal.Inc()
		return xerrors.Errorf("marshaling scan request: %w", err)
	}

	if err = e.dispatch(ctx, b); err != nil {
		metrics.EnqueueFailuresTotal.Inc()
		e.markUndispatched(ctx, logger, scanJob.Key, err)
		return xerrors.Errorf("enqueuing scan artifact job: %w", err)
	}

	metrics.EnqueuedTotal.Inc()
	logger.Debug("Successfully enqueued scan job")
	return nil
}

// markUndispatched records a job whose store record exists but whose dispatch
// failed. Left Queued it is indistinguishable from a job merely waiting for a
// worker, so Harbor would poll it until the TTL rather than being told why.
//
// Two things this deliberately does not pretend:
//
// A dispatch error does not prove non-delivery. RPUSH may have been applied with
// the reply lost, in which case a worker still has the job — and may already
// have moved it to Pending or even Finished by the time this write runs. That is
// why the write is FailIfQueued rather than an unconditional UpdateStatus: only
// a record still sitting in Queued is claimed as failed; anything a worker has
// touched is left alone rather than having a real result overwritten.
//
// The write runs on a context detached from the caller's. The common reason
// dispatch failed is that ctx is already done, and reusing it would make the
// cleanup fail for exactly the same reason -- the same trap that stranded
// terminal writes in scan.controller.
func (e *enqueuer) markUndispatched(ctx context.Context, logger *slog.Logger, key job.ScanJobKey, cause error) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), undispatchedWriteTimeout)
	defer cancel()

	msg := fmt.Sprintf("scan job could not be queued: %v (if the queue write did land, a worker may still run it)", cause)
	if uErr := e.store.FailIfQueued(writeCtx, key, msg); uErr != nil {
		logger.Warn("Could not mark an undispatched scan job as failed",
			slog.String("err", uErr.Error()))
	}
}

// makeIdentifier fails rather than returning an empty ID: every job would then
// collide on the same store key, which is near-undiagnosable in production.
func makeIdentifier() (string, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", xerrors.Errorf("generating scan job identifier: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}

func redisJobList(namespace string) string {
	return namespace + ":jobs:" + scanArtifactJobName
}
