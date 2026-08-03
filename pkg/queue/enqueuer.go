// Package queue is the Redis job queue (enqueuer + worker) with a SetNX
// distributed lock, ported from harbor-scanner-trivy. The lock TTL is derived
// from the scan timeout rather than a copied constant (plan m5).
//
// Transport is a Redis list (RPUSH / BRPOP), not Pub/Sub: see worker.Start for
// the two ways Pub/Sub silently loses an accepted job.
package queue

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
)

const scanArtifactJobName = "scan_artifact"

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
			// RPUSH appends at the tail and the workers BLPOP from the head:
			// opposite ends, so the queue is FIFO. (Same-end RPUSH/BRPOP would be
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
					Name: scanArtifactJobName,
					Key:  jobKey,
					Args: Args{ScanRequest: &request},
				}
				scanJob := job.ScanJob{Key: jobKey, Status: job.Queued}
				if err := e.enqueue(ctx, j, scanJob); err != nil {
					return "", xerrors.Errorf("enqueuing scan job: %v", err)
				}
			}
		}
	}

	return jobID, nil
}

func (e *enqueuer) enqueue(ctx context.Context, j Job, scanJob job.ScanJob) error {
	logger := slog.With(slog.String("job_id", j.Key.ID), slog.String("mime_type", j.Key.MIMEType.String()))
	logger.Debug("Enqueueing scan job")

	if err := e.store.Create(ctx, scanJob); err != nil {
		return xerrors.Errorf("creating scan job %v", err)
	}

	b, err := json.Marshal(j)
	if err != nil {
		return xerrors.Errorf("marshaling scan request: %v", err)
	}

	if err = e.dispatch(ctx, b); err != nil {
		return xerrors.Errorf("enqueuing scan artifact job: %v", err)
	}

	logger.Debug("Successfully enqueued scan job")
	return nil
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
