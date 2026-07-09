// Package queue is the Redis Pub/Sub job queue (enqueuer + worker) with a SetNX
// distributed lock, ported from harbor-scanner-trivy. The lock TTL is derived
// from the scan timeout rather than a copied constant (plan m5).
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

	"github.com/container-registry/mikebom-harbor-adapter/pkg/etc"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/harbor"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/http/api"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/job"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence"
)

const scanArtifactJobName = "scan_artifact"

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type enqueuer struct {
	namespace string
	rdb       *redis.Client
	store     persistence.Store
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
	return &enqueuer{
		namespace: config.Namespace,
		rdb:       rdb,
		store:     store,
	}
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	if len(request.Capabilities) == 0 {
		return "", xerrors.Errorf("no capabilities provided")
	}

	jobID := makeIdentifier()

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

	if err = e.rdb.Publish(ctx, redisJobChannel(e.namespace), b).Err(); err != nil {
		return xerrors.Errorf("enqueuing scan artifact job: %v", err)
	}

	logger.Debug("Successfully enqueued scan job")
	return nil
}

func makeIdentifier() string {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func redisJobChannel(namespace string) string {
	return namespace + ":jobs:" + scanArtifactJobName
}
