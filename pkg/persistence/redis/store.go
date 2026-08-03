package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	redis "github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
)

type store struct {
	cfg etc.RedisStore
	rdb *redis.Client
}

func NewStore(cfg etc.RedisStore, rdb *redis.Client) persistence.Store {
	return &store{cfg: cfg, rdb: rdb}
}

func (s *store) Create(ctx context.Context, scanJob job.ScanJob) error {
	bytes, err := encode(scanJob)
	if err != nil {
		return err
	}
	key := s.keyForScanJob(scanJob.Key)
	storeLogger(scanJob.Key).Debug("Saving scan job",
		slog.String("scan_job_status", scanJob.Status.String()),
		slog.String("redis_key", key),
		slog.Duration("expire", s.cfg.ScanJobTTL),
	)
	if err = s.rdb.SetNX(ctx, key, bytes, s.cfg.ScanJobTTL).Err(); err != nil {
		return xerrors.Errorf("creating scan job: %w", err)
	}
	return nil
}

func (s *store) update(ctx context.Context, scanJob job.ScanJob) error {
	bytes, err := encode(scanJob)
	if err != nil {
		return err
	}
	key := s.keyForScanJob(scanJob.Key)
	// SetXX reports whether the key was actually there to update. Checking only
	// Err() would treat "the key expired between the Get and this write" as
	// success and silently drop the update — the exact race ScanJobTTL makes
	// likely for a long scan.
	updated, err := s.rdb.SetXX(ctx, key, bytes, s.cfg.ScanJobTTL).Result()
	if err != nil {
		return xerrors.Errorf("updating scan job: %w", err)
	}
	if !updated {
		return xerrors.Errorf("updating scan job (%s): %w", scanJob.Key.String(), persistence.ErrJobNotFound)
	}
	return nil
}

func (s *store) Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error) {
	key := s.keyForScanJob(scanJobKey)
	value, err := s.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	scanJob, err := decode([]byte(value))
	if err != nil {
		return nil, err
	}
	return scanJob, nil
}

func (s *store) UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, errorMsg ...string) error {
	scanJob, err := s.Get(ctx, scanJobKey)
	if err != nil {
		return err
	}
	if scanJob == nil {
		return xerrors.Errorf("scan job (%s): %w", scanJobKey.String(), persistence.ErrJobNotFound)
	}
	scanJob.Status = newStatus
	if len(errorMsg) > 0 {
		scanJob.Error = errorMsg[0]
	}
	return s.update(ctx, *scanJob)
}

// Finish writes the terminal record without reading it first. Every field is
// known here — the key from the caller, Finished, an empty error and the report
// — so the read-modify-write the other updaters need would only pull the report
// back out of Redis to put it straight back in.
func (s *store) Finish(ctx context.Context, scanJobKey job.ScanJobKey, report json.RawMessage) error {
	return s.update(ctx, job.ScanJob{
		Key:    scanJobKey,
		Status: job.Finished,
		Report: report,
	})
}

func (s *store) keyForScanJob(scanJobKey job.ScanJobKey) string {
	return fmt.Sprintf("%s:scan-job:%s", s.cfg.Namespace, scanJobKey.String())
}

func storeLogger(scanJobKey job.ScanJobKey) *slog.Logger {
	return slog.With(
		slog.String("scan_job_id", scanJobKey.ID),
		slog.String("mime_type", scanJobKey.MIMEType.String()),
	)
}
