// Package memory is an in-process Store for dev and unit/component tests only.
// Production uses the Redis store (plan D-8).
package memory

import (
	"context"
	"encoding/json"
	"sync"

	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
)

type store struct {
	mu   sync.RWMutex
	jobs map[string]job.ScanJob
}

func NewStore() persistence.Store {
	return &store{jobs: make(map[string]job.ScanJob)}
}

func (s *store) Create(_ context.Context, scanJob job.ScanJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scanJob.Key.String()
	if _, ok := s.jobs[key]; ok {
		return nil // SetNX semantics: do not overwrite an existing job
	}
	s.jobs[key] = scanJob
	return nil
}

func (s *store) Get(_ context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[scanJobKey.String()]
	if !ok {
		return nil, nil
	}
	// A struct copy still shares Report's backing array, so a caller mutating
	// the returned report would mutate the stored one. Dev-only backend, but a
	// silent aliasing bug is not worth keeping.
	clone := j
	if j.Report != nil {
		clone.Report = append(json.RawMessage(nil), j.Report...)
	}
	return &clone, nil
}

func (s *store) UpdateStatus(_ context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, errorMsg ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scanJobKey.String()
	j, ok := s.jobs[key]
	if !ok {
		return xerrors.Errorf("scan job (%s): %w", key, persistence.ErrJobNotFound)
	}
	j.Status = newStatus
	if len(errorMsg) > 0 {
		j.Error = errorMsg[0]
	}
	s.jobs[key] = j
	return nil
}

func (s *store) Finish(_ context.Context, scanJobKey job.ScanJobKey, report json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scanJobKey.String()
	j, ok := s.jobs[key]
	if !ok {
		return xerrors.Errorf("scan job (%s): %w", key, persistence.ErrJobNotFound)
	}
	// Clear Error as well: the Redis store writes the terminal record from
	// scratch, so leaving a stale error here would make the two backends
	// disagree on what a finished job looks like.
	// Copy the report for the same aliasing reason Get copies it on the way out:
	// the Redis path serializes, so sharing bytes with the caller would make the
	// two backends diverge.
	j.Report = append(json.RawMessage(nil), report...)
	j.Status = job.Finished
	j.Error = ""
	s.jobs[key] = j
	return nil
}

func (s *store) FailIfQueued(_ context.Context, scanJobKey job.ScanJobKey, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scanJobKey.String()
	j, ok := s.jobs[key]
	if !ok {
		return xerrors.Errorf("scan job (%s): %w", key, persistence.ErrJobNotFound)
	}
	if j.Status != job.Queued {
		return nil
	}
	j.Status = job.Failed
	j.Error = errorMsg
	s.jobs[key] = j
	return nil
}
