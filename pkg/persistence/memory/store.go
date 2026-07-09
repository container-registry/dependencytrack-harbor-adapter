// Package memory is an in-process Store for dev and unit/component tests only.
// Production uses the Redis store (plan D-8).
package memory

import (
	"context"
	"encoding/json"
	"sync"

	"golang.org/x/xerrors"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/job"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence"
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
	clone := j
	return &clone, nil
}

func (s *store) UpdateStatus(_ context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, errorMsg ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scanJobKey.String()
	j, ok := s.jobs[key]
	if !ok {
		return xerrors.Errorf("scan job (%s) not found", key)
	}
	j.Status = newStatus
	if len(errorMsg) > 0 {
		j.Error = errorMsg[0]
	}
	s.jobs[key] = j
	return nil
}

func (s *store) UpdateReport(_ context.Context, scanJobKey job.ScanJobKey, report json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scanJobKey.String()
	j, ok := s.jobs[key]
	if !ok {
		return xerrors.Errorf("scan job (%s) not found", key)
	}
	j.Report = report
	s.jobs[key] = j
	return nil
}
