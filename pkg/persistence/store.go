// Package persistence defines the scan-job store interface and its Redis and
// in-memory implementations.
package persistence

import (
	"context"
	"encoding/json"

	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
)

type Store interface {
	Create(ctx context.Context, scanJob job.ScanJob) error
	Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error)
	UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, error ...string) error
	// UpdateReport stores the pre-marshaled report envelope (json.RawMessage).
	UpdateReport(ctx context.Context, scanJobKey job.ScanJobKey, report json.RawMessage) error
}
