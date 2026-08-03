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
	// Finish stores the pre-marshaled report envelope (json.RawMessage) and marks
	// the job Finished in a single write.
	//
	// It is one method rather than UpdateReport + UpdateStatus(Finished) because
	// each of those was a read-modify-write: finishing a job dragged the whole
	// multi-MB SPDX report across the wire four times. Every field of the record
	// is known here, so the terminal write needs no read at all.
	Finish(ctx context.Context, scanJobKey job.ScanJobKey, report json.RawMessage) error
}
