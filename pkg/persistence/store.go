// Package persistence defines the scan-job store interface and its Redis and
// in-memory implementations.
package persistence

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
)

// ErrJobNotFound is returned when a write targets a record that is not there.
// In practice that means the job outlived SCANNER_STORE_REDIS_SCAN_JOB_TTL while
// it sat in the queue, which is a capacity signal, not a bug — so it is a
// sentinel rather than a bare string, and callers report it separately instead
// of folding it in with genuine failures.
var ErrJobNotFound = errors.New("scan job not found (queued longer than the scan job TTL?)")

type Store interface {
	Create(ctx context.Context, scanJob job.ScanJob) error
	Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error)
	UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, errorMsg ...string) error
	// Finish stores the pre-marshaled report envelope (json.RawMessage) and marks
	// the job Finished in a single write.
	//
	// It is one method rather than UpdateReport + UpdateStatus(Finished) because
	// each of those was a read-modify-write: finishing a job dragged the whole
	// multi-MB SPDX report across the wire four times. Every field of the record
	// is known here, so the terminal write needs no read at all.
	Finish(ctx context.Context, scanJobKey job.ScanJobKey, report json.RawMessage) error
	// FailIfQueued marks the job Failed only while it is still Queued, atomically
	// with respect to concurrent writers. It exists for enqueue cleanup: a
	// dispatch error does not prove non-delivery (the queue write may have landed
	// with the reply lost), so a worker may already be running — or have finished
	// — the job. An unconditional Failed write would overwrite that real result.
	// A record no longer Queued is left untouched and no error is returned.
	FailIfQueued(ctx context.Context, scanJobKey job.ScanJobKey, errorMsg string) error
}
