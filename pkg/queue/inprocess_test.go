package queue

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/memory"
)

func sbomRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
		Capabilities: []harbor.Capability{{
			Type:              harbor.CapabilityTypeSBOM,
			ProducesMIMETypes: []string{api.MimeTypeSecuritySBOMReport.String()},
			Parameters:        &harbor.CapabilityAttributes{SBOMMediaTypes: []api.MediaType{api.MediaTypeSPDX}},
		}},
	}
}

// TestInProcessQueueRunsTheScan is the regression pin for the memory backend.
// It used to build an enqueuer around a nil Redis client and start no worker at
// all, so the adapter came up healthy and could not run a single scan: the first
// POST /api/v1/scan panicked on the nil dereference, and had it not, no consumer
// existed to pick the job up.
func TestInProcessQueueRunsTheScan(t *testing.T) {
	store := memory.NewStore()
	ctrl := &countingController{}
	enq, w := NewInProcessQueue(
		etc.JobQueue{Namespace: "harbor.scanner.dependencytrack:job-queue", WorkerConcurrency: 1},
		time.Minute, store, ctrl,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	id, err := enq.Enqueue(context.Background(), sbomRequest())
	require.NoError(t, err, "enqueue must not panic or error under the memory backend")
	require.NotEmpty(t, id)

	require.Eventually(t, func() bool { return ctrl.count() == 1 }, 10*time.Second, 10*time.Millisecond,
		"the in-process worker must actually run the enqueued scan")

	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	assert.Equal(t, id, ctrl.keys[0].ID)
	assert.Equal(t, api.MediaTypeSPDX, ctrl.keys[0].MediaType)
}

// TestInProcessQueueCreatesTheJobRecord proves the poll-side contract holds too:
// the store record Harbor polls exists as soon as Enqueue returns, so the report
// endpoint answers 302 rather than 404 before the worker gets to it.
func TestInProcessQueueCreatesTheJobRecord(t *testing.T) {
	store := memory.NewStore()
	// No worker started: the record must be there on Enqueue alone.
	enq, _ := NewInProcessQueue(
		etc.JobQueue{Namespace: "ns", WorkerConcurrency: 1},
		time.Minute, store, &countingController{},
	)

	id, err := enq.Enqueue(context.Background(), sbomRequest())
	require.NoError(t, err)

	got, err := store.Get(context.Background(), job.ScanJobKey{
		ID: id, MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX,
	})
	require.NoError(t, err)
	require.NotNil(t, got, "Harbor polls immediately after the 202; the Queued record must already exist")
	assert.Equal(t, job.Queued, got.Status)
}

// TestInProcessQueueRejectsWhenFull pins that a full backlog fails the enqueue
// instead of blocking the HTTP handler past Harbor's 5s client timeout.
func TestInProcessQueueRejectsWhenFull(t *testing.T) {
	store := memory.NewStore()
	// No worker consuming, so the channel fills and stays full.
	enq, _ := NewInProcessQueue(
		etc.JobQueue{Namespace: "ns", WorkerConcurrency: 1},
		time.Minute, store, &countingController{},
	)

	var lastErr error
	for i := 0; i < inProcessBacklog+5; i++ {
		if _, err := enq.Enqueue(context.Background(), sbomRequest()); err != nil {
			lastErr = err
			break
		}
	}
	require.Error(t, lastErr, "a full in-process backlog must fail fast, not block the handler")
	assert.Contains(t, lastErr.Error(), "full")
}
