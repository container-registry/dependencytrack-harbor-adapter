package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/container-registry/waybill-harbor-adapter/pkg/job"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/metrics"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence/memory"
)

// TestDepthCountsWaitingJobs backs the queue_depth gauge. Depth is what tells an
// operator that scans are late because the worker pool is saturated rather than
// because any individual scan is slow.
func TestDepthCountsWaitingJobs(t *testing.T) {
	_, rdb := newTestRedis(t)
	const ns = "test.ns"

	// No worker started, so nothing is consumed and the list holds every job.
	enq := NewEnqueuer(etc.JobQueue{Namespace: ns}, rdb, noopStore{})
	for i := 0; i < 3; i++ {
		_, err := enq.Enqueue(context.Background(), sbomRequest())
		require.NoError(t, err)
	}

	w := NewWorker(etc.JobQueue{Namespace: ns, WorkerConcurrency: 1}, time.Minute, rdb, &countingController{})
	depth, err := w.Depth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), depth)
}

func TestInProcessDepthCountsWaitingJobs(t *testing.T) {
	enq, w := NewInProcessQueue(
		etc.JobQueue{Namespace: "ns", WorkerConcurrency: 1},
		time.Minute, memory.NewStore(), &countingController{},
	)
	for i := 0; i < 3; i++ {
		_, err := enq.Enqueue(context.Background(), sbomRequest())
		require.NoError(t, err)
	}

	depth, err := w.Depth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), depth)
}

// TestQueueWaitIsObserved pins that the wait is measured from enqueue, not from
// pickup. Measuring the scan alone hides the case this metric exists for: a fast
// scan that Harbor still abandons because the job sat in the list first.
func TestQueueWaitIsObserved(t *testing.T) {
	_, rdb := newTestRedis(t)
	const ns = "test.ns"

	enq := NewEnqueuer(etc.JobQueue{Namespace: ns}, rdb, noopStore{})
	_, err := enq.Enqueue(context.Background(), sbomRequest())
	require.NoError(t, err)

	before := observationCount(t, metrics.QueueWaitSeconds)

	ctrl := &countingController{}
	w := NewWorker(etc.JobQueue{Namespace: ns, WorkerConcurrency: 1}, time.Minute, rdb, ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == 1 }, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, before+1, observationCount(t, metrics.QueueWaitSeconds))
}

// TestQueueWaitSkipsJobsWithoutTimestamp covers the upgrade window: jobs already
// on the list when this field was added carry a zero time, and reporting a wait
// measured from the epoch would wreck the histogram permanently.
func TestQueueWaitSkipsJobsWithoutTimestamp(t *testing.T) {
	before := observationCount(t, metrics.QueueWaitSeconds)
	observeQueueWait(Job{})
	assert.Equal(t, before, observationCount(t, metrics.QueueWaitSeconds))
}

func observationCount(t *testing.T, obs prometheus.Observer) uint64 {
	t.Helper()
	m, ok := obs.(prometheus.Metric)
	require.True(t, ok, "observer must be collectable")
	var pb dto.Metric
	require.NoError(t, m.Write(&pb))
	return pb.GetHistogram().GetSampleCount()
}

// TestEnqueueFailsWhenNoJobWasCreated pins the accepted-but-nonexistent case: if
// every produces-MIME is unsupported the fan-out loops run zero times, and
// returning an ID handed Harbor a 202 for a job that does not exist, which it
// then polled until the TTL.
func TestEnqueueFailsWhenNoJobWasCreated(t *testing.T) {
	_, rdb := newTestRedis(t)
	enq := NewEnqueuer(etc.JobQueue{Namespace: "ns"}, rdb, noopStore{})

	req := sbomRequest()
	req.Capabilities[0].ProducesMIMETypes = []string{"application/vnd.oci.image.manifest.v1+json"}

	id, err := enq.Enqueue(context.Background(), req)
	require.Error(t, err, "an request that produces no job must not report success")
	assert.Empty(t, id)
	assert.Contains(t, err.Error(), "no scan job created")
}

// TestUndispatchedJobIsMarkedFailed pins that a job whose store record was
// created but whose dispatch then failed does not sit at Queued. Queued is
// indistinguishable from "waiting for a worker", so Harbor polled such a job
// until the TTL instead of being told the real cause.
func TestUndispatchedJobIsMarkedFailed(t *testing.T) {
	store := memory.NewStore()
	var dispatched job.ScanJobKey
	enq := &enqueuer{
		namespace: "ns",
		store:     store,
		dispatch: func(_ context.Context, payload []byte) error {
			var j Job
			require.NoError(t, json.Unmarshal(payload, &j))
			dispatched = j.Key
			return errors.New("transport down")
		},
	}

	_, err := enq.Enqueue(context.Background(), sbomRequest())
	require.Error(t, err)
	require.NotEmpty(t, dispatched.ID, "dispatch must have been attempted")

	got, err := store.Get(context.Background(), dispatched)
	require.NoError(t, err)
	require.NotNil(t, got, "the record is created before dispatch, so it exists")
	assert.Equal(t, job.Failed, got.Status, "an undispatched job must not be left Queued")
	assert.Contains(t, got.Error, "transport down")
}

// TestUndispatchedCleanupSurvivesACanceledContext pins the detached write. The
// usual reason a dispatch fails is that the request context is already done, and
// reusing it made the cleanup fail for exactly the same reason -- leaving the
// record at Queued, which is the state this path exists to avoid.
func TestUndispatchedCleanupSurvivesACanceledContext(t *testing.T) {
	store := memory.NewStore()
	var dispatched job.ScanJobKey

	ctx, cancel := context.WithCancel(context.Background())
	enq := &enqueuer{
		namespace: "ns",
		store:     ctxStore{Store: store},
		dispatch: func(dctx context.Context, payload []byte) error {
			var j Job
			require.NoError(t, json.Unmarshal(payload, &j))
			dispatched = j.Key
			cancel() // the request went away mid-dispatch
			return dctx.Err()
		},
	}

	_, err := enq.Enqueue(ctx, sbomRequest())
	require.Error(t, err)
	require.NotEmpty(t, dispatched.ID)

	got, err := store.Get(context.Background(), dispatched)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Failed, got.Status, "the cleanup must not inherit the dead context")
}

// ctxStore rejects writes on an expired context, the way go-redis does. The
// memory store ignores ctx, so it cannot exercise the detached write on its own.
type ctxStore struct {
	persistence.Store
}

func (s ctxStore) UpdateStatus(ctx context.Context, key job.ScanJobKey, status job.ScanJobStatus, msg ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.UpdateStatus(ctx, key, status, msg...)
}
