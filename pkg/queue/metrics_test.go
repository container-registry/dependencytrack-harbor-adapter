package queue

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/metrics"
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
