package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
)

type capturingController struct {
	gotDeadline bool
	deadline    time.Time
}

func (c *capturingController) Scan(ctx context.Context, _ job.ScanJobKey, _ *harbor.ScanRequest) error {
	c.deadline, c.gotDeadline = ctx.Deadline()
	return nil
}

// TestRunJobBoundsScanByDeadline proves the whole job (pull + scan) is bounded by a
// deadline. Before the fix, controller.Scan received context.Background() straight
// from main, so an unbounded registry pull could wedge the (single) worker goroutine
// forever. runJob must hand controller.Scan a context whose deadline is ~lockTTL out.
func TestRunJobBoundsScanByDeadline(t *testing.T) {
	const lockTTL = 90 * time.Second
	ctrl := &capturingController{}
	w := &worker{lockTTL: lockTTL, controller: ctrl}

	before := time.Now()
	err := w.runJob(context.Background(), Job{})
	require.NoError(t, err)

	require.True(t, ctrl.gotDeadline, "controller.Scan must receive a context with a deadline (unbounded pull would otherwise wedge the worker)")
	remaining := time.Until(ctrl.deadline)
	assert.Greater(t, remaining, lockTTL-5*time.Second, "deadline must be ~lockTTL out")
	assert.LessOrEqual(t, remaining, lockTTL, "deadline must not exceed lockTTL")
	assert.WithinDuration(t, before.Add(lockTTL), ctrl.deadline, 5*time.Second)
}

// countingController records every job key it is asked to scan.
type countingController struct {
	mu   sync.Mutex
	keys []job.ScanJobKey
}

func (c *countingController) Scan(_ context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = append(c.keys, key)
	return nil
}

func (c *countingController) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.keys)
}

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb
}

// TestEnqueueBeforeWorkerStartsStillRuns is the regression pin for the move off
// Redis Pub/Sub. Publish drops a message when nobody is subscribed, so a job
// accepted during a worker restart was silently lost: the store record stayed
// Queued and Harbor 302-polled it until the TTL. With a list the entry waits.
func TestEnqueueBeforeWorkerStartsStillRuns(t *testing.T) {
	_, rdb := newTestRedis(t)
	const ns = "test.ns"

	enq := &enqueuer{namespace: ns, rdb: rdb, store: noopStore{}}
	j := Job{Name: scanArtifactJobName, Key: job.ScanJobKey{ID: "job-1", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}, Args: Args{ScanRequest: &harbor.ScanRequest{}}}
	require.NoError(t, enq.enqueue(context.Background(), j, jobpkgScanJob(j)))

	// No worker was running at enqueue time; start one only now.
	ctrl := &countingController{}
	w := NewWorker(etc.JobQueue{Namespace: ns, WorkerConcurrency: 1}, time.Minute, rdb, ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == 1 }, 10*time.Second, 20*time.Millisecond,
		"a job enqueued while no worker was listening must still be picked up")
	assert.Equal(t, "job-1", ctrl.keys[0].ID)
}

// TestBacklogLargerThanPubSubBufferIsNotDropped pins the second Pub/Sub failure
// mode: go-redis's PubSub.Channel() buffers 100 messages and discards the rest
// while the reader loop is busy scanning. A list has no such bound.
func TestBacklogLargerThanPubSubBufferIsNotDropped(t *testing.T) {
	_, rdb := newTestRedis(t)
	const ns = "test.ns"
	const jobs = 150 // > go-redis's 100-message Channel() buffer

	enq := &enqueuer{namespace: ns, rdb: rdb, store: noopStore{}}
	for i := 0; i < jobs; i++ {
		j := Job{Name: scanArtifactJobName, Key: job.ScanJobKey{ID: fmt.Sprintf("job-%d", i), MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}, Args: Args{ScanRequest: &harbor.ScanRequest{}}}
		require.NoError(t, enq.enqueue(context.Background(), j, jobpkgScanJob(j)))
	}

	ctrl := &countingController{}
	w := NewWorker(etc.JobQueue{Namespace: ns, WorkerConcurrency: 2}, time.Minute, rdb, ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == jobs }, 30*time.Second, 50*time.Millisecond,
		"every enqueued job must be delivered; got %d of %d", ctrl.count(), jobs)
}

// noopStore satisfies persistence.Store for the enqueue path; these tests care
// only about the queue transport, not the store.
type noopStore struct{}

func (noopStore) Create(context.Context, job.ScanJob) error { return nil }
func (noopStore) Get(context.Context, job.ScanJobKey) (*job.ScanJob, error) {
	return nil, nil
}

func (noopStore) UpdateStatus(context.Context, job.ScanJobKey, job.ScanJobStatus, ...string) error {
	return nil
}
func (noopStore) UpdateReport(context.Context, job.ScanJobKey, json.RawMessage) error { return nil }

func jobpkgScanJob(j Job) job.ScanJob {
	return job.ScanJob{Key: j.Key, Status: job.Queued}
}
