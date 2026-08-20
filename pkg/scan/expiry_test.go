package scan

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/metrics"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence"
	predis "github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/redis"
)

// expiredJobController builds a controller over a Redis store whose only record
// has already outlived its TTL: the state of a job that waited in the queue for
// longer than SCANNER_STORE_REDIS_SCAN_JOB_TTL.
func expiredJobController(t *testing.T) (*fakeWrapper, Controller, job.ScanJobKey) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	s := predis.NewStore(etc.RedisStore{Namespace: "ns", ScanJobTTL: time.Hour}, rdb)
	key := newJobKey()
	require.NoError(t, s.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))
	mr.FastForward(2 * time.Hour)

	w := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}
	return w, NewController(s, w, harbor.Scanner{}, t.TempDir(), Options{}), key
}

func expiredScanRequest() *harbor.ScanRequest {
	return &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
}

// TestExpiredJobSkipsThePull pins that the expensive work is not done for a job
// whose record is already gone. The abort happens on the first status write,
// before the registry pull, so an overloaded adapter does not keep burning
// egress and CPU on reports that have nowhere to be stored.
func TestExpiredJobSkipsThePull(t *testing.T) {
	w, c, key := expiredJobController(t)

	require.NoError(t, c.Scan(context.Background(), key, expiredScanRequest()))
	assert.False(t, w.called, "an expired job must not reach the registry pull")
}

// TestExpiredJobIsCountedSeparately keeps the failure categories honest. Folding
// expiry into Adapter would read as an adapter bug on the dashboard when it is a
// capacity signal: raise concurrency, add replicas, or raise the TTL.
func TestExpiredJobIsCountedSeparately(t *testing.T) {
	_, c, key := expiredJobController(t)

	expired := metrics.ScansTotal.WithLabelValues(metrics.OutcomeFailure, metrics.CategoryExpired)
	adapter := metrics.ScansTotal.WithLabelValues(metrics.OutcomeFailure, metrics.CategoryAdapter)
	beforeExpired := testutil.ToFloat64(expired)
	beforeAdapter := testutil.ToFloat64(adapter)

	require.NoError(t, c.Scan(context.Background(), key, expiredScanRequest()))

	assert.Equal(t, beforeExpired+1, testutil.ToFloat64(expired))
	assert.Equal(t, beforeAdapter, testutil.ToFloat64(adapter), "expiry must not be counted as an adapter failure")
}

// TestExpiredJobDoesNotChaseTheFailedWrite: the record is gone, so writing
// Failed to it fails with the same cause. Returning that error made the worker
// log a second, misleading "Failed to scan artifact" line for what is a normal
// consequence of overload.
func TestExpiredJobDoesNotChaseTheFailedWrite(t *testing.T) {
	_, c, key := expiredJobController(t)
	err := c.Scan(context.Background(), key, expiredScanRequest())
	require.NoError(t, err)
}

// TestStoreReportsExpiryAsSentinel pins the sentinel across both backends, since
// the category mapping is an errors.Is check rather than a string match.
func TestStoreReportsExpiryAsSentinel(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	s := predis.NewStore(etc.RedisStore{Namespace: "ns", ScanJobTTL: time.Hour}, rdb)
	key := newJobKey()

	assert.ErrorIs(t, s.UpdateStatus(context.Background(), key, job.Pending), persistence.ErrJobNotFound)
	assert.ErrorIs(t, s.Finish(context.Background(), key, json.RawMessage(`{}`)), persistence.ErrJobNotFound)
}
