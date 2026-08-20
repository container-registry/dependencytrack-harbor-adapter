package scan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/imageprobe"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/metrics"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/memory"
)

type fakeProber struct {
	size   int64
	err    error
	called bool
	target imageprobe.Target
}

func (p *fakeProber) CompressedSize(_ context.Context, target imageprobe.Target) (int64, error) {
	p.called = true
	p.target = target
	return p.size, p.err
}

func cappedController(t *testing.T, prober imageprobe.Prober, limit int64) (*fakeWrapper, Controller, job.ScanJobKey) {
	t.Helper()
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))
	w := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}
	return w, NewController(store, w, harbor.Scanner{}, t.TempDir(), Options{Prober: prober, MaxImageSize: limit}), key
}

func cappedRequest() *harbor.ScanRequest {
	return &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080", Authorization: basicHeader("robot", "s3cret")},
		Artifact: harbor.Artifact{Repository: "library/huge", Digest: "sha256:deadbeef"},
	}
}

// TestOversizeArtifactIsRejectedBeforeThePull is the whole point of the cap: the
// measured failure without it is not a failed scan but an OOM kill of the
// container, which takes every concurrent scan down and restarts the pod.
func TestOversizeArtifactIsRejectedBeforeThePull(t *testing.T) {
	prober := &fakeProber{size: 3_700_000_000}
	w, c, key := cappedController(t, prober, 536_870_912)

	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))

	assert.True(t, prober.called, "the size check must run")
	assert.False(t, w.called, "an oversize artifact must never reach the pull")
}

func TestOversizeArtifactFailsTheJobWithAnActionableError(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))
	c := NewController(store, &fakeWrapper{}, harbor.Scanner{}, t.TempDir(),
		Options{Prober: &fakeProber{size: 3_700_000_000}, MaxImageSize: 536_870_912})

	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Failed, got.Status)
	// Both numbers and the knob to change, so the operator does not have to
	// reverse-engineer the limit from a bare "too large".
	assert.Contains(t, got.Error, "3700000000")
	assert.Contains(t, got.Error, "536870912")
	assert.Contains(t, got.Error, "SCANNER_SYFT_MAX_IMAGE_SIZE")
}

func TestOversizeArtifactIsCountedAsARefusalNotAFault(t *testing.T) {
	counter := metrics.ScansTotal.WithLabelValues(metrics.OutcomeFailure, metrics.CategoryImageTooLarge)
	adapter := metrics.ScansTotal.WithLabelValues(metrics.OutcomeFailure, metrics.CategoryAdapter)
	before := testutil.ToFloat64(counter)
	beforeAdapter := testutil.ToFloat64(adapter)

	_, c, key := cappedController(t, &fakeProber{size: 1 << 40}, 1024)
	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))

	assert.Equal(t, before+1, testutil.ToFloat64(counter))
	assert.Equal(t, beforeAdapter, testutil.ToFloat64(adapter),
		"a deliberate refusal must not be counted as an adapter fault")
}

func TestArtifactWithinTheCapIsScanned(t *testing.T) {
	w, c, key := cappedController(t, &fakeProber{size: 316_000_000}, 536_870_912)
	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))
	assert.True(t, w.called, "an artifact under the cap must be scanned normally")
}

// TestProbeFailureDoesNotBlockTheScan pins the fail-open choice. The probe
// reaches the same registry over the same credentials as the pull, so making
// every scan depend on it would trade a rare OOM for a common outage. The gap is
// counted instead.
func TestProbeFailureDoesNotBlockTheScan(t *testing.T) {
	failures := testutil.ToFloat64(metrics.ImageProbeFailuresTotal)
	w, c, key := cappedController(t, &fakeProber{err: errors.New("registry unreachable")}, 1024)

	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))

	assert.True(t, w.called, "a probe failure must not stop the scan")
	assert.Equal(t, failures+1, testutil.ToFloat64(metrics.ImageProbeFailuresTotal),
		"an unguarded scan must be visible in the metrics")
}

// TestProbeReceivesThePullCredentials: the probe hits the same private registry
// the pull does, so it needs the same Basic credentials and the same insecure
// flag, or it fails on every non-public Harbor and silently disables the guard.
func TestProbeReceivesThePullCredentials(t *testing.T) {
	prober := &fakeProber{size: 1}
	_, c, key := cappedController(t, prober, 1<<30)

	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))

	assert.Equal(t, "robot", prober.target.Username)
	assert.Equal(t, "s3cret", prober.target.Password)
	assert.True(t, prober.target.Insecure, "http:// registry.url must reach the probe as insecure")
	assert.Equal(t, "core:8080/library/huge@sha256:deadbeef", prober.target.Ref)
}

func TestSizeCapDisabledSkipsTheProbe(t *testing.T) {
	prober := &fakeProber{size: 1 << 40}
	w, c, key := cappedController(t, prober, 0)

	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))

	assert.False(t, prober.called, "a non-positive limit must skip the probe entirely")
	assert.True(t, w.called)
}

func TestNilProberSkipsTheCheck(t *testing.T) {
	w, c, key := cappedController(t, nil, 1024)
	require.NoError(t, c.Scan(context.Background(), key, cappedRequest()))
	assert.True(t, w.called)
}
