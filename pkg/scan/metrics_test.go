package scan

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/metrics"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence/memory"
	"github.com/container-registry/waybill-harbor-adapter/pkg/waybill"
)

// TestScanRecordsOutcomeAndCategory is the reason the metrics exist: the error
// categories were already computed for the job error string and went nowhere but
// the logs, so "scans are failing" could not be told apart from "the robot
// account lost pull rights" without grepping pods.
func TestScanRecordsOutcomeAndCategory(t *testing.T) {
	tests := []struct {
		name     string
		wrapErr  error
		outcome  string
		category string
	}{
		{
			name:     "success",
			outcome:  metrics.OutcomeSuccess,
			category: metrics.CategoryNone,
		},
		{
			name:     "registry rejected the credentials",
			wrapErr:  &waybill.Error{Category: waybill.CategoryPullAuth, Detail: "401 Unauthorized"},
			outcome:  metrics.OutcomeFailure,
			category: string(waybill.CategoryPullAuth),
		},
		{
			name:     "registry transport is misconfigured",
			wrapErr:  &waybill.Error{Category: waybill.CategoryPullTransport, Detail: "unknown issuer"},
			outcome:  metrics.OutcomeFailure,
			category: string(waybill.CategoryPullTransport),
		},
		{
			name:     "waybill itself failed",
			wrapErr:  &waybill.Error{Category: waybill.CategoryExec, Detail: "exit 101"},
			outcome:  metrics.OutcomeFailure,
			category: string(waybill.CategoryExec),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.NewStore()
			key := newJobKey()
			require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

			counter := metrics.ScansTotal.WithLabelValues(tc.outcome, tc.category)
			before := testutil.ToFloat64(counter)

			wrapper := &fakeWrapper{
				sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`),
				err:  tc.wrapErr,
			}
			c := NewController(store, wrapper, harbor.Scanner{}, t.TempDir())
			require.NoError(t, c.Scan(context.Background(), key, &harbor.ScanRequest{
				Registry: harbor.Registry{URL: "http://core:8080"},
				Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
			}))

			assert.Equal(t, before+1, testutil.ToFloat64(counter),
				"scan must be counted as outcome=%s category=%s", tc.outcome, tc.category)
		})
	}
}

// TestAdapterFailuresAreNotBlamedOnWaybill pins the separate label for failures
// the adapter raised itself. Folding them into WaybillExec would send an
// operator debugging the scanner for what is an adapter bug.
func TestAdapterFailuresAreNotBlamedOnWaybill(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	counter := metrics.ScansTotal.WithLabelValues(metrics.OutcomeFailure, "Adapter")
	before := testutil.ToFloat64(counter)

	c := NewController(store, &fakeWrapper{}, harbor.Scanner{}, t.TempDir())
	// nil request: raised by the controller, never reaches waybill.
	require.NoError(t, c.Scan(context.Background(), key, nil))

	assert.Equal(t, before+1, testutil.ToFloat64(counter))
}

// TestScanDurationIsObserved guards against the histogram being registered but
// never written to, which reads on a dashboard as "no scans ran" rather than as
// a broken metric.
func TestScanDurationIsObserved(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	obs := metrics.ScanDurationSeconds.WithLabelValues(metrics.OutcomeSuccess)
	before := observationCount(t, obs)

	wrapper := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}
	c := NewController(store, wrapper, harbor.Scanner{}, t.TempDir())
	require.NoError(t, c.Scan(context.Background(), key, &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}))

	assert.Equal(t, before+1, observationCount(t, obs))
}

func observationCount(t *testing.T, obs prometheus.Observer) uint64 {
	t.Helper()
	m, ok := obs.(prometheus.Metric)
	require.True(t, ok, "observer must be collectable")
	var pb dto.Metric
	require.NoError(t, m.Write(&pb))
	return pb.GetHistogram().GetSampleCount()
}
