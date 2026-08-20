package memory

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
)

func key() job.ScanJobKey {
	return job.ScanJobKey{ID: "id1", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
}

func TestMemoryStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	k := key()

	// Unknown -> nil, nil.
	got, err := s.Get(ctx, k)
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, s.Create(ctx, job.ScanJob{Key: k, Status: job.Queued}))

	require.NoError(t, s.UpdateStatus(ctx, k, job.Pending))
	got, err = s.Get(ctx, k)
	require.NoError(t, err)
	assert.Equal(t, job.Pending, got.Status)

	report := json.RawMessage(`{"media_type":"application/spdx+json"}`)
	require.NoError(t, s.Finish(ctx, k, report))

	got, err = s.Get(ctx, k)
	require.NoError(t, err)
	assert.Equal(t, job.Finished, got.Status)
	assert.JSONEq(t, string(report), string(got.Report))

	// Create is SetNX: does not overwrite.
	require.NoError(t, s.Create(ctx, job.ScanJob{Key: k, Status: job.Queued}))
	got, err = s.Get(ctx, k)
	require.NoError(t, err)
	assert.Equal(t, job.Finished, got.Status)
}

func TestMemoryStoreUpdateMissing(t *testing.T) {
	s := NewStore()
	require.Error(t, s.UpdateStatus(context.Background(), key(), job.Finished))
	require.Error(t, s.Finish(context.Background(), key(), json.RawMessage(`{}`)))
	require.Error(t, s.FailIfQueued(context.Background(), key(), "boom"))
}

// TestMemoryStoreFailIfQueued mirrors the Redis contract: only a Queued record
// may be claimed as Failed by enqueue cleanup.
func TestMemoryStoreFailIfQueued(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	k := key()
	require.NoError(t, s.Create(ctx, job.ScanJob{Key: k, Status: job.Queued}))
	require.NoError(t, s.FailIfQueued(ctx, k, "undispatched"))
	got, err := s.Get(ctx, k)
	require.NoError(t, err)
	assert.Equal(t, job.Failed, got.Status)

	require.NoError(t, s.UpdateStatus(ctx, k, job.Finished))
	require.NoError(t, s.FailIfQueued(ctx, k, "undispatched"))
	got, err = s.Get(ctx, k)
	require.NoError(t, err)
	assert.Equal(t, job.Finished, got.Status, "a non-Queued record must be left untouched")
}

// TestGetReturnsAnIndependentReport pins that the returned record does not alias
// the stored one. A struct copy still shares json.RawMessage's backing array, so
// a caller writing through the returned report corrupted the store.
func TestGetReturnsAnIndependentReport(t *testing.T) {
	s := NewStore()
	ctx := context.Background()
	k := key()
	require.NoError(t, s.Create(ctx, job.ScanJob{Key: k, Status: job.Queued}))
	require.NoError(t, s.Finish(ctx, k, json.RawMessage(`{"a":1}`)))

	got, err := s.Get(ctx, k)
	require.NoError(t, err)
	got.Report[2] = 'X' // mutate through the returned copy

	again, err := s.Get(ctx, k)
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(again.Report), "the stored report must be unaffected")
}
