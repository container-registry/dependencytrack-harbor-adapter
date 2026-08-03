package memory

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
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
	got, _ = s.Get(ctx, k)
	assert.Equal(t, job.Finished, got.Status)
}

func TestMemoryStoreUpdateMissing(t *testing.T) {
	s := NewStore()
	require.Error(t, s.UpdateStatus(context.Background(), key(), job.Finished))
}
