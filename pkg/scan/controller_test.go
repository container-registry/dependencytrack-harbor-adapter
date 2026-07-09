package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/harbor"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/http/api"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/job"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence/memory"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/registry"
)

type fakePuller struct {
	called bool
	ref    registry.ImageRef
	err    error
}

func (p *fakePuller) PullToTarball(_ context.Context, ref registry.ImageRef, _ string) error {
	p.called = true
	p.ref = ref
	return p.err
}

type fakeWrapper struct {
	sbom json.RawMessage
	err  error
}

func (w *fakeWrapper) Version(context.Context) (string, error) { return "0.1.0-alpha.55", nil }
func (w *fakeWrapper) GenerateSBOM(context.Context, string, string) (json.RawMessage, error) {
	return w.sbom, w.err
}

func newJobKey() job.ScanJobKey {
	return job.ScanJobKey{ID: "abc123", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestScan_Success(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	puller := &fakePuller{}
	spdx := json.RawMessage(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`)
	wrapper := &fakeWrapper{sbom: spdx}
	scanner := harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "0.1.0-alpha.55"}

	ctrl := NewController(store, puller, wrapper, scanner, t.TempDir())
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain", Authorization: basicHeader("robot$x", "pw:with:colon")},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status)

	// Basic creds decoded and passed to the puller (password with colons intact).
	assert.True(t, puller.called)
	assert.Equal(t, "robot$x", puller.ref.Username)
	assert.Equal(t, "pw:with:colon", puller.ref.Password)
	assert.False(t, puller.ref.Anonymous)
	assert.False(t, puller.ref.Insecure)

	// Report envelope round-trips and embeds the SBOM object.
	var env harbor.ScanReport
	require.NoError(t, json.Unmarshal(got.Report, &env))
	assert.Equal(t, api.MediaTypeSPDX, env.MediaType)
	var sbom map[string]any
	require.NoError(t, json.Unmarshal(env.SBOM, &sbom))
	assert.Equal(t, "SPDX-2.3", sbom["spdxVersion"])
}

func TestScan_AnonymousWhenNoAuth(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	puller := &fakePuller{}
	ctrl := NewController(store, puller, &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)},
		harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "v"}, t.TempDir())

	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080"}, // http scheme => insecure
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	assert.True(t, puller.ref.Anonymous)
	assert.True(t, puller.ref.Insecure, "http scheme must derive insecure=true")
}

func TestScan_WrapperErrorMarksFailed(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctrl := NewController(store, &fakePuller{}, &fakeWrapper{err: errors.New("mikebom blew up")},
		harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "v"}, t.TempDir())
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	assert.Equal(t, job.Failed, got.Status)
	assert.Contains(t, got.Error, "mikebom blew up")
}

func TestScan_PullErrorMarksFailed(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctrl := NewController(store, &fakePuller{err: errors.New("401 unauthorized")}, &fakeWrapper{},
		harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "v"}, t.TempDir())
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain", Authorization: basicHeader("u", "p")},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	assert.Equal(t, job.Failed, got.Status)
	assert.Contains(t, got.Error, "401 unauthorized")
}

func TestApplyAuth(t *testing.T) {
	t.Run("empty is anonymous", func(t *testing.T) {
		var ref registry.ImageRef
		require.NoError(t, applyAuth(&ref, ""))
		assert.True(t, ref.Anonymous)
	})
	t.Run("basic decodes with colon password", func(t *testing.T) {
		var ref registry.ImageRef
		require.NoError(t, applyAuth(&ref, basicHeader("robot$x", "a:b:c")))
		assert.Equal(t, "robot$x", ref.Username)
		assert.Equal(t, "a:b:c", ref.Password)
	})
	t.Run("bearer rejected", func(t *testing.T) {
		var ref registry.ImageRef
		require.Error(t, applyAuth(&ref, "Bearer sometoken"))
	})
}
