package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/harbor"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/http/api"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/job"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence/memory"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/registry"
)

// ctxStore wraps a Store and rejects writes on an expired context, mirroring
// go-redis (which fails any command once ctx is Done). The memory store ignores
// ctx, so it cannot exercise the detached-context terminal writes on its own.
type ctxStore struct {
	persistence.Store
}

func (s ctxStore) UpdateStatus(ctx context.Context, key job.ScanJobKey, status job.ScanJobStatus, msg ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.UpdateStatus(ctx, key, status, msg...)
}

func (s ctxStore) UpdateReport(ctx context.Context, key job.ScanJobKey, report json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.UpdateReport(ctx, key, report)
}

type fakePuller struct {
	called bool
	ref    registry.ImageRef
	err    error
	// onCall fires when PullToTarball is invoked; tests use it to expire the job
	// context mid-scan (simulating the per-job deadline firing during the pull).
	onCall func()
}

func (p *fakePuller) PullToTarball(_ context.Context, ref registry.ImageRef, _ string) error {
	p.called = true
	p.ref = ref
	if p.onCall != nil {
		p.onCall()
	}
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

// TestScan_FailedWriteSurvivesExpiredContext proves the Failed status write is not
// lost when the per-job deadline (queue.runJob) has already fired. Against a store
// that fails writes on an expired context (like go-redis), reusing the job context
// for the Failed write would leave the job stuck Pending; the detached write must
// still land it as Failed.
func TestScan_FailedWriteSurvivesExpiredContext(t *testing.T) {
	store := ctxStore{Store: memory.NewStore()}
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctrl := NewController(store, &fakePuller{}, &fakeWrapper{},
		harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "v"}, t.TempDir())
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}

	// Job context already past its deadline: every write on it fails.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	require.NoError(t, ctrl.Scan(ctx, key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Failed, got.Status, "an expired job context must not leave the job Pending")
}

// TestScan_FinishedWriteSurvivesDeadlineDuringScan proves the terminal report and
// Finished writes are detached too: a scan that completes just as the deadline
// fires (here, cancelled during the pull) must still be recorded as Finished.
func TestScan_FinishedWriteSurvivesDeadlineDuringScan(t *testing.T) {
	store := ctxStore{Store: memory.NewStore()}
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel the job context while the pull is in flight (after the Pending write,
	// before the terminal writes). Only the detached terminal writes survive this.
	puller := &fakePuller{onCall: cancel}
	spdx := json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)
	ctrl := NewController(store, puller, &fakeWrapper{sbom: spdx},
		harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "v"}, t.TempDir())
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(ctx, key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status, "a scan that completed under the deadline must record Finished")
	require.NotNil(t, got.Report)
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
