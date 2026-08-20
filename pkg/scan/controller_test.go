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

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/memory"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/syft"
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

func (s ctxStore) Finish(ctx context.Context, key job.ScanJobKey, report json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.Finish(ctx, key, report)
}

type fakeWrapper struct {
	called     bool
	converted  bool
	target     syft.Target
	jobDir     string
	sbom       json.RawMessage
	cdx        json.RawMessage
	err        error
	convertErr error
	// onCall fires when Generate is invoked; tests use it to expire the job
	// context mid-scan (simulating the per-job deadline firing during the scan).
	onCall func()
}

func (w *fakeWrapper) Version(context.Context) (string, error) { return "1.46.0", nil }

func (w *fakeWrapper) Generate(_ context.Context, target syft.Target, jobDir string) (syft.Documents, error) {
	w.called = true
	w.target = target
	w.jobDir = jobDir
	if w.onCall != nil {
		w.onCall()
	}
	if w.err != nil {
		return syft.Documents{}, w.err
	}
	return syft.Documents{SPDX: w.sbom, CycloneDX: w.cycloneDX()}, nil
}

func (w *fakeWrapper) Convert(_ context.Context, _ json.RawMessage, jobDir string) (json.RawMessage, error) {
	w.converted = true
	w.jobDir = jobDir
	if w.convertErr != nil {
		return nil, w.convertErr
	}
	return w.cycloneDX(), nil
}

// cycloneDX defaults to a minimal valid document so a test that only cares about
// the SPDX side still exercises the upload path.
func (w *fakeWrapper) cycloneDX() json.RawMessage {
	if w.cdx != nil {
		return w.cdx
	}
	return json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
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

	spdx := json.RawMessage(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`)
	wrapper := &fakeWrapper{sbom: spdx}
	scanner := harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "0.1.0-alpha.69"}

	ctrl := NewController(store, wrapper, scanner, t.TempDir(), Options{})
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain", Authorization: basicHeader("robot$x", "pw:with:colon")},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status)

	// Basic creds decoded and handed to syft (password with colons intact).
	assert.True(t, wrapper.called)
	assert.Equal(t, "core.harbor.domain:443/library/alpine@sha256:deadbeef", wrapper.target.Ref)
	assert.Equal(t, "robot$x", wrapper.target.Username)
	assert.Equal(t, "pw:with:colon", wrapper.target.Password)
	assert.False(t, wrapper.target.Insecure)

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

	wrapper := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}
	ctrl := NewController(store, wrapper, harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "v"}, t.TempDir(), Options{})

	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080"}, // http scheme => insecure
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	assert.Empty(t, wrapper.target.Username, "no authorization header must leave the pull anonymous")
	assert.Empty(t, wrapper.target.Password)
	assert.True(t, wrapper.target.Insecure, "http scheme must derive insecure=true")
	assert.Equal(t, "core:8080", wrapper.target.Registry())
}

func TestScan_WrapperErrorMarksFailed(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctrl := NewController(store, &fakeWrapper{err: errors.New("syft blew up")},
		harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "v"}, t.TempDir(), Options{})
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	assert.Equal(t, job.Failed, got.Status)
	assert.Contains(t, got.Error, "syft blew up")
}

// TestScan_PullErrorMarksFailed pins that a registry-pull failure — which now
// happens inside the syft subprocess rather than in the adapter — still lands
// on the job as Failed with the classified category visible to Harbor.
func TestScan_PullErrorMarksFailed(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	pullErr := &syft.Error{
		Category: syft.CategoryPullAuth,
		Cause:    errors.New("running syft: exit status 1: registry returned 401"),
	}
	ctrl := NewController(store, &fakeWrapper{err: pullErr},
		harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "v"}, t.TempDir(), Options{})
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain", Authorization: basicHeader("u", "p")},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	assert.Equal(t, job.Failed, got.Status)
	assert.Contains(t, got.Error, string(syft.CategoryPullAuth))
	assert.Contains(t, got.Error, "401")
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

	ctrl := NewController(store, &fakeWrapper{},
		harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "v"}, t.TempDir(), Options{})
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
// fires (here, canceled during the syft run) must still be recorded as Finished.
func TestScan_FinishedWriteSurvivesDeadlineDuringScan(t *testing.T) {
	store := ctxStore{Store: memory.NewStore()}
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel the job context while the scan is in flight (after the Pending write,
	// before the terminal writes). Only the detached terminal writes survive this.
	spdx := json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)
	wrapper := &fakeWrapper{sbom: spdx, onCall: cancel}
	ctrl := NewController(store, wrapper,
		harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "v"}, t.TempDir(), Options{})
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

// TestScan_JobDirRemoved pins that the per-job workdir handed to syft (its
// HOME/TMPDIR, and therefore where its layer scratch and blob cache land) does not
// outlive the job.
func TestScan_JobDirRemoved(t *testing.T) {
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	workDir := t.TempDir()
	wrapper := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}
	ctrl := NewController(store, wrapper, harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "v"}, workDir, Options{})
	req := &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	require.NoError(t, ctrl.Scan(context.Background(), key, req))

	require.NotEmpty(t, wrapper.jobDir)
	assert.NoDirExists(t, wrapper.jobDir)
}

func TestApplyAuth(t *testing.T) {
	t.Run("empty is anonymous", func(t *testing.T) {
		var target syft.Target
		require.NoError(t, applyAuth(&target, ""))
		assert.Empty(t, target.Username)
		assert.Empty(t, target.Password)
	})
	t.Run("basic decodes with colon password", func(t *testing.T) {
		var target syft.Target
		require.NoError(t, applyAuth(&target, basicHeader("robot$x", "a:b:c")))
		assert.Equal(t, "robot$x", target.Username)
		assert.Equal(t, "a:b:c", target.Password)
	})
	t.Run("bearer rejected", func(t *testing.T) {
		var target syft.Target
		require.Error(t, applyAuth(&target, "Bearer sometoken"))
	})
}

// TestApplyAuthSchemeIsCaseInsensitive: RFC 9110 makes the auth scheme
// case-insensitive, and matching it exactly rejected "basic" outright.
func TestApplyAuthSchemeIsCaseInsensitive(t *testing.T) {
	for _, scheme := range []string{"Basic", "basic", "BASIC", "BaSiC"} {
		t.Run(scheme, func(t *testing.T) {
			var target syft.Target
			header := scheme + " " + base64.StdEncoding.EncodeToString([]byte("robot:secret"))
			require.NoError(t, applyAuth(&target, header))
			assert.Equal(t, "robot", target.Username)
			assert.Equal(t, "secret", target.Password)
		})
	}

	// Bearer stays rejected however it is spelled.
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		var target syft.Target
		err := applyAuth(&target, scheme+" token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bearer authorization is not supported")
	}
}
