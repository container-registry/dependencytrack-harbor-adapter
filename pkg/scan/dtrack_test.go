package scan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/accessory"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/dtrack"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/memory"
)

type fakeFetcher struct {
	called bool
	target accessory.Target
	sbom   json.RawMessage
	err    error
}

func (f *fakeFetcher) Fetch(_ context.Context, target accessory.Target) (json.RawMessage, error) {
	f.called = true
	f.target = target
	return f.sbom, f.err
}

type fakeUploader struct {
	called   bool
	requests []dtrack.UploadRequest
	err      error
}

func (u *fakeUploader) Upload(_ context.Context, req dtrack.UploadRequest) error {
	u.called = true
	u.requests = append(u.requests, req)
	return u.err
}

func (u *fakeUploader) Ping(context.Context) error { return nil }

func harborSBOM() json.RawMessage {
	return json.RawMessage(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"from-harbor"}`)
}

func scanRequest() *harbor.ScanRequest {
	return &harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain", Authorization: basicHeader("robot$x", "pw")},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
}

func runScan(t *testing.T, w *fakeWrapper, opts Options) job.ScanJob {
	t.Helper()
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctrl := NewController(store, w, harbor.Scanner{Name: "Dependency-Track"}, t.TempDir(), opts)
	require.NoError(t, ctrl.Scan(context.Background(), key, scanRequest()))

	got, err := store.Get(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, got)
	return *got
}

// The reason this adapter exists: when Harbor already has an SBOM, the image is
// never pulled. If Generate is ever reached on this path the saving is gone.
func TestExistingHarborSBOMIsReusedWithoutPullingTheImage(t *testing.T) {
	fetcher := &fakeFetcher{sbom: harborSBOM()}
	uploader := &fakeUploader{}
	w := &fakeWrapper{sbom: json.RawMessage(`{"generated":true}`)}

	got := runScan(t, w, Options{Fetcher: fetcher, Uploader: uploader})

	assert.Equal(t, job.Finished, got.Status)
	assert.True(t, fetcher.called)
	assert.True(t, w.converted, "the reused SPDX must be converted for Dependency-Track")
	assert.False(t, w.called, "reusing an existing SBOM must not pull and scan the image")

	// Harbor must receive the document it produced, not a regenerated one.
	var report map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(got.Report, &report))
	assert.JSONEq(t, string(harborSBOM()), string(report["sbom"]))
}

// The credentials Harbor supplied for the pull are the same ones the accessory
// lookup needs; a private repository fails the lookup without them.
func TestAccessoryLookupUsesTheScanRequestCredentials(t *testing.T) {
	fetcher := &fakeFetcher{sbom: harborSBOM()}
	runScan(t, &fakeWrapper{}, Options{Fetcher: fetcher, Uploader: &fakeUploader{}})

	assert.Equal(t, "robot$x", fetcher.target.Username)
	assert.Equal(t, "pw", fetcher.target.Password)
	assert.Equal(t, "core.harbor.domain:443/library/alpine@sha256:deadbeef", fetcher.target.Ref)
}

// No accessory is the ordinary case for a project that never had SBOM generation
// enabled. It must fall through to generating, not fail.
func TestMissingAccessoryFallsBackToGenerating(t *testing.T) {
	fetcher := &fakeFetcher{err: accessory.ErrNotFound}
	w := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}

	got := runScan(t, w, Options{Fetcher: fetcher, Uploader: &fakeUploader{}})

	assert.Equal(t, job.Finished, got.Status)
	assert.True(t, w.called, "a missing accessory must fall back to generating")
}

// A broken registry, a truncated blob, a lookup timeout: the fast path is an
// optimization, and none of its failures should cost a scan that can still be
// completed by pulling the image.
func TestAccessoryLookupErrorFallsBackToGenerating(t *testing.T) {
	fetcher := &fakeFetcher{err: errors.New("registry exploded")}
	w := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}

	got := runScan(t, w, Options{Fetcher: fetcher, Uploader: &fakeUploader{}})

	assert.Equal(t, job.Finished, got.Status)
	assert.True(t, w.called)
}

// Converting a document Harbor produced should not happen, but if it does the
// scan is still completable from the image.
func TestConversionFailureFallsBackToGenerating(t *testing.T) {
	fetcher := &fakeFetcher{sbom: harborSBOM()}
	w := &fakeWrapper{
		sbom:       json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`),
		convertErr: errors.New("unparseable SPDX"),
	}

	got := runScan(t, w, Options{Fetcher: fetcher, Uploader: &fakeUploader{}})

	assert.Equal(t, job.Finished, got.Status)
	assert.True(t, w.called, "a failed conversion must fall back to generating")
}

// Dependency-Track keys projects by name and version, and Harbor supplies a
// repository and a digest. Getting this mapping wrong scatters one image's
// history across unrelated projects.
func TestUploadCarriesTheHarborIdentity(t *testing.T) {
	uploader := &fakeUploader{}
	runScan(t, &fakeWrapper{sbom: json.RawMessage(`{}`)}, Options{
		Uploader:               uploader,
		ProjectTags:            []string{"harbor", "adapter"},
		NestUnderHarborProject: true,
	})

	require.Len(t, uploader.requests, 1)
	req := uploader.requests[0]
	assert.Equal(t, "library/alpine", req.ProjectName)
	assert.Equal(t, "sha256:deadbeef", req.ProjectVersion)
	assert.Equal(t, "library", req.ParentName, "the Harbor project must become the parent")
	assert.Equal(t, []string{"harbor", "adapter"}, req.ProjectTags)
	assert.True(t, req.IsLatest)
	assert.NotEmpty(t, req.CycloneDX, "the upload must carry CycloneDX, not the SPDX Harbor gets")
}

func TestNestingUnderTheHarborProjectCanBeDisabled(t *testing.T) {
	uploader := &fakeUploader{}
	runScan(t, &fakeWrapper{sbom: json.RawMessage(`{}`)}, Options{
		Uploader:               uploader,
		NestUnderHarborProject: false,
	})

	require.Len(t, uploader.requests, 1)
	assert.Empty(t, uploader.requests[0].ParentName)
}

// The default: the SBOM is Harbor's deliverable and it is already generated, so
// a third system being unreachable must not throw it away.
func TestUploadFailureStillReturnsTheSBOMToHarbor(t *testing.T) {
	uploader := &fakeUploader{err: errors.New("dependency-track is down")}
	got := runScan(t, &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)},
		Options{Uploader: uploader})

	assert.Equal(t, job.Finished, got.Status)
	assert.NotEmpty(t, got.Report)
}

// The opposite policy, for deployments where a silent gap in the portfolio is
// worse than a visible failed scan.
func TestUploadFailureCanFailTheScan(t *testing.T) {
	uploader := &fakeUploader{err: errors.New("dependency-track is down")}
	got := runScan(t, &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)},
		Options{Uploader: uploader, FailOnUploadError: true})

	assert.Equal(t, job.Failed, got.Status)
	assert.Contains(t, got.Error, "dependency-track is down")
}

// Running without Dependency-Track configured is a legitimate mode while
// credentials are being provisioned; it must not nil-panic.
func TestScanWorksWithoutAnUploaderConfigured(t *testing.T) {
	got := runScan(t, &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}, Options{})
	assert.Equal(t, job.Finished, got.Status)
}

// A nil fetcher disables the fast path entirely rather than crashing.
func TestScanWorksWithoutAFetcherConfigured(t *testing.T) {
	w := &fakeWrapper{sbom: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)}
	got := runScan(t, w, Options{Uploader: &fakeUploader{}})

	assert.Equal(t, job.Finished, got.Status)
	assert.True(t, w.called)
}

// A failed scan must upload nothing: Dependency-Track would otherwise record an
// inventory for an image the adapter never successfully read.
func TestAFailedScanUploadsNothing(t *testing.T) {
	uploader := &fakeUploader{}
	store := memory.NewStore()
	key := newJobKey()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))

	ctrl := NewController(store, &fakeWrapper{err: errors.New("pull failed")},
		harbor.Scanner{}, t.TempDir(), Options{Uploader: uploader})
	require.NoError(t, ctrl.Scan(context.Background(), key, scanRequest()))

	assert.False(t, uploader.called)
}
