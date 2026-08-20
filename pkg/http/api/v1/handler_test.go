package v1

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/metrics"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence/memory"
)

type fakeEnqueuer struct {
	id  string
	err error
}

func (f *fakeEnqueuer) Enqueue(context.Context, harbor.ScanRequest) (string, error) {
	return f.id, f.err
}

func newHandler(t *testing.T, store persistence.Store, enq *fakeEnqueuer) http.Handler {
	t.Helper()
	cfg, err := etc.GetConfig()
	require.NoError(t, err)
	cfg.API.MetricsEnabled = false
	// Hermetic against ambient env: a SCANNER_API_AUTH_API_KEY set in the
	// developer's shell would otherwise arm the auth middleware and 401 every
	// test that does not send the header.
	cfg.API.APIKey = ""
	scanner := harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "0.1.0-alpha.55"}
	info := etc.BuildInfo{Version: "1.2.3", Commit: "deadbee", Date: "2026-07-09"}
	return NewAPIHandler(info, cfg, scanner, enq, store, func(context.Context) error { return nil })
}

func sbomScanRequestBody() string {
	return `{
      "registry": {"url":"https://core.harbor.domain","authorization":"Basic dXNlcjpwYXNz"},
      "artifact": {"repository":"library/alpine","digest":"sha256:deadbeef"},
      "enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]
    }`
}

func TestAcceptScan_202(t *testing.T) {
	h := newHandler(t, memory.NewStore(), &fakeEnqueuer{id: "job-1"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(sbomScanRequestBody()))
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusAccepted, rr.Code)
	assert.Equal(t, api.MimeTypeScanResponse.String(), rr.Header().Get("Content-Type"))
	var resp harbor.ScanResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "job-1", resp.ID)
}

func TestAcceptScan_ValidationMatrix(t *testing.T) {
	cases := []struct {
		name string
		body string
		code int
		msg  string
	}{
		{"malformed json", `{`, http.StatusBadRequest, ""},
		{
			"missing registry url",
			`{"registry":{"url":""},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "registry.url",
		},
		{
			"missing repository",
			`{"registry":{"url":"https://c"},"artifact":{"digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "artifact.repository",
		},
		{
			"missing digest",
			`{"registry":{"url":"https://c"},"artifact":{"repository":"a"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "artifact.digest",
		},
		{
			"vulnerability capability rejected",
			`{"registry":{"url":"https://c"},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"vulnerability","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"]}]}`,
			http.StatusUnprocessableEntity, "only supports sbom",
		},
		{
			"unsupported sbom media type",
			`{"registry":{"url":"https://c"},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/vnd.cyclonedx+json"]}}]}`,
			http.StatusUnprocessableEntity, "unsupported SBOM media type",
		},
		{
			"unsupported produces mime type",
			`{"registry":{"url":"https://c"},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.example+json"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "unsupported produces mime type",
		},
		{
			"registry url without scheme",
			`{"registry":{"url":"core.harbor.domain"},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "registry.url",
		},
		{
			"registry url with non-http scheme",
			`{"registry":{"url":"ftp://core.harbor.domain"},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "registry.url",
		},
		{
			"malformed basic authorization rejected",
			`{"registry":{"url":"https://c","authorization":"Basic not-base64!!"},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "authorization",
		},
		{
			"basic authorization without separator rejected",
			`{"registry":{"url":"https://c","authorization":"Basic dXNlcnBhc3M="},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "username:password",
		},
		{
			"bearer authorization rejected",
			`{"registry":{"url":"https://c","authorization":"Bearer tok"},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`,
			http.StatusUnprocessableEntity, "Basic",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(t, memory.NewStore(), &fakeEnqueuer{id: "x"})
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(tc.body))
			h.ServeHTTP(rr, req)
			assert.Equal(t, tc.code, rr.Code)
			if tc.msg != "" {
				assert.Contains(t, rr.Body.String(), tc.msg)
			}
			// Errors use the {"error":{"message":...}} envelope.
			if tc.code >= 400 {
				var e struct {
					Error struct {
						Message string `json:"message"`
					} `json:"error"`
				}
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &e))
			}
		})
	}
}

func TestAcceptScan_EmptyAuthAllowed(t *testing.T) {
	h := newHandler(t, memory.NewStore(), &fakeEnqueuer{id: "job-1"})
	body := `{"registry":{"url":"https://c","authorization":""},"artifact":{"repository":"a","digest":"sha256:x"},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],"parameters":{"sbom_media_types":["application/spdx+json"]}}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body))
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestAcceptScan_EmptyCapabilitiesDefaultsToSBOM(t *testing.T) {
	h := newHandler(t, memory.NewStore(), &fakeEnqueuer{id: "job-1"})
	body := `{"registry":{"url":"https://c"},"artifact":{"repository":"a","digest":"sha256:x"}}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body))
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func seedJob(t *testing.T, store persistence.Store, id string, status job.ScanJobStatus, report json.RawMessage, errMsg string) job.ScanJobKey {
	t.Helper()
	key := job.ScanJobKey{ID: id, MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
	require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: key, Status: status, Report: report, Error: errMsg}))
	return key
}

func reportRequest(id string, gzipAccept bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/"+id+"/report?sbom_media_type=application%2Fspdx%2Bjson", nil)
	req.Header.Set(api.HeaderAccept, api.MimeTypeSecuritySBOMReport.String())
	if gzipAccept {
		req.Header.Set(api.HeaderAcceptEncoding, "gzip")
	}
	return req
}

func TestGetReport_PendingReturns302WithRefreshAfter(t *testing.T) {
	store := memory.NewStore()
	seedJob(t, store, "p1", job.Pending, nil, "")
	h := newHandler(t, store, &fakeEnqueuer{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reportRequest("p1", false))

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "5", rr.Header().Get(api.HeaderRefreshAfter))
	assert.NotEmpty(t, rr.Header().Get("Location"))
}

func TestGetReport_FinishedReturns200Envelope(t *testing.T) {
	store := memory.NewStore()
	report := json.RawMessage(`{"generated_at":"2026-07-09T12:00:00Z","media_type":"application/spdx+json","sbom":{"spdxVersion":"SPDX-2.3"}}`)
	seedJob(t, store, "f1", job.Finished, report, "")
	h := newHandler(t, store, &fakeEnqueuer{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reportRequest("f1", false))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, api.MimeTypeSecuritySBOMReport.String(), rr.Header().Get("Content-Type"))
	assert.JSONEq(t, string(report), rr.Body.String())
}

func TestGetReport_GzipEncoded(t *testing.T) {
	store := memory.NewStore()
	report := json.RawMessage(`{"media_type":"application/spdx+json","sbom":{"spdxVersion":"SPDX-2.3"}}`)
	seedJob(t, store, "g1", job.Finished, report, "")
	h := newHandler(t, store, &fakeEnqueuer{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reportRequest("g1", true))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "gzip", rr.Header().Get(api.HeaderContentEncoding))

	gz, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
	require.NoError(t, err)
	decoded, err := io.ReadAll(gz)
	require.NoError(t, err)
	assert.JSONEq(t, string(report), string(decoded))
}

func TestGetReport_UnknownReturns404(t *testing.T) {
	h := newHandler(t, memory.NewStore(), &fakeEnqueuer{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reportRequest("nope", false))
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetReport_FailedReturns500(t *testing.T) {
	store := memory.NewStore()
	seedJob(t, store, "x1", job.Failed, nil, "syft exploded")
	h := newHandler(t, store, &fakeEnqueuer{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reportRequest("x1", false))
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "syft exploded")
}

func TestGetReport_MissingSBOMMediaType400(t *testing.T) {
	store := memory.NewStore()
	seedJob(t, store, "m1", job.Finished, json.RawMessage(`{}`), "")
	h := newHandler(t, store, &fakeEnqueuer{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/m1/report", nil)
	req.Header.Set(api.HeaderAccept, api.MimeTypeSecuritySBOMReport.String())
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAPIKeyMiddleware(t *testing.T) {
	cfg, err := etc.GetConfig()
	require.NoError(t, err)
	cfg.API.MetricsEnabled = false
	cfg.API.APIKey = "the-key"
	scanner := harbor.Scanner{Name: "syft", Vendor: "Kusari", Version: "v"}
	h := NewAPIHandler(etc.BuildInfo{}, cfg, scanner, &fakeEnqueuer{id: "x"}, memory.NewStore(), func(context.Context) error { return nil })

	// Missing key -> 401.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil))
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// Correct key -> 200.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
	req.Header.Set("X-ScannerAdapter-API-Key", "the-key")
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestMetricsExposesAdapterCollectors pins that /metrics carries the adapter's
// own series, not just the Go runtime defaults promhttp ships with. Registering
// a collector in a package nothing imports compiles and serves nothing.
func TestMetricsExposesAdapterCollectors(t *testing.T) {
	cfg, err := etc.GetConfig()
	require.NoError(t, err)
	cfg.API.MetricsEnabled = true
	h := NewAPIHandler(etc.BuildInfo{}, cfg, harbor.Scanner{}, &fakeEnqueuer{}, memory.NewStore(),
		func(context.Context) error { return nil })

	// A *Vec exports nothing until a label combination has been used, so the
	// labeled metrics need one observation before the scrape can see them.
	metrics.ScansTotal.WithLabelValues(metrics.OutcomeSuccess, metrics.CategoryNone).Inc()
	metrics.ScanDurationSeconds.WithLabelValues(metrics.OutcomeSuccess).Observe(0)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rr.Code)

	body := rr.Body.String()
	for _, name := range []string{
		"harbor_scanner_dependencytrack_scans_total",
		"harbor_scanner_dependencytrack_scan_duration_seconds",
		"harbor_scanner_dependencytrack_queue_wait_seconds",
		"harbor_scanner_dependencytrack_scans_in_flight",
		"harbor_scanner_dependencytrack_enqueued_total",
		"harbor_scanner_dependencytrack_report_stored_bytes",
	} {
		assert.Contains(t, body, name)
	}
}

func TestProbes(t *testing.T) {
	h := newHandler(t, memory.NewStore(), &fakeEnqueuer{})
	for _, path := range []string{"/probe/healthy", "/probe/ready"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusOK, rr.Code, path)
	}
}
