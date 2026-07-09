package contract

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/etc"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/harbor"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/http/api"
	v1 "github.com/container-registry/mikebom-harbor-adapter/pkg/http/api/v1"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/persistence/memory"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/queue"
	"github.com/container-registry/mikebom-harbor-adapter/test/contract/harborcontract"
)

// These are the exact contract strings Harbor uses. They are duplicated here as
// literals (not imported) so a drift in the adapter's constants is caught.
const (
	exactProducesSBOMReport = "application/vnd.security.sbom.report+json; version=1.0"
	exactConsumesDockerV2   = "application/vnd.docker.distribution.manifest.v2+json"
	exactConsumesOCI        = "application/vnd.oci.image.manifest.v1+json"
	exactSBOMMediaType      = "application/spdx+json"
)

func newMetadataServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg, err := etc.GetConfig()
	require.NoError(t, err)
	cfg.API.MetricsEnabled = false

	// scanner.version is the mikebom CLI version (exec'd once at startup), never
	// from env (plan D-4). Simulate a real `mikebom --version` result here.
	scanner := harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "0.1.0-alpha.55"}

	store := memory.NewStore()
	enqueuer := queue.NewEnqueuer(cfg.JobQueue, nil, store)
	info := etc.BuildInfo{Version: "9.9.9", Commit: "abcdef", Date: "2026-07-09"}
	handler := v1.NewAPIHandler(info, cfg, scanner, enqueuer, store, nil)
	return httptest.NewServer(handler)
}

// TestMetadataPassesVendoredHarborValidate proves the served /metadata document
// passes a vendored copy of Harbor's ScannerAdapterMetadata.Validate() (gate c)
// and pins the exact produces MIME string incl. "; version=1.0" (gate a).
func TestMetadataPassesVendoredHarborValidate(t *testing.T) {
	srv := newMetadataServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/metadata")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, api.MimeTypeMetadata.String(), resp.Header.Get("Content-Type"))

	// (c) Unmarshal into the vendored Harbor type and run Harbor's Validate().
	var vendored harborcontract.ScannerAdapterMetadata
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&vendored))
	require.NoError(t, vendored.Validate(), "served metadata must pass Harbor's Validate()")

	require.Len(t, vendored.Capabilities, 1, "exactly one capability")
	cap0 := vendored.Capabilities[0]
	assert.Equal(t, "sbom", cap0.Type)

	// (a) Exact produces MIME string, including the version parameter.
	require.Len(t, cap0.ProducesMimeTypes, 1)
	assert.Equal(t, exactProducesSBOMReport, cap0.ProducesMimeTypes[0])

	// consumes = docker manifest v2 + oci image manifest, no index types.
	assert.ElementsMatch(t, []string{exactConsumesDockerV2, exactConsumesOCI}, cap0.ConsumesMimeTypes)

	// registry-authorization-type advertised explicitly as Basic (plan D-2).
	assert.Equal(t, "Basic", vendored.Properties["harbor.scanner-adapter/registry-authorization-type"])

	// scanner.version is the mikebom version; adapter version lives in properties.
	assert.Equal(t, "0.1.0-alpha.55", vendored.Scanner.Version)
	assert.Equal(t, "9.9.9", vendored.Properties["org.label-schema.version"])
}

// TestMetadataSBOMMediaTypes pins additional_attributes.sbom_media_types.
func TestMetadataSBOMMediaTypes(t *testing.T) {
	srv := newMetadataServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/metadata")
	require.NoError(t, err)
	defer resp.Body.Close()

	var raw struct {
		Capabilities []struct {
			AdditionalAttributes struct {
				SBOMMediaTypes []string `json:"sbom_media_types"`
			} `json:"additional_attributes"`
		} `json:"capabilities"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))
	require.Len(t, raw.Capabilities, 1)
	assert.Equal(t, []string{exactSBOMMediaType}, raw.Capabilities[0].AdditionalAttributes.SBOMMediaTypes)
}

// TestReportEnvelopeRoundTripsThroughRawSBOMReport proves the report envelope
// round-trips through a vendored copy of Harbor's RawSBOMReport (gate b): sbom
// must be a JSON object, media_type exactly application/spdx+json, and
// json.Marshal(rpt.SBOM) reproduces the document (Harbor's retrieveSBOMContent).
func TestReportEnvelopeRoundTripsThroughRawSBOMReport(t *testing.T) {
	spdxDoc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":      "SPDXRef-DOCUMENT",
		"name":        "alpine",
		"packages": []any{
			map[string]any{"name": "musl", "SPDXID": "SPDXRef-Package-musl"},
		},
	}
	spdxBytes, err := json.Marshal(spdxDoc)
	require.NoError(t, err)

	// This is exactly what the controller stores (harbor.ScanReport marshaled).
	envelope := harbor.ScanReport{
		GeneratedAt: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		Artifact:    harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
		Scanner:     harbor.Scanner{Name: "mikebom", Vendor: "Kusari", Version: "0.1.0-alpha.55"},
		MediaType:   api.MediaTypeSPDX,
		SBOM:        json.RawMessage(spdxBytes),
	}
	stored, err := json.Marshal(envelope)
	require.NoError(t, err)

	// (b) Harbor parses the stored report into RawSBOMReport.
	var rpt harborcontract.RawSBOMReport
	require.NoError(t, json.Unmarshal(stored, &rpt))

	assert.Equal(t, exactSBOMMediaType, rpt.MediaType)
	require.NotNil(t, rpt.Scanner)
	assert.Equal(t, "mikebom", rpt.Scanner.Name)

	// sbom MUST be a JSON object (map), never a string.
	require.NotNil(t, rpt.SBOM)
	assert.Equal(t, "SPDX-2.3", rpt.SBOM["spdxVersion"])

	// Harbor re-marshals rpt.SBOM and pushes it as the accessory content.
	remarshaled, err := json.Marshal(rpt.SBOM)
	require.NoError(t, err)
	var got, want map[string]any
	require.NoError(t, json.Unmarshal(remarshaled, &got))
	require.NoError(t, json.Unmarshal(spdxBytes, &want))
	assert.Equal(t, want, got, "SBOM document must survive the Harbor round-trip")
}
