// Package harbor holds the Harbor Scanner Adapter API v1 domain models used by
// this adapter. It is ported from harbor-scanner-trivy with all vulnerability
// types stripped: mikebom generates SBOMs only, so the adapter advertises a
// single "sbom" capability.
package harbor

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/http/api"
)

type CapabilityType string

const (
	CapabilityTypeSBOM          CapabilityType = "sbom"
	CapabilityTypeVulnerability CapabilityType = "vulnerability"
)

// SupportedSBOMMediaTypes lists the only SBOM media type this adapter accepts.
// Harbor core hardcodes application/spdx+json, so CycloneDX is intentionally not
// advertised (plan D-3).
var SupportedSBOMMediaTypes = []api.MediaType{
	api.MediaTypeSPDX,
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MimeType   string `json:"mime_type,omitempty"`
}

// ScanReportQuery holds the query parameters at "/scan/{scan_request_id}/report".
type ScanReportQuery struct {
	SBOMMediaType api.MediaType `schema:"sbom_media_type"`
}

type ScanRequest struct {
	Registry     Registry     `json:"registry"`
	Artifact     Artifact     `json:"artifact"`
	Capabilities []Capability `json:"enabled_capabilities"`
}

// GetImageRef returns the Docker image reference for this ScanRequest.
// Example: core.harbor.domain:443/library/nginx@sha256:3b00a364fb74...
//
// insecure is derived from the URL scheme because Harbor never populates
// Registry.Insecure: the Registry struct passed to the adapter is built with
// URL only (harbor/src/controller/scan/base_controller.go). trivy's adapter does
// the same (nonSSL = scheme == "http").
func (c ScanRequest) GetImageRef() (imageRef string, insecure bool, err error) {
	registryURL, err := url.Parse(c.Registry.URL)
	if err != nil {
		return "", false, fmt.Errorf("parsing registry URL: %w", err)
	}

	port := registryURL.Port()
	if port == "" && registryURL.Scheme == "http" {
		port = "80"
	}
	if port == "" && registryURL.Scheme == "https" {
		port = "443"
	}

	imageRef = fmt.Sprintf("%s:%s/%s@%s", registryURL.Hostname(), port, c.Artifact.Repository, c.Artifact.Digest)
	insecure = registryURL.Scheme == "http"
	return imageRef, insecure, nil
}

type ScanResponse struct {
	ID string `json:"id"`
}

// ScanReport is the SBOM report envelope returned to Harbor. sbom is the entire
// mikebom SPDX 2.3 document embedded verbatim as a JSON object (Harbor parses it
// into RawSBOMReport{sbom map[string]any}). It is stored pre-marshaled as
// json.RawMessage in the report envelope (see pkg/scan) to avoid re-marshaling
// the possibly multi-MB document per report poll.
type ScanReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Artifact    Artifact        `json:"artifact"`
	Scanner     Scanner         `json:"scanner"`
	MediaType   api.MediaType   `json:"media_type"`
	SBOM        json.RawMessage `json:"sbom"`
}

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	Type CapabilityType `json:"type"`
	// ConsumesMIMETypes / ProducesMIMETypes are plain strings (Harbor's own
	// ScannerCapability shape). Keeping produces loose lets the handler return a
	// 422 for a vulnerability capability instead of a 400 at JSON-unmarshal when
	// a non-SBOM produces MIME arrives (defense in depth, plan m1).
	ConsumesMIMETypes []string `json:"consumes_mime_types"`
	ProducesMIMETypes []string `json:"produces_mime_types"`

	// For /metadata
	AdditionalAttributes *CapabilityAttributes `json:"additional_attributes,omitempty"`

	// For /scan
	Parameters *CapabilityAttributes `json:"parameters,omitempty"`
}

type CapabilityAttributes struct {
	SBOMMediaTypes []api.MediaType `json:"sbom_media_types,omitempty"`
}
