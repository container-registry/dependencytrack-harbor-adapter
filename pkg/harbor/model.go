// Package harbor holds the Harbor Scanner Adapter API v1 domain models used by
// this adapter. It is ported from harbor-scanner-trivy with all vulnerability
// types stripped: waybill generates SBOMs only, so the adapter advertises a
// single "sbom" capability.
package harbor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
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

	// Hostname() strips the brackets from an IPv6 literal, and "::1:443/repo"
	// is not a parseable reference. Put them back when the host is IPv6.
	host := registryURL.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	imageRef = fmt.Sprintf("%s:%s/%s@%s", host, port, c.Artifact.Repository, c.Artifact.Digest)
	insecure = registryURL.Scheme == "http"
	return imageRef, insecure, nil
}

// ParseBasicAuthorization decodes a "Basic <base64>" authorization header value
// into a username/password pair (split on the first ':' so robot secrets
// containing ':' survive). It is shared by the /scan validation and the scan
// controller so a credential the handler 202-accepts can never fail to parse in
// the worker. Empty input means anonymous. Any non-Basic scheme is an error:
// this adapter advertises Basic, and waybill's credential chain takes only a
// username/password pair (docs/upstream-issues.md issue 3).
func ParseBasicAuthorization(authorization string) (username, password string, err error) {
	if authorization == "" {
		return "", "", nil
	}

	scheme, value, ok := strings.Cut(authorization, " ")
	if !ok {
		return "", "", fmt.Errorf("parsing authorization: expected \"<scheme> <credentials>\"")
	}

	// RFC 9110 makes the scheme case-insensitive. Matching it exactly rejected
	// "basic"/"BASIC" as an unrecognized scheme.
	switch {
	case strings.EqualFold(scheme, "Basic"):
		creds, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", "", fmt.Errorf("decoding basic authorization: %v", err)
		}
		user, pass, ok := strings.Cut(string(creds), ":")
		if !ok {
			// Without the separator this is not a credential pair. Accepting it
			// queued a scan that failed later at registry auth, or silently
			// became an anonymous pull when the payload was empty.
			return "", "", fmt.Errorf("decoding basic authorization: expected \"username:password\"")
		}
		return user, pass, nil
	case strings.EqualFold(scheme, "Bearer"):
		return "", "", fmt.Errorf("bearer authorization is not supported; this adapter advertises Basic")
	default:
		return "", "", fmt.Errorf("unrecognized authorization scheme: %s", scheme)
	}
}

type ScanResponse struct {
	ID string `json:"id"`
}

// ScanReport is the SBOM report envelope returned to Harbor. sbom is the entire
// waybill SPDX 2.3 document embedded verbatim as a JSON object (Harbor parses it
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
