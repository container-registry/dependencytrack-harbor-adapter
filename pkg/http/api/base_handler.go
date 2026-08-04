package api

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/xerrors"
)

const (
	HeaderContentType     = "Content-Type"
	HeaderContentEncoding = "Content-Encoding"
	HeaderAccept          = "Accept"
	HeaderAcceptEncoding  = "Accept-Encoding"
	HeaderRefreshAfter    = "Refresh-After"
)

type (
	MimeTypeParams map[string]string
	MediaType      string
)

// Error holds the information about an error, including metadata about its JSON structure.
type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

var (
	MimeTypeVersion = map[string]string{"version": "1.0"}

	MimeTypeOCIImageManifest = MIMEType{
		Type:    "application",
		Subtype: "vnd.oci.image.manifest.v1+json",
	}
	MimeTypeDockerImageManifestV2 = MIMEType{
		Type:    "application",
		Subtype: "vnd.docker.distribution.manifest.v2+json",
	}
	MimeTypeScanResponse = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.scan.response+json",
		Params:  MimeTypeVersion,
	}
	// MimeTypeSecuritySBOMReport is the exact produces MIME type pinned by the
	// Harbor contract: "application/vnd.security.sbom.report+json; version=1.0".
	MimeTypeSecuritySBOMReport = MIMEType{
		Type:    "application",
		Subtype: "vnd.security.sbom.report+json",
		Params:  map[string]string{"version": "1.0"},
	}
	MimeTypeMetadata = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.metadata+json",
		Params:  MimeTypeVersion,
	}
	MimeTypeError = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.error",
		Params:  MimeTypeVersion,
	}

	// MediaTypeSPDX is the only SBOM media type this adapter supports. Harbor
	// hardcodes application/spdx+json (harbor/src/pkg/scan/sbom/sbom.go:49).
	MediaTypeSPDX MediaType = "application/spdx+json"
)

type MIMEType struct {
	Type    string
	Subtype string
	Params  MimeTypeParams
}

func (mt MIMEType) MarshalJSON() ([]byte, error) {
	return json.Marshal(mt.String())
}

func (mt *MIMEType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return mt.Parse(s)
}

func (mt *MIMEType) String() string {
	if mt.Type == "" || mt.Subtype == "" {
		return ""
	}
	s := fmt.Sprintf("%s/%s", mt.Type, mt.Subtype)
	if len(mt.Params) == 0 {
		return s
	}
	params := make([]string, 0, len(mt.Params))
	for k, v := range mt.Params {
		params = append(params, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%s; %s", s, strings.Join(params, ";"))
}

// Parse resolves the Accept header sent by Harbor for the report endpoint. This
// adapter produces only SBOM reports, so it accepts the SBOM report type (with
// or without the version parameter). Anything else is unsupported.
func (mt *MIMEType) Parse(value string) error {
	// mime.ParseMediaType rather than a string switch: the switch only matched
	// this adapter's own spelling, so a client sending the same type without the
	// space after ";" -- which RFC 9110 permits and other clients emit -- got a
	// 415 for a request it had every right to make.
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return xerrors.Errorf("unsupported mime type: %s: %w", value, err)
	}

	want := fmt.Sprintf("%s/%s", MimeTypeSecuritySBOMReport.Type, MimeTypeSecuritySBOMReport.Subtype)
	if mediaType != want {
		return xerrors.Errorf("unsupported mime type: %s", value)
	}
	// The version parameter is optional, but a version we do not produce is not
	// something to answer with a report anyway.
	if v, ok := params["version"]; ok && v != MimeTypeSecuritySBOMReport.Params["version"] {
		return xerrors.Errorf("unsupported mime type version: %s", value)
	}

	mt.Type = MimeTypeSecuritySBOMReport.Type
	mt.Subtype = MimeTypeSecuritySBOMReport.Subtype
	mt.Params = MimeTypeSecuritySBOMReport.Params
	return nil
}

func (mt *MIMEType) Equal(other MIMEType) bool {
	if mt.Type != other.Type || mt.Subtype != other.Subtype || len(mt.Params) != len(other.Params) {
		return false
	}
	for k, v := range mt.Params {
		if other.Params[k] != v {
			return false
		}
	}
	return true
}

type BaseHandler struct{}

func (h *BaseHandler) WriteJSON(res http.ResponseWriter, data any, mimeType MIMEType, statusCode int) {
	res.Header().Set(HeaderContentType, mimeType.String())
	res.WriteHeader(statusCode)

	if err := json.NewEncoder(res).Encode(data); err != nil {
		slog.Error("Error while writing JSON", slog.String("err", err.Error()))
		h.SendInternalServerError(res)
		return
	}
}

// WriteRawJSON writes a pre-marshaled JSON payload (json.RawMessage) with the
// given MIME type, gzip-encoding the body when the client accepts it. The SPDX
// envelope can be multi-MB (M1 spike: golang ~5.5 MB), so the report path must
// stream stored bytes rather than re-marshal per poll (Harbor's client has a 5s
// per-request timeout). gzip shrinks the body 5-8x (M1 spike measured -9; the
// default level is used here, trading a few percent of size for lower latency).
func (h *BaseHandler) WriteRawJSON(res http.ResponseWriter, req *http.Request, payload []byte, mimeType MIMEType, statusCode int) {
	res.Header().Set(HeaderContentType, mimeType.String())

	if clientAcceptsGzip(req) {
		res.Header().Set(HeaderContentEncoding, "gzip")
		res.WriteHeader(statusCode)
		gz := gzip.NewWriter(res)
		if _, err := gz.Write(payload); err != nil {
			slog.Error("Error while writing gzip body", slog.String("err", err.Error()))
		}
		if err := gz.Close(); err != nil {
			slog.Error("Error while closing gzip writer", slog.String("err", err.Error()))
		}
		return
	}

	res.WriteHeader(statusCode)
	if _, err := res.Write(payload); err != nil {
		slog.Error("Error while writing body", slog.String("err", err.Error()))
	}
}

// clientAcceptsGzip honors the q-values in Accept-Encoding. A substring match
// treated "gzip;q=0" -- the explicit way to refuse an encoding -- as acceptance,
// so a client that said it could not decompress got a compressed report.
func clientAcceptsGzip(req *http.Request) bool {
	if req == nil {
		return false
	}

	wildcard := false
	for _, directive := range strings.Split(req.Header.Get(HeaderAcceptEncoding), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(directive), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "gzip" && name != "*" {
			continue
		}

		acceptable := true
		if _, q, found := strings.Cut(strings.ToLower(params), "q="); found {
			if weight, err := strconv.ParseFloat(strings.TrimSpace(q), 64); err == nil {
				acceptable = weight > 0
			}
		}

		// An explicit "gzip" settles it either way; "*" only fills in when gzip
		// is not named at all.
		if name == "gzip" {
			return acceptable
		}
		wildcard = acceptable
	}
	return wildcard
}

func (h *BaseHandler) WriteJSONError(res http.ResponseWriter, err Error) {
	data := struct {
		Err Error `json:"error"`
	}{err}

	h.WriteJSON(res, data, MimeTypeError, err.HTTPCode)
}

func (h *BaseHandler) SendInternalServerError(res http.ResponseWriter) {
	http.Error(res, "Internal Server Error", http.StatusInternalServerError)
}
