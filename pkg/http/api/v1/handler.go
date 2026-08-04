// Package v1 implements the Harbor Scanner Adapter API v1 for the waybill
// (SBOM-only) adapter: /metadata, /scan, /scan/{id}/report, probes and metrics.
package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/lo"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
	"github.com/container-registry/waybill-harbor-adapter/pkg/queue"
)

const (
	pathVarScanRequestID = "scan_request_id"

	// propertyRegistryAuthType is advertised explicitly so Harbor sends Basic
	// robot credentials and Bearer becomes provably unreachable (plan D-2).
	propertyRegistryAuthType = "harbor.scanner-adapter/registry-authorization-type"

	// refreshAfter is the report poll hint. Harbor parses Refresh-After with
	// ParseInt(v,10,8), so it MUST be <= 127 (plan m4). 5 seconds.
	refreshAfter = "5"

	// The repository as it exists today. The rename to waybill-harbor-adapter is
	// pending; GitHub will redirect this URL once it lands, so the value Harbor
	// surfaces resolves either way.
	vcsURL = "https://github.com/container-registry/mikebom-harbor-adapter"
)

// ReadyFunc reports readiness (Redis reachable, waybill exec-able). 503 on error.
type ReadyFunc func(ctx context.Context) error

type requestHandler struct {
	info     etc.BuildInfo
	config   etc.Config
	scanner  harbor.Scanner
	enqueuer queue.Enqueuer
	store    persistence.Store
	ready    ReadyFunc
	api.BaseHandler
}

var decoder = schema.NewDecoder()

func NewAPIHandler(info etc.BuildInfo, config etc.Config, scanner harbor.Scanner, enqueuer queue.Enqueuer, store persistence.Store, ready ReadyFunc) http.Handler {
	h := &requestHandler{
		info:     info,
		config:   config,
		scanner:  scanner,
		enqueuer: enqueuer,
		store:    store,
		ready:    ready,
	}

	router := mux.NewRouter()
	router.Use(h.logRequest)

	apiV1 := router.PathPrefix("/api/v1").Subrouter()
	if config.API.APIKey != "" {
		apiV1.Use(h.requireAPIKey)
	}
	apiV1.Methods(http.MethodPost).Path("/scan").HandlerFunc(h.AcceptScanRequest)
	apiV1.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(h.GetScanReport)
	apiV1.Methods(http.MethodGet).Path("/metadata").HandlerFunc(h.GetMetadata)

	probe := router.PathPrefix("/probe").Subrouter()
	probe.Methods(http.MethodGet).Path("/healthy").HandlerFunc(h.GetHealthy)
	probe.Methods(http.MethodGet).Path("/ready").HandlerFunc(h.GetReady)

	if config.API.MetricsEnabled {
		router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())
	}

	return router
}

func (h *requestHandler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request",
			slog.String("method", r.Method),
			slog.String("uri", r.URL.RequestURI()),
		)
		next.ServeHTTP(w, r)
	})
}

func (h *requestHandler) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ScannerAdapter-API-Key") != h.config.API.APIKey {
			h.WriteJSONError(w, api.Error{HTTPCode: http.StatusUnauthorized, Message: "invalid api key"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	var scanRequest harbor.ScanRequest
	if err := json.NewDecoder(req.Body).Decode(&scanRequest); err != nil {
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("unmarshaling scan request: %s", err.Error()),
		})
		return
	}

	if validationError := h.validateScanRequest(scanRequest); validationError != nil {
		slog.Error("Invalid scan request", slog.String("err", validationError.Message))
		h.WriteJSONError(res, *validationError)
		return
	}

	// Empty enabled_capabilities: default to the single sbom capability. This
	// adapter has exactly one thing it can do (plan §2).
	if len(scanRequest.Capabilities) == 0 {
		scanRequest.Capabilities = []harbor.Capability{{
			Type:              harbor.CapabilityTypeSBOM,
			ProducesMIMETypes: []string{api.MimeTypeSecuritySBOMReport.String()},
			Parameters:        &harbor.CapabilityAttributes{SBOMMediaTypes: []api.MediaType{api.MediaTypeSPDX}},
		}}
	}

	scanJobID, err := h.enqueuer.Enqueue(req.Context(), scanRequest)
	if err != nil {
		slog.Error("Error while enqueuing scan job", slog.String("err", err.Error()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("enqueuing scan job: %s", err.Error()),
		})
		return
	}

	h.WriteJSON(res, harbor.ScanResponse{ID: scanJobID}, api.MimeTypeScanResponse, http.StatusAccepted)
}

func (h *requestHandler) validateScanRequest(req harbor.ScanRequest) *api.Error {
	if err := validateCapabilities(req.Capabilities); err != nil {
		return err
	}

	if req.Registry.URL == "" {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "missing registry.url"}
	}
	// Scheme and host are required, not just parseability: GetImageRef builds
	// the pull reference from them, so "registry.example.com" (no scheme) or
	// "ftp://..." was 202-accepted here and failed only after a worker took the
	// job — an error Harbor should have been handed synchronously as a 422.
	registryURL, err := url.ParseRequestURI(req.Registry.URL)
	if err != nil || registryURL.Host == "" || (registryURL.Scheme != "http" && registryURL.Scheme != "https") {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "invalid registry.url: expected an absolute http(s) URL"}
	}
	if req.Artifact.Repository == "" {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "missing artifact.repository"}
	}
	if req.Artifact.Digest == "" {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "missing artifact.digest"}
	}

	// The same parse the worker applies (plan D-2, docs/upstream-issues.md issue
	// 3): Bearer and malformed Basic are rejected at submit rather than being
	// 202-accepted and failing later inside the worker. Empty auth = anonymous
	// pull, allowed.
	if _, _, err := harbor.ParseBasicAuthorization(req.Registry.Authorization); err != nil {
		return &api.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message: fmt.Sprintf("invalid registry.authorization (%s); this adapter advertises Basic registry authorization — "+
				"a non-Basic or malformed authorization indicates a misconfigured scanner registration", err),
		}
	}

	return nil
}

func validateCapabilities(capabilities []harbor.Capability) *api.Error {
	for _, c := range capabilities {
		if len(c.ProducesMIMETypes) == 0 {
			return &api.Error{HTTPCode: http.StatusBadRequest, Message: `"enabled_capabilities.produces_mime_types" is missing`}
		}

		// Defense in depth: reject vulnerability capability explicitly. Harbor's
		// hasCapability is MIME-based so a vuln trigger against an sbom-only
		// registration never reaches here (plan m1), but a direct client might.
		if c.Type == harbor.CapabilityTypeVulnerability {
			return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "this adapter only supports sbom generation"}
		}
		if c.Type != harbor.CapabilityTypeSBOM {
			return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: fmt.Sprintf("unsupported scan type: %q", c.Type)}
		}

		// Every produces MIME must be one this adapter can serve. The enqueuer
		// skips unsupported ones defensively, so without this check a request
		// carrying only unsupported values was acknowledged and then failed at
		// enqueue as a 500 — a caller error, not a server one, and it deserves
		// the same synchronous 422 as every other contract violation.
		for _, produces := range c.ProducesMIMETypes {
			var m api.MIMEType
			if err := m.Parse(produces); err != nil {
				return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: fmt.Sprintf("unsupported produces mime type: %q", produces)}
			}
		}

		params := lo.FromPtr(c.Parameters)
		if len(params.SBOMMediaTypes) == 0 {
			return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "missing SBOM media type"}
		}
		for _, mediaType := range params.SBOMMediaTypes {
			if !slices.Contains(harbor.SupportedSBOMMediaTypes, mediaType) {
				return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: fmt.Sprintf("unsupported SBOM media type: %q", mediaType)}
			}
		}
	}
	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	scanJobID, ok := mux.Vars(req)[pathVarScanRequestID]
	if !ok {
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusBadRequest, Message: "missing scan request id"})
		return
	}
	reqLog := slog.With(slog.String("scan_job_id", scanJobID))

	var reportMIMEType api.MIMEType
	if err := reportMIMEType.Parse(req.Header.Get(api.HeaderAccept)); err != nil {
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusUnsupportedMediaType,
			Message:  fmt.Sprintf("unsupported media type: %q", req.Header.Get(api.HeaderAccept)),
		})
		return
	}

	var query harbor.ScanReportQuery
	if err := decoder.Decode(&query, req.URL.Query()); err != nil {
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusBadRequest, Message: fmt.Sprintf("query parameter error: %s", err)})
		return
	}
	if query.SBOMMediaType == "" {
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusBadRequest, Message: "missing SBOM media type"})
		return
	}

	scanJob, err := h.store.Get(req.Context(), job.ScanJobKey{
		ID:        scanJobID,
		MIMEType:  reportMIMEType,
		MediaType: query.SBOMMediaType,
	})
	if err != nil {
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusInternalServerError, Message: fmt.Sprintf("getting scan job: %v", err)})
		return
	}
	if scanJob == nil {
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusNotFound, Message: fmt.Sprintf("cannot find scan job: %v", scanJobID)})
		return
	}

	switch scanJob.Status {
	case job.Queued, job.Pending:
		reqLog.Debug("Scan job not finished yet")
		res.Header().Set("Location", req.URL.String())
		res.Header().Set(api.HeaderRefreshAfter, refreshAfter)
		res.WriteHeader(http.StatusFound)
	case job.Failed:
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusInternalServerError, Message: scanJob.Error})
	case job.Finished:
		// Stream the pre-marshaled envelope (gzip-capable). Do NOT re-marshal the
		// possibly multi-MB SPDX document per poll (Harbor client 5s timeout).
		h.WriteRawJSON(res, req, scanJob.Report, reportMIMEType, http.StatusOK)
	default:
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusInternalServerError, Message: fmt.Sprintf("unexpected status %v", scanJob.Status)})
	}
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, _ *http.Request) {
	properties := map[string]string{
		propertyRegistryAuthType: "Basic",

		"org.label-schema.version":    h.info.Version,
		"org.label-schema.build-date": h.info.Date,
		"org.label-schema.vcs-ref":    h.info.Commit,
		"org.label-schema.vcs":        vcsURL,

		"env.SCANNER_WAYBILL_TIMEOUT":    h.config.Waybill.Timeout.String(),
		"env.SCANNER_WAYBILL_ENRICHMENT": fmt.Sprintf("%t", h.config.Waybill.Enrichment),
	}

	metadata := &harbor.ScannerAdapterMetadata{
		Scanner: h.scanner,
		Capabilities: []harbor.Capability{
			{
				Type: harbor.CapabilityTypeSBOM,
				ConsumesMIMETypes: []string{
					api.MimeTypeDockerImageManifestV2.String(),
					api.MimeTypeOCIImageManifest.String(),
				},
				ProducesMIMETypes: []string{
					api.MimeTypeSecuritySBOMReport.String(),
				},
				AdditionalAttributes: &harbor.CapabilityAttributes{
					SBOMMediaTypes: []api.MediaType{api.MediaTypeSPDX},
				},
			},
		},
		Properties: properties,
	}
	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

func (h *requestHandler) GetHealthy(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) GetReady(res http.ResponseWriter, req *http.Request) {
	if h.ready != nil {
		if err := h.ready(req.Context()); err != nil {
			slog.Debug("Not ready", slog.String("err", err.Error()))
			res.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	res.WriteHeader(http.StatusOK)
}
