// Package dtrack uploads a CycloneDX document to Dependency-Track.
//
// Dependency-Track's entire inventory intake is one endpoint, PUT /api/v1/bom.
// Everything else it knows it fetches itself: it mirrors NVD, OSV, GitHub
// Advisories and EPSS on its own schedule and re-analyzes the whole portfolio
// against them daily. That shapes this client in two ways.
//
// First, the upload carries components and nothing else. Vulnerabilities found
// by a scanner are deliberately not sent, even when the source document has
// them, because Dependency-Track does its own correlation and a scanner's
// findings would be a stale, redundant second opinion.
//
// Second, the upload is fire-and-forget. Dependency-Track queues the document
// and returns a token; the analysis that follows is asynchronous and, more to
// the point, never finishes, because it runs again every day. Waiting for a
// result would mean freezing a point-in-time answer out of a system whose value
// is that it keeps re-deciding. So this client confirms the document was
// accepted and stops there.
package dtrack

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// bomEndpoint is the CycloneDX intake. PUT rather than POST: POST is the
// multipart form variant, PUT takes a JSON body, and a JSON body is what this
// client already has in hand.
const bomEndpoint = "/api/v1/bom"

// maxErrorBody bounds how much of an error response is copied into a Go error.
// Dependency-Track answers a schema violation with an RFC 9457 problem document
// that can run long, and this text ends up in the Harbor scan job's failure
// message.
const maxErrorBody = 4096

// missingParentMarker identifies the one 404 that is recoverable.
//
// autoCreate creates the project being uploaded but NOT its parent, and
// Dependency-Track rejects the whole upload when parentName names a project that
// does not exist. Creating the parent needs PORTFOLIO_MANAGEMENT_CREATE, which is
// more than an upload-only key should carry, so the recovery is to drop the
// nesting rather than to widen the key. Verified against Dependency-Track 5.0.4:
// PUT /api/v1/project with an upload-scoped key is 403, while the same upload
// without parentName is 200.
const missingParentMarker = "parent project could not be found"

// UploadRequest is one BOM upload.
type UploadRequest struct {
	// ProjectName identifies the project in Dependency-Track. Projects are keyed
	// by name and version, not by digest.
	ProjectName string
	// ProjectVersion is the second half of that key.
	ProjectVersion string
	// ProjectTags are attached on creation. Used to mark provenance so a
	// Dependency-Track operator can tell adapter-created projects from ones a
	// build pipeline pushed.
	ProjectTags []string
	// IsLatest marks this version as the latest for the project. Harbor's own
	// notion of "latest" is a mutable tag, so the caller decides.
	IsLatest bool
	// ParentName optionally nests the project under a parent, which is how a
	// Harbor project maps onto a Dependency-Track collection.
	ParentName string
	// CycloneDX is the document itself.
	CycloneDX json.RawMessage
}

// bomSubmitRequest is Dependency-Track's PUT /api/v1/bom body. The BOM travels
// base64-encoded inside a JSON field, which is Dependency-Track's design, not a
// choice made here.
type bomSubmitRequest struct {
	ProjectName    string   `json:"projectName"`
	ProjectVersion string   `json:"projectVersion"`
	ProjectTags    []string `json:"projectTags,omitempty"`
	ParentName     string   `json:"parentName,omitempty"`
	AutoCreate     bool     `json:"autoCreate"`
	IsLatest       bool     `json:"isLatest,omitempty"`
	BOM            string   `json:"bom"`
}

// uploadResponse carries the processing token. Kept only for the log line: the
// client does not poll it, for the reason in the package comment.
type uploadResponse struct {
	Token string `json:"token"`
}

// Client uploads BOMs to Dependency-Track.
type Client interface {
	// Upload submits a CycloneDX document, creating the project if needed.
	Upload(ctx context.Context, req UploadRequest) error
	// Ping reports whether Dependency-Track is reachable and the API key works.
	Ping(ctx context.Context) error
}

type client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// Config is the Dependency-Track connection.
type Config struct {
	// BaseURL is the API server root, e.g. https://dependencytrack.example.com.
	BaseURL string
	// APIKey is a team API key holding BOM_UPLOAD, plus PROJECT_CREATION_UPLOAD
	// or PORTFOLIO_MANAGEMENT_CREATE for autoCreate to work.
	APIKey string
	// Timeout bounds a single upload.
	Timeout time.Duration
	// SkipTLSVerify disables certificate verification. Dev and CI only.
	SkipTLSVerify bool
}

func NewClient(cfg Config) Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, dev/CI only
	}
	return &client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  cfg.APIKey,
		http:    &http.Client{Timeout: cfg.Timeout, Transport: transport},
	}
}

func (c *client) Upload(ctx context.Context, req UploadRequest) error {
	token, err := c.submit(ctx, req)

	// Retry unparented rather than lose the BOM. Nesting is presentation; the
	// inventory is the point.
	if err != nil && req.ParentName != "" && strings.Contains(err.Error(), missingParentMarker) {
		slog.Warn("Dependency-Track has no such parent project; uploading unnested. "+
			"Create it there, or set SCANNER_DTRACK_NEST_UNDER_HARBOR_PROJECT=false to stop trying.",
			slog.String("parent", req.ParentName),
			slog.String("project", req.ProjectName))
		req.ParentName = ""
		token, err = c.submit(ctx, req)
	}
	if err != nil {
		return err
	}

	slog.Info("Uploaded BOM to Dependency-Track",
		slog.String("project", req.ProjectName),
		slog.String("version", req.ProjectVersion),
		slog.String("token", token))
	return nil
}

// submit is one PUT /api/v1/bom, returning the processing token.
func (c *client) submit(ctx context.Context, req UploadRequest) (string, error) {
	body, err := json.Marshal(bomSubmitRequest{
		ProjectName:    req.ProjectName,
		ProjectVersion: req.ProjectVersion,
		ProjectTags:    req.ProjectTags,
		ParentName:     req.ParentName,
		AutoCreate:     true,
		IsLatest:       req.IsLatest,
		BOM:            base64.StdEncoding.EncodeToString(req.CycloneDX),
	})
	if err != nil {
		return "", fmt.Errorf("marshaling BOM upload: %w", err)
	}

	resp, err := c.do(ctx, http.MethodPut, bomEndpoint, body)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkStatus(resp); err != nil {
		return "", err
	}

	var parsed uploadResponse
	// A missing or unparseable token is not a failure: the upload was accepted,
	// and the token is only ever logged.
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBody)).Decode(&parsed)
	return parsed.Token, nil
}

func (c *client) Ping(ctx context.Context) error {
	// /api/version is unauthenticated, which would make it a liveness check
	// only. This one requires a valid key, so a bad or unprivileged API key
	// fails readiness at startup instead of on the first scan.
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/team/self", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return checkStatus(resp)
}

func (c *client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("building Dependency-Track request: %w", err)
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Dependency-Track %s: %w", path, err)
	}
	return resp, nil
}

func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	return fmt.Errorf("Dependency-Track returned %s: %s", resp.Status, strings.TrimSpace(string(detail)))
}
