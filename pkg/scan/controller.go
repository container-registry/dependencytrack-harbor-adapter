// Package scan orchestrates one SBOM scan job: hand waybill the artifact
// reference and the pull credentials, assemble the report envelope, and persist
// it. waybill pulls from the registry itself, so the adapter's only filesystem
// responsibility is the per-job workdir it gives waybill as HOME/TMPDIR and
// deletes afterwards. The SPDX document is stored pre-marshaled
// (json.RawMessage) so it is never re-marshaled on a report poll.
package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
	"github.com/container-registry/waybill-harbor-adapter/pkg/waybill"
)

// statusWriteTimeout bounds the terminal status/report writes. Those writes run on
// a context detached from the per-job deadline (queue.runJob) so a job that hit the
// deadline is still recorded as Failed, and a job that finished just under the
// deadline is still recorded as Finished. go-redis fails any command on an expired
// context, so reusing the job context here would leave the job stuck Pending until
// its TTL, and Harbor would 302-poll it for up to ScanJobTTL before 404ing.
const statusWriteTimeout = 10 * time.Second

// Clock is injectable so tests can pin generated_at.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Controller interface {
	Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error
}

type controller struct {
	store   persistence.Store
	wrapper waybill.Wrapper
	scanner harbor.Scanner
	workDir string
	clock   Clock
}

func NewController(store persistence.Store, wrapper waybill.Wrapper, scanner harbor.Scanner, workDir string) Controller {
	return &controller{
		store:   store,
		wrapper: wrapper,
		scanner: scanner,
		workDir: workDir,
		clock:   systemClock{},
	}
}

func (c *controller) Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error {
	if err := c.scan(ctx, scanJobKey, request); err != nil {
		errMsg := err.Error()
		slog.Error("Scan failed", slog.String("scan_job_id", scanJobKey.ID), slog.String("err", errMsg))
		// Detach from ctx: the per-job deadline may already have fired (that is
		// precisely how most failures arrive), and the Failed write must still land.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
		defer cancel()
		if uErr := c.store.UpdateStatus(writeCtx, scanJobKey, job.Failed, errMsg); uErr != nil {
			return xerrors.Errorf("updating scan job as failed: %v", uErr)
		}
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobKey job.ScanJobKey, req *harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during scan: %v", r)
		}
	}()

	if req == nil {
		return xerrors.New("nil scan request")
	}

	if err = c.store.UpdateStatus(ctx, scanJobKey, job.Pending); err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	imageRef, insecure, err := req.GetImageRef()
	if err != nil {
		return err
	}

	target := waybill.ScanTarget{ImageRef: imageRef, Insecure: insecure}
	if err = applyAuth(&target, req.Registry.Authorization); err != nil {
		return err
	}

	jobDir, err := os.MkdirTemp(c.workDir, "scan-*")
	if err != nil {
		return xerrors.Errorf("creating job workdir: %v", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(jobDir); rmErr != nil {
			slog.Warn("Failed to remove job workdir", slog.String("path", jobDir), slog.String("err", rmErr.Error()))
		}
	}()

	sbom, err := c.wrapper.GenerateSBOM(ctx, target, jobDir)
	if err != nil {
		return err
	}

	envelope, err := c.buildEnvelope(req, sbom)
	if err != nil {
		return err
	}

	// Terminal writes run detached from the job deadline: a scan that completed
	// just under the deadline must still be recorded as Finished, not lost to an
	// expired context (same window that strands a Failed write, escalated blocker).
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
	defer cancel()
	if err = c.store.UpdateReport(writeCtx, scanJobKey, envelope); err != nil {
		return xerrors.Errorf("saving scan report: %v", err)
	}
	if err = c.store.UpdateStatus(writeCtx, scanJobKey, job.Finished); err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}
	return nil
}

func (c *controller) buildEnvelope(req *harbor.ScanRequest, sbom json.RawMessage) (json.RawMessage, error) {
	report := harbor.ScanReport{
		GeneratedAt: c.clock.Now(),
		Artifact:    req.Artifact,
		Scanner:     c.scanner,
		MediaType:   api.MediaTypeSPDX,
		SBOM:        sbom,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, xerrors.Errorf("marshaling report envelope: %v", err)
	}
	return raw, nil
}

// applyAuth decodes the scan request authorization into the pull credentials.
// Empty header = anonymous pull (waybill falls through to anonymous when neither
// credential env var is set). Basic = decoded username/password (split on the
// first ':' so robot secrets containing ':' survive). Bearer is rejected as
// defense-in-depth; the handler already 422s it (plan D-2). Bearer stays rejected
// after the move to waybill's native pull: waybill's credential chain still takes
// only username/password and performs its own token exchange, so a pre-minted
// Bearer token has nowhere to go (docs/upstream-issues.md issue 3).
func applyAuth(target *waybill.ScanTarget, authorization string) error {
	if authorization == "" {
		return nil
	}

	scheme, value, ok := strings.Cut(authorization, " ")
	if !ok {
		return xerrors.Errorf("parsing authorization: expected \"<scheme> <credentials>\"")
	}

	switch scheme {
	case "Basic":
		creds, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return xerrors.Errorf("decoding basic authorization: %v", err)
		}
		username, password, _ := strings.Cut(string(creds), ":")
		target.Username = username
		target.Password = password
		return nil
	case "Bearer":
		return xerrors.Errorf("bearer authorization is not supported; this adapter advertises Basic")
	default:
		return xerrors.Errorf("unrecognized authorization scheme: %s", scheme)
	}
}
