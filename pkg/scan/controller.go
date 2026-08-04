// Package scan orchestrates one SBOM scan job: hand waybill the artifact
// reference and the pull credentials, assemble the report envelope, and persist
// it. waybill pulls from the registry itself, so the adapter's only filesystem
// responsibility is the per-job workdir it gives waybill as HOME/TMPDIR and
// deletes afterwards. The SPDX document is stored pre-marshaled
// (json.RawMessage) so it is never re-marshaled on a report poll.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/harbor"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/imageprobe"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/metrics"
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

	// prober and maxImageSize are the pre-pull memory guard. A nil prober or a
	// non-positive limit disables it.
	prober       imageprobe.Prober
	maxImageSize int64
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

// NewControllerWithSizeCap is NewController plus the pre-pull memory guard. A
// nil prober or a non-positive maxImageSize leaves the guard off.
func NewControllerWithSizeCap(
	store persistence.Store, wrapper waybill.Wrapper, scanner harbor.Scanner, workDir string,
	prober imageprobe.Prober, maxImageSize int64,
) Controller {
	return &controller{
		store:        store,
		wrapper:      wrapper,
		scanner:      scanner,
		workDir:      workDir,
		clock:        systemClock{},
		prober:       prober,
		maxImageSize: maxImageSize,
	}
}

func (c *controller) Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error {
	metrics.ScansInFlight.Inc()
	// Wall-clock, not c.clock: the injectable clock is pinned in tests so a
	// difference taken from it would be a constant zero.
	started := time.Now()

	err := c.scan(ctx, scanJobKey, request)

	metrics.ScansInFlight.Dec()
	metrics.ObserveScan(err == nil, errorCategory(err), time.Since(started).Seconds())

	if err != nil {
		errMsg := err.Error()
		// A vanished record is a capacity symptom, not a scan failure, and there
		// is nothing left to write the Failed status to — attempting it would
		// only fail again with the same cause. Harbor is already polling a key
		// that 404s, which is how it learns the scan is gone.
		if errors.Is(err, persistence.ErrJobNotFound) {
			slog.Warn("Scan job record is gone; it outlived the scan job TTL while queued",
				slog.String("scan_job_id", scanJobKey.ID), slog.String("err", errMsg))
			return nil
		}
		slog.Error("Scan failed", slog.String("scan_job_id", scanJobKey.ID), slog.String("err", errMsg))
		// Detach from ctx: the per-job deadline may already have fired (that is
		// precisely how most failures arrive), and the Failed write must still land.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
		defer cancel()
		if uErr := c.store.UpdateStatus(writeCtx, scanJobKey, job.Failed, errMsg); uErr != nil {
			return xerrors.Errorf("updating scan job as failed: %w", uErr)
		}
	}
	return nil
}

// checkSize rejects an artifact too big to scan within the container's memory
// limit, before the pull allocates anything.
//
// A probe that cannot answer does NOT block the scan. The probe is a safety net
// reached over the same network and credentials as the pull, so making every
// scan depend on it would trade a rare OOM for a common outage; the pull that
// follows will fail on its own if the registry is genuinely unreachable. The
// gap is counted, because a silently unguarded scanner is the one thing worse
// than no guard.
func (c *controller) checkSize(ctx context.Context, target waybill.ScanTarget) error {
	if c.prober == nil || c.maxImageSize <= 0 {
		return nil
	}

	size, err := c.prober.CompressedSize(ctx, imageprobe.Target{
		Ref:      target.ImageRef,
		Username: target.Username,
		Password: target.Password,
		Insecure: target.Insecure,
	})
	if err != nil {
		metrics.ImageProbeFailuresTotal.Inc()
		slog.Warn("Pre-pull size check failed; scanning without the memory guard",
			slog.String("image_ref", target.ImageRef), slog.String("err", err.Error()))
		return nil
	}

	metrics.ImageCompressedBytes.Observe(float64(size))
	if size > c.maxImageSize {
		return &imageprobe.TooLargeError{Ref: target.ImageRef, Size: size, Limit: c.maxImageSize}
	}

	slog.Debug("Artifact size accepted",
		slog.String("image_ref", target.ImageRef),
		slog.Int64("compressed_bytes", size),
		slog.Int64("limit", c.maxImageSize))
	return nil
}

// errorCategory maps a scan failure onto the metrics category label. Failures
// raised by the adapter itself (nil request, workdir, store write) carry no
// waybill.Error; they get their own label rather than being folded into
// WaybillExec, which would blame the scanner for the adapter's bugs.
func errorCategory(err error) string {
	if err == nil {
		return metrics.CategoryNone
	}
	var wErr *waybill.Error
	if errors.As(err, &wErr) {
		return string(wErr.Category)
	}
	if errors.Is(err, persistence.ErrJobNotFound) {
		return metrics.CategoryExpired
	}
	var tooLarge *imageprobe.TooLargeError
	if errors.As(err, &tooLarge) {
		return metrics.CategoryImageTooLarge
	}
	return metrics.CategoryAdapter
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
		return xerrors.Errorf("updating scan job status: %w", err)
	}

	imageRef, insecure, err := req.GetImageRef()
	if err != nil {
		return err
	}

	target := waybill.ScanTarget{ImageRef: imageRef, Insecure: insecure}
	if err = applyAuth(&target, req.Registry.Authorization); err != nil {
		return err
	}

	if err = c.checkSize(ctx, target); err != nil {
		return err
	}

	jobDir, err := os.MkdirTemp(c.workDir, "scan-*")
	if err != nil {
		return xerrors.Errorf("creating job workdir: %w", err)
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

	// The terminal write runs detached from the job deadline: a scan that
	// completed just under the deadline must still be recorded as Finished, not
	// lost to an expired context (same window that strands a Failed write,
	// escalated blocker).
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
	defer cancel()
	if err = c.store.Finish(writeCtx, scanJobKey, envelope); err != nil {
		return xerrors.Errorf("saving scan report: %w", err)
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
		return nil, xerrors.Errorf("marshaling report envelope: %w", err)
	}
	return raw, nil
}

// applyAuth decodes the scan request authorization into the pull credentials.
// Empty header = anonymous pull (waybill falls through to anonymous when neither
// credential env var is set). The parse is shared with the handler's /scan
// validation (harbor.ParseBasicAuthorization), so a request that was 202-accepted
// cannot fail to parse here; this remains as defense-in-depth for payloads that
// reached the queue some other way.
func applyAuth(target *waybill.ScanTarget, authorization string) error {
	username, password, err := harbor.ParseBasicAuthorization(authorization)
	if err != nil {
		return xerrors.Errorf("%v", err)
	}
	target.Username = username
	target.Password = password
	return nil
}
