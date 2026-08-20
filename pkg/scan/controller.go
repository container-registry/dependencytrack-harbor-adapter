// Package scan orchestrates one scan job. The shape of that job is the point of
// this adapter, so it is worth stating plainly:
//
//  1. Look for an SBOM Harbor has already generated and attached to the image as
//     an OCI accessory. If one exists, that is roughly 40 KB off the wire and the
//     image is never pulled.
//  2. Otherwise generate one with syft, which costs a full image pull.
//  3. Either way, end up holding both an SPDX document (Harbor's deliverable)
//     and a CycloneDX one (Dependency-Track's only accepted input).
//  4. Return the SPDX to Harbor, upload the CycloneDX to Dependency-Track.
//
// Step 4's two halves have different consequences on failure. The SPDX is what
// Harbor asked for and is already in hand; the upload is a side effect on a
// third system. By default a failed upload does not discard a good SBOM. See
// etc.DTrack.FailScanOnUploadError.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/accessory"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/dtrack"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/harbor"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/imageprobe"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/metrics"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/syft"
)

// statusWriteTimeout bounds the terminal status/report writes. Those writes run
// on a context detached from the per-job deadline (queue.runJob) so a job that
// hit the deadline is still recorded as Failed, and a job that finished just
// under the deadline is still recorded as Finished. go-redis fails any command
// on an expired context, so reusing the job context here would leave the job
// stuck Pending until its TTL, and Harbor would 302-poll it for up to
// ScanJobTTL before 404ing.
const statusWriteTimeout = 10 * time.Second

// Clock is injectable so tests can pin generated_at.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Controller interface {
	Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error
}

// Options carries the collaborators that are optional at runtime, so the
// constructor does not grow a parameter per feature flag.
type Options struct {
	// Fetcher enables the accessory fast path. Nil disables it, and every scan
	// generates from the image.
	Fetcher accessory.Fetcher
	// Uploader enables the Dependency-Track upload. Nil disables it.
	Uploader dtrack.Client
	// Prober and MaxImageSize are the pre-pull memory guard. A nil prober or a
	// non-positive limit disables it.
	Prober       imageprobe.Prober
	MaxImageSize int64
	// FailOnUploadError promotes a failed Dependency-Track upload from a logged
	// warning to a failed scan.
	FailOnUploadError bool
	// ProjectTags are attached to every Dependency-Track project created here.
	ProjectTags []string
	// NestUnderHarborProject files each repository under a parent project named
	// after its Harbor project.
	NestUnderHarborProject bool
	// SkipTLSVerify is passed to the accessory fetcher's registry client.
	SkipTLSVerify bool
}

type controller struct {
	store   persistence.Store
	wrapper syft.Wrapper
	scanner harbor.Scanner
	workDir string
	clock   Clock
	opts    Options
}

func NewController(store persistence.Store, wrapper syft.Wrapper, scanner harbor.Scanner, workDir string, opts Options) Controller {
	return &controller{
		store:   store,
		wrapper: wrapper,
		scanner: scanner,
		workDir: workDir,
		clock:   systemClock{},
		opts:    opts,
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
		// is nothing left to write the Failed status to. Harbor is already
		// polling a key that 404s, which is how it learns the scan is gone.
		if errors.Is(err, persistence.ErrJobNotFound) {
			slog.Warn("Scan job record is gone; it outlived the scan job TTL while queued",
				slog.String("scan_job_id", scanJobKey.ID), slog.String("err", errMsg))
			return nil
		}
		slog.Error("Scan failed", slog.String("scan_job_id", scanJobKey.ID), slog.String("err", errMsg))
		// Detach from ctx: the per-job deadline may already have fired (that is
		// precisely how most failures arrive), and the Failed write must land.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
		defer cancel()
		if uErr := c.store.UpdateStatus(writeCtx, scanJobKey, job.Failed, errMsg); uErr != nil {
			return xerrors.Errorf("updating scan job as failed: %w", uErr)
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
		return xerrors.Errorf("updating scan job status: %w", err)
	}

	imageRef, insecure, err := req.GetImageRef()
	if err != nil {
		return err
	}

	target := syft.Target{Ref: imageRef, Insecure: insecure}
	if err = applyAuth(&target, req.Registry.Authorization); err != nil {
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

	docs, reused, err := c.resolveSBOM(ctx, target, jobDir)
	if err != nil {
		return err
	}

	// Upload before the report is stored. Harbor treats a stored report as the
	// end of the scan and stops polling, so anything done after it is invisible
	// to the operator watching the scan.
	if err = c.upload(ctx, req, docs.CycloneDX); err != nil {
		return err
	}

	envelope, err := c.buildEnvelope(req, docs.SPDX)
	if err != nil {
		return err
	}

	slog.Info("Scan finished",
		slog.String("scan_job_id", scanJobKey.ID),
		slog.String("image_ref", imageRef),
		slog.Bool("reused_harbor_sbom", reused))

	// The terminal write runs detached from the job deadline: a scan that
	// completed just under the deadline must still be recorded as Finished, not
	// lost to an expired context.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
	defer cancel()
	if err = c.store.Finish(writeCtx, scanJobKey, envelope); err != nil {
		return xerrors.Errorf("saving scan report: %w", err)
	}
	return nil
}

// resolveSBOM produces both documents, preferring one Harbor already generated.
// reused reports which path was taken, for the log line and the metric.
func (c *controller) resolveSBOM(ctx context.Context, target syft.Target, jobDir string) (docs syft.Documents, reused bool, err error) {
	if spdx, ok := c.fetchExisting(ctx, target); ok {
		cdx, convErr := c.wrapper.Convert(ctx, spdx, jobDir)
		if convErr == nil {
			metrics.SBOMReusedTotal.Inc()
			return syft.Documents{SPDX: spdx, CycloneDX: cdx}, true, nil
		}
		// Conversion of a document Harbor itself produced failing is worth a
		// warning, but not worth failing a scan that can still be completed by
		// generating from the image.
		slog.Warn("Converting the Harbor SBOM failed; generating instead",
			slog.String("image_ref", target.Ref), slog.String("err", convErr.Error()))
	}

	// Only the generation path pulls the image, so the size guard belongs here
	// rather than at the top of the scan.
	if err = c.checkSize(ctx, target); err != nil {
		return syft.Documents{}, false, err
	}

	metrics.SBOMGeneratedTotal.Inc()
	docs, err = c.wrapper.Generate(ctx, target, jobDir)
	return docs, false, err
}

// fetchExisting looks for a Harbor-generated SBOM accessory. Every failure here
// is non-fatal: the fast path is an optimization, and the caller falls back to
// generating one.
func (c *controller) fetchExisting(ctx context.Context, target syft.Target) (json.RawMessage, bool) {
	if c.opts.Fetcher == nil {
		return nil, false
	}

	spdx, err := c.opts.Fetcher.Fetch(ctx, accessory.Target{
		Ref:           target.Ref,
		Username:      target.Username,
		Password:      target.Password,
		Insecure:      target.Insecure,
		SkipTLSVerify: c.opts.SkipTLSVerify,
	})
	switch {
	case err == nil:
		return spdx, true
	case errors.Is(err, accessory.ErrNotFound):
		// The ordinary case for a project that never had SBOM generation on.
		slog.Debug("No Harbor SBOM accessory; generating", slog.String("image_ref", target.Ref))
	default:
		metrics.AccessoryFetchFailuresTotal.Inc()
		slog.Warn("Fetching the Harbor SBOM accessory failed; generating instead",
			slog.String("image_ref", target.Ref), slog.String("err", err.Error()))
	}
	return nil, false
}

// upload sends the CycloneDX document to Dependency-Track.
//
// The default on failure is to log and continue. The SBOM is Harbor's
// deliverable and it is already generated; throwing it away because a third
// system was briefly unreachable would make the adapter strictly less useful
// than one that never had the integration. Deployments where the feed is the
// whole point can invert that with FailOnUploadError.
func (c *controller) upload(ctx context.Context, req *harbor.ScanRequest, cdx json.RawMessage) error {
	if c.opts.Uploader == nil || len(cdx) == 0 {
		return nil
	}

	name, version, parent := projectIdentity(req, c.opts.NestUnderHarborProject)
	err := c.opts.Uploader.Upload(ctx, dtrack.UploadRequest{
		ProjectName:    name,
		ProjectVersion: version,
		ParentName:     parent,
		ProjectTags:    c.opts.ProjectTags,
		// Harbor addresses artifacts by digest and the scan request carries no
		// tag, so the newest thing this adapter has seen for a repository is the
		// best available answer to "latest".
		IsLatest:  true,
		CycloneDX: cdx,
	})
	if err == nil {
		metrics.BOMUploadsTotal.Inc()
		return nil
	}

	metrics.BOMUploadFailuresTotal.Inc()
	if c.opts.FailOnUploadError {
		return xerrors.Errorf("uploading BOM to Dependency-Track: %w", err)
	}
	slog.Error("Uploading the BOM to Dependency-Track failed; the SBOM is still returned to Harbor",
		slog.String("project", name), slog.String("err", err.Error()))
	return nil
}

// projectIdentity maps a Harbor artifact onto Dependency-Track's project model.
//
// Dependency-Track keys projects by name and version, and Harbor gives the
// adapter a repository and a digest and no tag. So the repository is the name
// and the digest is the version, which means one project version per image
// build. That is unbounded growth over time and is deliberate: it is the only
// identity Harbor actually supplies, and inventing a stable one from a mutable
// tag would silently overwrite the history of what was deployed.
func projectIdentity(req *harbor.ScanRequest, nest bool) (name, version, parent string) {
	name = req.Artifact.Repository
	version = req.Artifact.Digest
	if nest {
		// Harbor repositories are always "<project>/<path>", so the first
		// segment names the Harbor project.
		if project, _, found := strings.Cut(name, "/"); found {
			parent = project
		}
	}
	return name, version, parent
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
func (c *controller) checkSize(ctx context.Context, target syft.Target) error {
	if c.opts.Prober == nil || c.opts.MaxImageSize <= 0 {
		return nil
	}

	size, err := c.opts.Prober.CompressedSize(ctx, imageprobe.Target{
		Ref:      target.Ref,
		Username: target.Username,
		Password: target.Password,
		Insecure: target.Insecure,
	})
	if err != nil {
		metrics.ImageProbeFailuresTotal.Inc()
		slog.Warn("Pre-pull size check failed; scanning without the memory guard",
			slog.String("image_ref", target.Ref), slog.String("err", err.Error()))
		return nil
	}

	metrics.ImageCompressedBytes.Observe(float64(size))
	if size > c.opts.MaxImageSize {
		return &imageprobe.TooLargeError{Ref: target.Ref, Size: size, Limit: c.opts.MaxImageSize}
	}

	slog.Debug("Artifact size accepted",
		slog.String("image_ref", target.Ref),
		slog.Int64("compressed_bytes", size),
		slog.Int64("limit", c.opts.MaxImageSize))
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

// errorCategory maps a scan failure onto the metrics category label. Failures
// raised by the adapter itself carry no syft.Error; they get their own label
// rather than being folded into SyftExec, which would blame the scanner for the
// adapter's bugs.
func errorCategory(err error) string {
	if err == nil {
		return metrics.CategoryNone
	}
	var sErr *syft.Error
	if errors.As(err, &sErr) {
		return string(sErr.Category)
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

// applyAuth decodes the scan request authorization into the pull credentials.
// Empty header means an anonymous pull. The parse is shared with the handler's
// /scan validation (harbor.ParseBasicAuthorization), so a request that was
// 202-accepted cannot fail to parse here; this remains as defense-in-depth for
// payloads that reached the queue some other way.
func applyAuth(target *syft.Target, authorization string) error {
	username, password, err := harbor.ParseBasicAuthorization(authorization)
	if err != nil {
		return xerrors.Errorf("%v", err)
	}
	target.Username = username
	target.Password = password
	return nil
}
