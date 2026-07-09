// Package mikebom wraps the mikebom SBOM CLI as a subprocess. It runs mikebom
// against a local docker-save tarball (the adapter pulls the artifact itself,
// plan D-1) with a per-job workdir and a constructed environment allowlist.
//
// Egress control: mikebom's enrichment sources (deps.dev, ClearlyDefined)
// default ON and are gated on the --offline CLI flag, NOT the MIKEBOM_OFFLINE
// env var (root-caused in docs/spike-m1.md). The wrapper therefore passes
// --offline in argv as the real egress control and additionally sets
// MIKEBOM_OFFLINE=1 in the child env (belt and suspenders: the golang
// graph_resolver / package_db / binary-fingerprint paths read the env var).
package mikebom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/etc"
)

// exitCodeTimeout is mikebom's POSIX timeout(1) convention exit status when its
// own --timeout fires (cli-reference.md).
const exitCodeTimeout = 124

// reportFileName is the SBOM output file inside the per-job workdir.
const reportFileName = "report.spdx.json"

// vexFileName is the OpenVEX sidecar output. mikebom writes it only when advisory
// data is present, which never happens for an SBOM-only scan (M1 spike Task 4),
// so it is pinned and discarded. Kept as a harmless no-op per plan D-7.
const vexFileName = "out.vex.json"

// Wrapper is the mikebom subprocess boundary.
type Wrapper interface {
	// Version returns the mikebom CLI version (e.g. "0.1.0-alpha.55").
	Version(ctx context.Context) (string, error)
	// GenerateSBOM scans a docker-save tarball and returns the SPDX 2.3 document
	// as a JSON object (json.RawMessage). jobDir is the per-job workdir used for
	// output and as HOME/TMPDIR.
	GenerateSBOM(ctx context.Context, tarballPath, jobDir string) (json.RawMessage, error)
}

type wrapper struct {
	cfg etc.Mikebom
}

func NewWrapper(cfg etc.Mikebom) Wrapper {
	return &wrapper{cfg: cfg}
}

func (w *wrapper) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, w.cfg.Binary, "--version")
	cmd.Env = w.childEnv("")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("running mikebom --version: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	// Output form: "mikebom 0.1.0-alpha.55".
	out := strings.TrimSpace(stdout.String())
	return strings.TrimSpace(strings.TrimPrefix(out, "mikebom")), nil
}

func (w *wrapper) GenerateSBOM(ctx context.Context, tarballPath, jobDir string) (json.RawMessage, error) {
	reportPath := filepath.Join(jobDir, reportFileName)
	args := w.scanArgs(tarballPath, jobDir, reportPath)

	// Backstop context in case mikebom's own --timer wedges (plan §3.6). It must
	// outlive mikebom's own --timeout so exit 124 is observed rather than a
	// context kill masking it.
	runCtx := ctx
	var cancel context.CancelFunc
	if w.cfg.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, w.cfg.Timeout+30*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(runCtx, w.cfg.Binary, args...)
	cmd.Env = w.childEnv(jobDir)
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	slog.Debug("Executing mikebom",
		slog.String("binary", w.cfg.Binary),
		slog.String("args", strings.Join(args, " ")),
	)

	runErr := cmd.Run()
	if runErr != nil {
		return nil, w.classifyRunError(runErr, cmd, runCtx, tarballPath, stderr.String())
	}

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("reading mikebom output %s: %w", reportPath, err)
	}

	// Guard against truncated output and guarantee Harbor's RawSBOMReport
	// (SBOM map[string]any) can unmarshal it: the SPDX report must be a JSON
	// object.
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("mikebom output is not a JSON object: %w", err)
	}

	return json.RawMessage(raw), nil
}

// scanArgs builds the mikebom argv. Global flags (--offline, --timeout) precede
// the "sbom scan" subcommand; subcommand flags follow (cli-reference.md).
func (w *wrapper) scanArgs(tarballPath, jobDir, reportPath string) []string {
	var args []string

	// --offline is the real egress control (see package doc). Enrichment opt-in
	// drops it.
	if !w.cfg.Enrichment {
		args = append(args, "--offline")
	}
	if w.cfg.Timeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(int(w.cfg.Timeout.Seconds())))
	}

	args = append(args,
		"sbom", "scan",
		"--image", tarballPath,
		"--format", "spdx-2.3-json",
		"--output", "spdx-2.3-json="+reportPath,
		"--output", "openvex="+filepath.Join(jobDir, vexFileName),
	)

	if w.cfg.OCICacheSize > 0 {
		args = append(args, "--oci-cache-size", strconv.Itoa(w.cfg.OCICacheSize))
	} else {
		args = append(args, "--no-oci-cache")
	}

	if w.cfg.ImagePlatform != "" {
		args = append(args, "--image-platform", w.cfg.ImagePlatform)
	}

	args = append(args, w.cfg.ExtraArgs...)
	return args
}

func (w *wrapper) classifyRunError(runErr error, _ *exec.Cmd, runCtx context.Context, tarballPath, stderr string) error {
	// Check the context first: a backstop timeout kills mikebom via signal, which
	// surfaces as an ExitError with code -1. That must be classified as a timeout,
	// not a generic exec failure, so it is caught before the exit-code branch.
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.Canceled) {
		return &Error{
			Category: CategoryTimeout,
			Detail:   fmt.Sprintf("mikebom exceeded backstop timeout scanning %s", tarballPath),
		}
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		code := exitErr.ExitCode()
		if code == exitCodeTimeout {
			return &Error{
				Category: CategoryTimeout,
				Detail:   fmt.Sprintf("mikebom timed out after %s scanning %s", w.cfg.Timeout, tarballPath),
				ExitCode: code,
			}
		}
		return &Error{
			Category: CategoryExec,
			Detail:   fmt.Sprintf("mikebom exit %d: %s", code, tailStderr(stderr)),
			ExitCode: code,
		}
	}

	return &Error{
		Category: CategoryExec,
		Detail:   fmt.Sprintf("running mikebom: %v: %s", runErr, tailStderr(stderr)),
	}
}

// childEnv builds the subprocess environment as an explicit allowlist. It is
// NEVER os.Environ(): the adapter's own env carries secrets (SCANNER_REDIS_URL,
// SCANNER_API_AUTH_API_KEY, the persisted robot Basic header) that must not leak
// into mikebom. HOME/TMPDIR are pinned into the writable per-job workdir under a
// read-only root filesystem. MIKEBOM_OFFLINE=1 backs up the --offline flag.
func (w *wrapper) childEnv(jobDir string) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	if jobDir != "" {
		env = append(env, "HOME="+jobDir, "TMPDIR="+jobDir)
	}
	if !w.cfg.Enrichment {
		env = append(env, "MIKEBOM_OFFLINE=1")
	}
	return env
}

func tailStderr(s string) string {
	const max = 2048
	s = strings.TrimSpace(s)
	if len(s) > max {
		return "..." + s[len(s)-max:]
	}
	return s
}
