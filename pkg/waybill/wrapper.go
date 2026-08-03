// Package waybill wraps the waybill SBOM CLI as a subprocess. waybill pulls the
// artifact from the Harbor-managed registry itself (`--image-src remote`) and
// scans it in one process; the adapter only supplies the reference, the
// credentials, and the registry transport configuration.
//
// Transport: waybill milestone 182 added --insecure-registry (plain HTTP),
// --registry-ca-cert (private CA bundle) and --insecure-tls-skip-verify. Before
// m182 its OCI client hardcoded https:// and trusted webpki roots only, which is
// why earlier revisions of this adapter pulled the artifact itself with
// go-containerregistry and handed waybill a docker-save tarball. That workaround
// is gone; see docs/upstream-issues.md.
//
// Credentials: waybill resolves registry credentials from
// WAYBILL_REGISTRY_<HOST>_USERNAME/_PASSWORD (per-registry) before falling back
// to WAYBILL_REGISTRY_USERNAME/_PASSWORD (generic), then to a Docker config.
// Harbor hands the adapter a Basic authorization per scan, so the wrapper passes
// it through the environment rather than argv: argv is world-readable via /proc.
//
// Egress control: waybill's enrichment sources (deps.dev, ClearlyDefined) default
// ON and are gated on the --offline CLI flag, NOT the WAYBILL_OFFLINE env var
// (root-caused in docs/spike-m1.md). The wrapper therefore passes --offline in
// argv as the real egress control and additionally sets WAYBILL_OFFLINE=1 in the
// child env (belt and suspenders: the golang graph_resolver / package_db /
// binary-fingerprint paths read the env var). --offline gates enrichment only; it
// does not disable the registry pull the scan target depends on.
package waybill

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

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
)

// exitCodeTimeout is waybill's POSIX timeout(1) convention exit status when its
// own --timeout fires (cli-reference.md).
const exitCodeTimeout = 124

// reportFileName is the SBOM output file inside the per-job workdir.
const reportFileName = "report.spdx.json"

// vexFileName is the OpenVEX sidecar output. waybill writes it only when advisory
// data is present, which never happens for an SBOM-only scan (M1 spike Task 4),
// so it is pinned and discarded. Kept as a harmless no-op per plan D-7.
const vexFileName = "out.vex.json"

// ScanTarget is the artifact waybill must pull and scan, plus the credentials for
// the pull. Empty Username and Password means an anonymous pull.
type ScanTarget struct {
	// ImageRef is the fully-qualified reference Harbor asked for, always
	// host:port/repository@digest (harbor.ScanRequest.GetImageRef).
	ImageRef string
	Username string
	Password string
	// Insecure is true when Harbor's registry.url scheme is http, which makes
	// waybill pull from this registry over plain HTTP.
	Insecure bool
}

// Registry returns the user-facing registry name embedded in ImageRef, i.e.
// everything before the first '/'. That is exactly the string waybill matches
// --insecure-registry against and derives the per-registry credential env var
// from, so deriving it here (rather than passing it in separately) keeps the
// adapter and waybill from disagreeing about the target host.
func (t ScanTarget) Registry() string {
	host, _, found := strings.Cut(t.ImageRef, "/")
	if !found {
		return ""
	}
	return host
}

// Wrapper is the waybill subprocess boundary.
type Wrapper interface {
	// Version returns the waybill CLI version (e.g. "0.1.0-alpha.69").
	Version(ctx context.Context) (string, error)
	// GenerateSBOM pulls and scans target, returning the SPDX 2.3 document as a
	// JSON object (json.RawMessage). jobDir is the per-job workdir used for
	// output and as HOME/TMPDIR.
	GenerateSBOM(ctx context.Context, target ScanTarget, jobDir string) (json.RawMessage, error)
}

type wrapper struct {
	cfg etc.Waybill
}

func NewWrapper(cfg etc.Waybill) Wrapper {
	return &wrapper{cfg: cfg}
}

func (w *wrapper) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, w.cfg.Binary, "--version")
	cmd.Env = w.childEnv("", ScanTarget{})
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("running waybill --version: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	// Output form: "waybill 0.1.0-alpha.69".
	out := strings.TrimSpace(stdout.String())
	return strings.TrimSpace(strings.TrimPrefix(out, "waybill")), nil
}

func (w *wrapper) GenerateSBOM(ctx context.Context, target ScanTarget, jobDir string) (json.RawMessage, error) {
	if target.ImageRef == "" {
		return nil, &Error{Category: CategoryExec, Detail: "empty image reference"}
	}
	reportPath := filepath.Join(jobDir, reportFileName)
	args := w.scanArgs(target, jobDir, reportPath)

	// Backstop context in case waybill's own --timeout wedges (plan §3.6). It must
	// outlive waybill's own --timeout so exit 124 is observed rather than a
	// context kill masking it.
	runCtx := ctx
	var cancel context.CancelFunc
	if w.cfg.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, w.cfg.Timeout+30*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(runCtx, w.cfg.Binary, args...)
	cmd.Env = w.childEnv(jobDir, target)
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	slog.Debug("Executing waybill",
		slog.String("binary", w.cfg.Binary),
		slog.String("args", strings.Join(args, " ")),
	)

	runErr := cmd.Run()
	if runErr != nil {
		return nil, w.classifyRunError(runErr, runCtx, target.ImageRef, stderr.String())
	}

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("reading waybill output %s: %w", reportPath, err)
	}

	// Guard against truncated output and guarantee Harbor's RawSBOMReport
	// (SBOM map[string]any) can unmarshal it: the SPDX report must be a JSON
	// object.
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("waybill output is not a JSON object: %w", err)
	}

	return json.RawMessage(raw), nil
}

// scanArgs builds the waybill argv. Global flags (--offline, --timeout) precede
// the "sbom scan" subcommand; subcommand flags follow (cli-reference.md).
//
// Credentials never appear here: they go through the environment (childEnv), as
// argv is readable by any process that can stat /proc/<pid>/cmdline.
func (w *wrapper) scanArgs(target ScanTarget, jobDir, reportPath string) []string {
	var args []string

	// --offline is the real egress control (see package doc). Enrichment opt-in
	// drops it.
	if !w.cfg.Enrichment {
		args = append(args, "--offline")
	}
	if w.cfg.Timeout > 0 {
		// waybill's --timeout is whole seconds, and 0 means "no limit" to it. A
		// configured sub-second timeout truncating to 0 would silently remove the
		// limit rather than tighten it, so clamp up.
		seconds := max(int(w.cfg.Timeout.Seconds()), 1)
		args = append(args, "--timeout", strconv.Itoa(seconds))
	}

	args = append(args,
		"sbom", "scan",
		"--image", target.ImageRef,
		// Pinned, never defaulted: waybill's default source order is
		// docker,podman,remote, which would probe a container runtime the
		// adapter image deliberately does not have.
		"--image-src", "remote",
		"--format", "spdx-2.3-json",
		"--output", "spdx-2.3-json="+reportPath,
		"--output", "openvex="+filepath.Join(jobDir, vexFileName),
	)

	if target.Insecure {
		if reg := target.Registry(); reg != "" {
			args = append(args, "--insecure-registry", reg)
		}
	}
	for _, ca := range w.cfg.RegistryCACerts {
		args = append(args, "--registry-ca-cert", ca)
	}
	if w.cfg.InsecureSkipVerify {
		args = append(args, "--insecure-tls-skip-verify")
	}

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

func (w *wrapper) classifyRunError(runErr error, runCtx context.Context, imageRef, stderr string) error {
	// Check the context first: a backstop timeout kills waybill via signal, which
	// surfaces as an ExitError with code -1. That must be classified as a timeout,
	// not a generic exec failure, so it is caught before the exit-code branch.
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.Canceled) {
		return &Error{
			Category: CategoryTimeout,
			Detail:   fmt.Sprintf("waybill exceeded backstop timeout scanning %s", imageRef),
		}
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		code := exitErr.ExitCode()
		if code == exitCodeTimeout {
			return &Error{
				Category: CategoryTimeout,
				Detail:   fmt.Sprintf("waybill timed out after %s scanning %s", w.cfg.Timeout, imageRef),
				ExitCode: code,
			}
		}
		return &Error{
			Category: classifyStderr(stderr),
			Detail:   fmt.Sprintf("waybill exit %d scanning %s: %s", code, imageRef, tailStderr(stderr)),
			ExitCode: code,
		}
	}

	return &Error{
		Category: CategoryExec,
		Detail:   fmt.Sprintf("running waybill: %v: %s", runErr, tailStderr(stderr)),
	}
}

// classifyStderr separates a registry-pull failure from a scan failure. The pull
// now happens inside the waybill subprocess, so its stderr is the only signal the
// adapter has; naming "the registry rejected us" rather than a bare exit code is
// what makes a misconfigured scanner registration diagnosable from Harbor's UI.
// The matched substrings are waybill's own m182 error messages (registry.rs).
func classifyStderr(stderr string) ErrorCategory {
	switch {
	case strings.Contains(stderr, "no credentials are configured"),
		strings.Contains(stderr, "auth challenge"),
		strings.Contains(stderr, "registry returned 401"),
		strings.Contains(stderr, "registry returned 403"):
		return CategoryPullAuth
	case strings.Contains(stderr, "TLS handshake failed"),
		strings.Contains(stderr, "TLS certificate chain validation failed"),
		strings.Contains(stderr, "--insecure-registry"),
		strings.Contains(stderr, "--registry-ca-cert"):
		return CategoryPullTransport
	case strings.Contains(stderr, "pulling OCI image"),
		strings.Contains(stderr, "registry returned"):
		return CategoryPull
	default:
		return CategoryExec
	}
}

// childEnv builds the subprocess environment as an explicit allowlist. It is
// NEVER os.Environ(): the adapter's own env carries secrets (SCANNER_REDIS_URL,
// SCANNER_API_AUTH_API_KEY) that must not leak into waybill. HOME/TMPDIR are
// pinned into the writable per-job workdir under a read-only root filesystem,
// which also confines waybill's OCI blob cache and its layer-extraction scratch
// to a directory the controller deletes when the job ends. WAYBILL_OFFLINE=1
// backs up the --offline flag.
func (w *wrapper) childEnv(jobDir string, target ScanTarget) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	if jobDir != "" {
		env = append(env, "HOME="+jobDir, "TMPDIR="+jobDir)
	}
	if !w.cfg.Enrichment {
		env = append(env, "WAYBILL_OFFLINE=1")
	}
	if target.Username != "" || target.Password != "" {
		// Both forms are set on purpose. The per-registry pair is what waybill
		// consults first and is scoped to the exact host in the reference; the
		// generic pair is the fallback that keeps auth working if waybill's key
		// normalization ever diverges from registryEnvKey. Setting both costs
		// nothing in blast radius: one subprocess pulls one image from one
		// registry, so there is no second host the generic pair could reach.
		if key := registryEnvKey(target.Registry()); key != "" {
			env = append(env,
				"WAYBILL_REGISTRY_"+key+"_USERNAME="+target.Username,
				"WAYBILL_REGISTRY_"+key+"_PASSWORD="+target.Password,
			)
		}
		env = append(env,
			"WAYBILL_REGISTRY_USERNAME="+target.Username,
			"WAYBILL_REGISTRY_PASSWORD="+target.Password,
		)
	}
	return env
}

// registryEnvKey mirrors waybill's per-registry credential env-var key derivation
// (waybill-cli/src/scan_fs/oci_pull/auth.rs: normalize_registry_key, then
// uppercase with every non-alphanumeric byte replaced by '_'). The port is part
// of the key: core:8080 becomes CORE_8080.
func registryEnvKey(registry string) string {
	r := strings.ToLower(strings.TrimSpace(registry))
	for _, prefix := range []string{"https://", "http://"} {
		if stripped, ok := strings.CutPrefix(r, prefix); ok {
			r = stripped
			break
		}
	}
	if i := strings.Index(r, "/"); i >= 0 {
		r = r[:i]
	}
	if r == "index.docker.io" {
		r = "docker.io"
	}
	if r == "" {
		return ""
	}
	var b strings.Builder
	for _, c := range []byte(strings.ToUpper(r)) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func tailStderr(s string) string {
	const max = 2048
	s = strings.TrimSpace(s)
	if len(s) > max {
		return "..." + s[len(s)-max:]
	}
	return s
}
