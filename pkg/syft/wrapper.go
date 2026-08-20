// Package syft wraps the syft CLI as a subprocess. It covers the two jobs this
// adapter needs from an SBOM tool:
//
//   - Generate: pull an image from the Harbor-managed registry and write both an
//     SPDX 2.3 document (what Harbor stores) and a CycloneDX 1.6 document (what
//     Dependency-Track ingests) from a single scan. Two formats out of one pull
//     is the whole reason syft is the generator here rather than a converter
//     bolted onto something else.
//
//   - Convert: turn an SPDX document Harbor already generated into CycloneDX
//     1.6, for the accessory fast path where no pull happens at all.
//
// Why the CycloneDX version is pinned to 1.6 and not left to default:
// Dependency-Track validates every uploaded BOM against the CycloneDX schemas
// bundled in cyclonedx-core-java, and 5.0.4 ships bom-1.0 through bom-1.6 only.
// A 1.7 document, which several current SBOM tools emit by default, has no
// schema to validate against and is rejected. The pin is a compatibility
// contract, not a preference.
//
// Credentials reach syft through the environment (SYFT_REGISTRY_AUTH_*) and
// never through argv, because argv is readable by anything that can stat
// /proc/<pid>/cmdline.
package syft

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
	"strings"
	"time"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
)

const (
	// spdxFormat is what Harbor stores. Harbor core only ever asks a scanner for
	// application/spdx+json, so this is not configurable.
	spdxFormat = "spdx-json@2.3"

	// cycloneDXFormat is what Dependency-Track ingests. See the package comment
	// for why the version is pinned.
	cycloneDXFormat = "cyclonedx-json@1.6"

	spdxFileName      = "sbom.spdx.json"
	cycloneDXFileName = "sbom.cdx.json"
)

// Documents is one artifact described in both formats, pre-marshaled so neither
// is re-encoded on the way to Harbor or Dependency-Track.
type Documents struct {
	// SPDX is the SPDX 2.3 document returned to Harbor.
	SPDX json.RawMessage
	// CycloneDX is the CycloneDX 1.6 document uploaded to Dependency-Track.
	CycloneDX json.RawMessage
}

// Target is the artifact to scan plus the credentials for the pull. Empty
// Username and Password means an anonymous pull.
type Target struct {
	// Ref is the fully-qualified reference Harbor asked for, always
	// host:port/repository@digest.
	Ref      string
	Username string
	Password string
	// Insecure is true when Harbor's registry URL scheme is http.
	Insecure bool
}

// Registry returns the registry authority embedded in Ref, everything before the
// first '/'. syft scopes credentials per authority, so this must agree with what
// syft itself parses out of the reference.
func (t Target) Registry() string {
	host, _, found := strings.Cut(t.Ref, "/")
	if !found {
		return ""
	}
	return host
}

// Wrapper is the syft subprocess boundary.
type Wrapper interface {
	// Version returns the syft CLI version.
	Version(ctx context.Context) (string, error)
	// Generate pulls and scans target, writing both documents into jobDir.
	Generate(ctx context.Context, target Target, jobDir string) (Documents, error)
	// Convert turns an existing SPDX document into CycloneDX 1.6 without
	// touching the registry.
	Convert(ctx context.Context, spdx json.RawMessage, jobDir string) (json.RawMessage, error)
}

type wrapper struct {
	cfg etc.Syft
}

func NewWrapper(cfg etc.Syft) Wrapper {
	return &wrapper{cfg: cfg}
}

func (w *wrapper) Version(ctx context.Context) (string, error) {
	stdout, err := w.run(ctx, nil, "version", "-o", "text")
	if err != nil {
		return "", err
	}
	// `syft version -o text` prints several "Key: value" lines; the one that
	// matters is Version.
	for _, line := range strings.Split(stdout, "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(key), "version") {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("parsing syft version from %q", stdout)
}

func (w *wrapper) Generate(ctx context.Context, target Target, jobDir string) (Documents, error) {
	spdxPath := filepath.Join(jobDir, spdxFileName)
	cdxPath := filepath.Join(jobDir, cycloneDXFileName)

	args := []string{
		"scan",
		// registry: pins the source. syft's default source order probes for a
		// container runtime first, and this image ships none, so leaving it to
		// the default turns every scan into a slow walk through unavailable
		// backends before it reaches the registry.
		"registry:" + target.Ref,
		"-o", spdxFormat + "=" + spdxPath,
		"-o", cycloneDXFormat + "=" + cdxPath,
		"-q",
	}
	if w.cfg.Platform != "" {
		args = append(args, "--platform", w.cfg.Platform)
	}
	args = append(args, w.cfg.ExtraArgs...)

	if _, err := w.run(ctx, &target, args...); err != nil {
		return Documents{}, err
	}

	spdx, err := readJSONFile(spdxPath)
	if err != nil {
		return Documents{}, err
	}
	cdx, err := readJSONFile(cdxPath)
	if err != nil {
		return Documents{}, err
	}
	return Documents{SPDX: spdx, CycloneDX: cdx}, nil
}

func (w *wrapper) Convert(ctx context.Context, spdx json.RawMessage, jobDir string) (json.RawMessage, error) {
	inPath := filepath.Join(jobDir, "harbor."+spdxFileName)
	outPath := filepath.Join(jobDir, cycloneDXFileName)

	// 0600: the workdir is shared by every job in the container, and this
	// document describes a customer's image contents.
	if err := os.WriteFile(inPath, spdx, 0o600); err != nil {
		return nil, &Error{Category: CategoryAdapter, Cause: fmt.Errorf("staging SBOM for conversion: %w", err)}
	}

	// No Target: conversion reads a local file and must never touch the network,
	// so it gets no credentials.
	if _, err := w.run(ctx, nil, "convert", inPath, "-o", cycloneDXFormat+"="+outPath, "-q"); err != nil {
		return nil, err
	}
	return readJSONFile(outPath)
}

func (w *wrapper) run(ctx context.Context, target *Target, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, w.cfg.Binary, args...)
	cmd.Env = w.childEnv(target)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	started := time.Now()
	err := cmd.Run()
	slog.Debug("syft finished",
		slog.String("args", strings.Join(args, " ")),
		slog.Duration("took", time.Since(started)),
		slog.Bool("ok", err == nil))

	if err == nil {
		return stdout.String(), nil
	}

	// The deadline check comes first: an exec.ExitError from a killed process
	// would otherwise be reported as a scanner failure when the real cause is
	// the adapter's own timeout.
	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
		return "", &Error{Category: CategoryTimeout, Cause: fmt.Errorf("syft timed out: %w", ctxErr)}
	}

	return "", &Error{
		Category: classify(stderr.String()),
		Cause:    fmt.Errorf("running syft: %w: %s", err, truncate(stderr.String())),
	}
}

// childEnv builds the syft environment as an explicit allowlist rather than
// inheriting the adapter's. The adapter's own environment holds the
// Dependency-Track API key and the Redis URL, and none of that belongs in a
// subprocess that talks to a customer's registry.
func (w *wrapper) childEnv(target *Target) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + w.cfg.WorkDir,
		"TMPDIR=" + w.cfg.WorkDir,

		// syft phones home for a version check on every invocation. In an
		// air-gapped or egress-filtered deployment that is a multi-second stall
		// on a request Harbor is timing.
		"SYFT_CHECK_FOR_APP_UPDATE=false",

		// File cataloging emits one CycloneDX component per file in the image,
		// none of which carry a purl. On a small Alpine image that is 234 file
		// components against 18 real packages. Dependency-Track would store and
		// render every one of them while being able to analyze none, so the
		// cataloger is off.
		"SYFT_FILE_METADATA_SELECTION=none",
	}

	if target == nil {
		return env
	}

	if target.Insecure {
		env = append(env, "SYFT_REGISTRY_INSECURE_USE_HTTP=true")
	}
	if w.cfg.InsecureSkipVerify {
		env = append(env, "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")
	}
	if w.cfg.RegistryCACert != "" {
		env = append(env, "SYFT_REGISTRY_CA_CERT="+w.cfg.RegistryCACert)
	}
	if target.Username != "" || target.Password != "" {
		env = append(env,
			"SYFT_REGISTRY_AUTH_AUTHORITY="+target.Registry(),
			"SYFT_REGISTRY_AUTH_USERNAME="+target.Username,
			"SYFT_REGISTRY_AUTH_PASSWORD="+target.Password,
		)
	}
	return env
}

func readJSONFile(path string) (json.RawMessage, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is built from the adapter-owned job workdir
	if err != nil {
		return nil, &Error{Category: CategoryAdapter, Cause: fmt.Errorf("reading %s: %w", filepath.Base(path), err)}
	}
	// syft exits 0 having written an empty or partial file in some failure
	// modes. Catching it here keeps a malformed document from reaching Harbor's
	// report store, where it would be served on every subsequent poll.
	if !json.Valid(data) {
		return nil, &Error{Category: CategoryAdapter, Cause: fmt.Errorf("%s is not valid JSON", filepath.Base(path))}
	}
	return json.RawMessage(data), nil
}

// truncate bounds stderr copied into an error. The whole message is persisted as
// the job's failure reason and served back to Harbor, and syft can emit a very
// long trace.
func truncate(s string) string {
	const max = 2000
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "... (truncated)"
}
