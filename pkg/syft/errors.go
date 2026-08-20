package syft

import (
	"fmt"
	"strings"
)

// ErrorCategory classifies a syft failure. The categories exist to separate the
// three things an operator does differently: retry, fix the scanner
// registration, or fix the registry transport. They are surfaced both in the
// job's error message and as a metrics label, so the set is deliberately small
// and closed.
type ErrorCategory string

const (
	CategoryTimeout ErrorCategory = "Timeout"
	CategoryExec    ErrorCategory = "SyftExec"

	// CategoryAdapter marks a failure on the adapter's side of the subprocess
	// boundary: a workdir it could not write, an output file syft left
	// unparseable. Folding these into SyftExec would blame the scanner for the
	// adapter's own bugs.
	CategoryAdapter ErrorCategory = "Adapter"

	// The Pull* categories are recovered from syft's stderr. syft performs the
	// registry pull in-process, so these are the operator-facing difference
	// between a broken scanner and a misconfigured registration.
	CategoryPull          ErrorCategory = "RegistryPull"
	CategoryPullAuth      ErrorCategory = "RegistryPullAuth"
	CategoryPullTransport ErrorCategory = "RegistryPullTransport"
)

// Error is a structured syft failure.
type Error struct {
	Category ErrorCategory
	Cause    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %v", e.Category, e.Cause)
}

func (e *Error) Unwrap() error { return e.Cause }

// classify recovers a category from syft's stderr.
//
// This is string matching against another project's output, which is
// unavoidable: syft exits 1 for everything. The fallback is the generic exec
// category, so a wording change upstream costs a less precise label rather than
// a wrong one or a crash.
func classify(stderr string) ErrorCategory {
	s := strings.ToLower(stderr)
	switch {
	case containsAny(s, "unauthorized", "authentication required", "denied:", "forbidden"):
		return CategoryPullAuth
	case containsAny(s, "x509", "tls", "certificate", "connection refused", "no such host", "http: server gave http response"):
		return CategoryPullTransport
	case containsAny(s, "manifest unknown", "not found", "failed to get image", "unable to load image", "could not fetch image"):
		return CategoryPull
	default:
		return CategoryExec
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
