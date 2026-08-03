package waybill

import "fmt"

// ErrorCategory classifies a waybill failure for the job error message.
type ErrorCategory string

const (
	CategoryTimeout ErrorCategory = "Timeout"
	CategoryExec    ErrorCategory = "WaybillExec"

	// The Pull* categories are recovered from waybill's stderr. Since waybill
	// performs the registry pull in-process, these three are the operator-facing
	// difference between "the scanner is broken" and "the scanner registration or
	// registry transport is misconfigured".
	CategoryPull          ErrorCategory = "RegistryPull"
	CategoryPullAuth      ErrorCategory = "RegistryPullAuth"
	CategoryPullTransport ErrorCategory = "RegistryPullTransport"
)

// Error is a structured waybill subprocess failure.
type Error struct {
	Category ErrorCategory
	Detail   string
	ExitCode int
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s", e.Category, e.Detail)
}
