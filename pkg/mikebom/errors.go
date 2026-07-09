package mikebom

import "fmt"

// ErrorCategory classifies a mikebom failure for the job error message.
type ErrorCategory string

const (
	CategoryTimeout ErrorCategory = "Timeout"
	CategoryExec    ErrorCategory = "MikebomExec"
)

// Error is a structured mikebom subprocess failure.
type Error struct {
	Category ErrorCategory
	Detail   string
	ExitCode int
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s", e.Category, e.Detail)
}
