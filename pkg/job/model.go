package job

import (
	"encoding/json"
	"fmt"

	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
)

type ScanJobStatus int

const (
	Queued ScanJobStatus = iota
	Pending
	Finished
	Failed
)

func (s ScanJobStatus) String() string {
	if s < 0 || s > 3 {
		return "Unknown"
	}
	return [...]string{
		"Queued",
		"Pending",
		"Finished",
		"Failed",
	}[s]
}

// ScanJobKey uniquely identifies a scan job. For SBOM reports MediaType is set
// (application/spdx+json); it is how Harbor keys the report GET.
type ScanJobKey struct {
	ID        string        `json:"id"`
	MIMEType  api.MIMEType  `json:"mime_type"`
	MediaType api.MediaType `json:"media_type"`
}

func (s *ScanJobKey) String() string {
	if s.MediaType != "" {
		return fmt.Sprintf("%s:%s:%s", s.ID, s.MIMEType.String(), s.MediaType)
	}
	return fmt.Sprintf("%s:%s", s.ID, s.MIMEType.String())
}

// ScanJob is the persisted job record. Report holds the pre-marshaled SBOM
// report envelope (json.RawMessage) so the possibly multi-MB SPDX document is
// never re-marshaled on a report poll.
type ScanJob struct {
	Key    ScanJobKey      `json:"key"`
	Status ScanJobStatus   `json:"status"`
	Error  string          `json:"error"`
	Report json.RawMessage `json:"report,omitempty"`
}

func (s *ScanJob) ID() string {
	return s.Key.String()
}
