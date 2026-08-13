// Package model defines the backend's own request/response types. These
// intentionally aren't shared Go types with the agent module — the JSON
// wire format is the actual contract between agent-side tooling and the
// backend, and each side should be free to evolve its internal
// representation without the other needing a matching change.
package model

// FindingInput is a single finding as submitted in an ingestion request.
// It deliberately has no host field: the host is resolved server-side from
// the authenticated API key, never trusted from the request body — an
// authenticated agent for one host must not be able to claim to be another.
type FindingInput struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	CVEID        string `json:"cve_id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

// IngestRequest is the body of POST /v1/findings.
type IngestRequest struct {
	Findings []FindingInput `json:"findings"`
}

// IngestResponse confirms what was stored.
type IngestResponse struct {
	IngestionID string `json:"ingestion_id"`
	Stored      int    `json:"stored"`
}
