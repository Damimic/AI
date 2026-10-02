// Package model defines the dashboard's own read-side types. As with the
// backend, these aren't shared Go types across modules — the database
// schema is the actual contract, and this package only needs to represent
// what the dashboard displays.
package model

import "time"

// Finding is a single row as displayed on the findings list. JSON tags
// exist because this same type is both what html/template renders and
// what the JSON API (GET /api/findings, for the frontend) returns — one
// shape, two consumers, not a reason to duplicate the struct.
type Finding struct {
	Host         string `json:"host"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	CVEID        string `json:"cve_id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version,omitempty"`
	// Status is the distro tracker's own fix-status classification
	// ("fixed", "affected", "will_not_fix", "end_of_life", ...) — may be
	// empty for findings reported before this field existed. See
	// agent/internal/model.Finding for the full rationale.
	Status     string    `json:"status,omitempty"`
	ReportedAt time.Time `json:"reported_at"`
}
