// Package model defines the dashboard's own read-side types. As with the
// backend, these aren't shared Go types across modules — the database
// schema is the actual contract, and this package only needs to represent
// what the dashboard displays.
package model

import "time"

// Finding is a single row as displayed on the findings list.
type Finding struct {
	Host         string
	Package      string
	Version      string
	CVEID        string
	Severity     string
	FixedVersion string
	// Status is the distro tracker's own fix-status classification
	// ("fixed", "affected", "will_not_fix", "end_of_life", ...) — may be
	// empty for findings reported before this field existed. See
	// agent/internal/model.Finding for the full rationale.
	Status     string
	ReportedAt time.Time
}
