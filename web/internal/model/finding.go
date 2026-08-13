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
	ReportedAt   time.Time
}
