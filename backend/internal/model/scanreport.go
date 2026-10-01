package model

// ScanReportInput is the body of POST /v1/scan-reports: a host's raw
// collected package data, submitted for server-side CVE matching. This is
// the new primary path for a live agent — /v1/findings still exists for
// pre-matched submissions, but a real kepler-agent now reports here.
//
// Deliberately narrower than agent's full ScanReport: only OSName and
// OSVersionID (needed to pick a scanner) and Packages (the thing actually
// matched) are represented. Decoding a full ScanReport body into this
// struct silently drops Services, Ports, and CollectedAt — that's fine,
// nothing here uses them, and there's no schema to store them in yet.
//
// There is deliberately no Hostname field, even though agent's ScanReport
// carries one: host identity for storage is resolved server-side from the
// authenticated API key (see requireAPIKey), never from the request body.
// Omitting the field entirely — rather than including it and just not
// reading it — means a future change can't accidentally start trusting it
// without first adding it back and re-deriving why that would be wrong.
type ScanReportInput struct {
	Host     ScanReportHost      `json:"host"`
	Packages []ScanReportPackage `json:"packages"`
}

// ScanReportHost is the OS identity fields matching actually needs.
type ScanReportHost struct {
	OSName      string `json:"os_name"`
	OSVersionID string `json:"os_version_id"`
}

// ScanReportPackage mirrors agent's model.Package, narrowed to the fields
// the matcher reads (Architecture and Source are collected but never used
// for matching, so they're not represented here).
type ScanReportPackage struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	SourcePackage string `json:"source_package"`
	SourceVersion string `json:"source_version"`
}
