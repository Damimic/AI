package model

// Finding ties a host, an installed package, and a matched CVE together —
// the output of CVE matching, as distinct from ScanReport, which is the
// output of collection.
type Finding struct {
	Host         string `json:"host"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	CVEID        string `json:"cve_id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version,omitempty"`
}
