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

	// Status is the distro security tracker's own classification of this
	// CVE/package pairing — "fixed", "affected", "will_not_fix",
	// "end_of_life", "not_affected", "under_investigation",
	// "fix_deferred", or "unknown" (see trivy-db's types.Status). This is
	// not something Kepler infers or computes: it's Debian's/Ubuntu's own
	// security tracker data, passed through as-is. It matters because a
	// bare CVE ID and severity collapse two very different situations
	// into one line: "fixed" means a patched version exists right now,
	// while "affected"/"will_not_fix"/"end_of_life" mean no patch is
	// coming and the finding needs a compensating control instead of an
	// upgrade. Surfacing it (rather than discarding it, which is what
	// happened before this field existed) is what lets a dashboard
	// distinguish "upgrade this" from "this needs a different kind of
	// attention" without an operator having to look up every CVE by hand.
	Status string `json:"status,omitempty"`
}
