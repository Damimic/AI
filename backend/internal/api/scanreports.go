package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"kepler/backend/internal/matcher"
	"kepler/backend/internal/model"
	"kepler/backend/internal/store"
)

// maxScanReportBodyBytes bounds a scan report body the same way
// maxIngestBodyBytes bounds a findings batch — a real host's package list
// is at most a few thousand entries; this is generous headroom while still
// ruling out an unbounded body.
const maxScanReportBodyBytes = 10 << 20 // 10 MiB

func scanReportsHandler(st *store.Store, matchingAvailable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !matchingAvailable {
			http.Error(w, "CVE matching is not configured on this backend instance (no vulnerability database at startup) — submit pre-matched findings to POST /v1/findings instead", http.StatusServiceUnavailable)
			return
		}

		hostID, ok := hostIDFromContext(r.Context())
		if !ok {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxScanReportBodyBytes)

		var report model.ScanReportInput
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, "invalid JSON body (or exceeds size limit)", http.StatusBadRequest)
			return
		}
		if report.Host.OSName == "" {
			http.Error(w, "host.os_name is required", http.StatusBadRequest)
			return
		}
		if len(report.Packages) > maxIngestFindings {
			http.Error(w, fmt.Sprintf("packages must not exceed %d per scan report", maxIngestFindings), http.StatusBadRequest)
			return
		}

		findings, err := matcher.Match(r.Context(), report.Host, report.Packages)
		if err != nil {
			http.Error(w, "unsupported or unrecognized OS for CVE matching", http.StatusBadRequest)
			return
		}

		// Unlike /v1/findings, an empty result is a legitimate, good
		// outcome here — a host with no known-vulnerable packages is a
		// clean scan, not an error, and should still refresh last_seen_at
		// to prove the host is actively reporting.
		ingestionID, err := st.InsertFindings(r.Context(), hostID, findings)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(model.IngestResponse{
			IngestionID: ingestionID.String(),
			Stored:      len(findings),
		})
	}
}
