package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"kepler/backend/internal/model"
	"kepler/backend/internal/store"
)

// maxIngestBodyBytes bounds a single ingestion request body. A legitimate
// scan report is at most a few thousand findings; this is generous headroom
// while still ruling out an unbounded body from exhausting server memory.
const maxIngestBodyBytes = 10 << 20 // 10 MiB

// maxIngestFindings bounds how many findings a single request can carry, so
// a valid (but malicious or malfunctioning) API key can't force one request
// into a multi-million-row batch insert.
const maxIngestFindings = 10000

func ingestFindingsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := hostIDFromContext(r.Context())
		if !ok {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)

		var req model.IngestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body (or exceeds size limit)", http.StatusBadRequest)
			return
		}
		if len(req.Findings) == 0 {
			http.Error(w, "findings must not be empty", http.StatusBadRequest)
			return
		}
		if len(req.Findings) > maxIngestFindings {
			http.Error(w, fmt.Sprintf("findings must not exceed %d per request", maxIngestFindings), http.StatusBadRequest)
			return
		}
		for i, f := range req.Findings {
			if f.Package == "" || f.Version == "" || f.CVEID == "" || f.Severity == "" {
				http.Error(w, fmt.Sprintf("findings[%d]: package, version, cve_id, and severity are required", i), http.StatusBadRequest)
				return
			}
		}

		ingestionID, err := st.InsertFindings(r.Context(), hostID, req.Findings)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(model.IngestResponse{
			IngestionID: ingestionID.String(),
			Stored:      len(req.Findings),
		})
	}
}
