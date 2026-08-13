package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"kepler/backend/internal/model"
	"kepler/backend/internal/store"
)

func ingestFindingsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := hostIDFromContext(r.Context())
		if !ok {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var req model.IngestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if len(req.Findings) == 0 {
			http.Error(w, "findings must not be empty", http.StatusBadRequest)
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
