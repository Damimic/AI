// JSON API handlers for the frontend SPA — same data, same auth
// (RequireBasicAuth wraps these identically to the HTML routes), just
// JSON instead of a rendered page. Kept in a separate file from
// findings.go/landing.go rather than replacing those: the HTML routes stay
// so curl/a browser without JS still works, matching this codebase's
// existing "plain and auditable over clever" bias.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"kepler/web/internal/model"
	"kepler/web/internal/store"
)

type findingsAPIResponse struct {
	Findings  []model.Finding `json:"findings"`
	Hostnames []string        `json:"hostnames"`
}

// FindingsAPI returns findings (and the known hostnames, for a filter
// dropdown) as JSON, filterable via the same ?host=&severity= query
// params as the HTML route. Empty results encode as `[]`, never `null` —
// a frontend shouldn't need a special case for "no findings yet" versus
// "the findings field is missing."
func FindingsAPI(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filter := store.FindingFilter{
			Host:     r.URL.Query().Get("host"),
			Severity: r.URL.Query().Get("severity"),
		}

		findings, err := st.ListFindings(r.Context(), filter)
		if err != nil {
			log.Printf("listing findings: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if findings == nil {
			findings = []model.Finding{}
		}

		hostnames, err := st.ListHostnames(r.Context())
		if err != nil {
			log.Printf("listing hostnames: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if hostnames == nil {
			hostnames = []string{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(findingsAPIResponse{Findings: findings, Hostnames: hostnames})
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}
