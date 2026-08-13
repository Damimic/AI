package handlers

import (
	"log"
	"net/http"

	"kepler/web/internal/model"
	"kepler/web/internal/store"
	"kepler/web/internal/templates"
)

var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

type findingsPage struct {
	Findings         []model.Finding
	Hostnames        []string
	Severities       []string
	SelectedHost     string
	SelectedSeverity string
}

// Findings renders the findings list, filterable via ?host=&severity=
// query params.
func Findings(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filter := store.FindingFilter{
			Host:     r.URL.Query().Get("host"),
			Severity: r.URL.Query().Get("severity"),
		}

		findings, err := st.ListFindings(r.Context(), filter)
		if err != nil {
			log.Printf("listing findings: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		hostnames, err := st.ListHostnames(r.Context())
		if err != nil {
			log.Printf("listing hostnames: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		data := findingsPage{
			Findings:         findings,
			Hostnames:        hostnames,
			Severities:       severities,
			SelectedHost:     filter.Host,
			SelectedSeverity: filter.Severity,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.Findings.Execute(w, data); err != nil {
			log.Printf("rendering findings template: %v", err)
		}
	}
}
