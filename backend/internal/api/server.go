// Package api is the backend's HTTP layer: routing, authentication, and
// request handling for the ingestion endpoints.
package api

import (
	"net/http"

	"kepler/backend/internal/store"
)

// NewServer builds the backend's HTTP handler.
//
// matchingAvailable reflects whether the process successfully opened a
// Trivy vulnerability database at startup (see cmd/kepler-backend). It's a
// deliberate soft dependency: an existing deployment that only ever used
// POST /v1/findings (pre-matched submissions) must keep working exactly as
// before even if no database is configured. Only POST /v1/scan-reports —
// the new endpoint that does matching itself — needs it, and degrades with
// a clear 503 rather than the whole server failing to start.
func NewServer(st *store.Store, matchingAvailable bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/findings", requireAPIKey(st, ingestFindingsHandler(st)))
	mux.HandleFunc("POST /v1/scan-reports", requireAPIKey(st, scanReportsHandler(st, matchingAvailable)))
	return mux
}
