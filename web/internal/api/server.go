// Package api wires the dashboard's HTTP routing and auth together.
package api

import (
	"net/http"

	"kepler/web/internal/auth"
	"kepler/web/internal/handlers"
	"kepler/web/internal/store"
)

// NewServer builds the dashboard's HTTP handler. Every route requires the
// configured operator credential — including /api/findings, which exists
// so the frontend SPA can fetch the same data GET / renders as HTML.
func NewServer(st *store.Store, dashboardUser, dashboardPasswordHash string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handlers.Findings(st))
	mux.HandleFunc("GET /api/findings", handlers.FindingsAPI(st))
	return auth.RequireBasicAuth(dashboardUser, dashboardPasswordHash, mux)
}
