// Package api wires the dashboard's HTTP routing and auth together.
package api

import (
	"net/http"

	"kepler/web/internal/auth"
	"kepler/web/internal/handlers"
	"kepler/web/internal/store"
)

// NewServer builds the dashboard's HTTP handler. Every route requires the
// configured operator credential.
func NewServer(st *store.Store, dashboardUser, dashboardPasswordHash string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handlers.Findings(st))
	return auth.RequireBasicAuth(dashboardUser, dashboardPasswordHash, mux)
}
