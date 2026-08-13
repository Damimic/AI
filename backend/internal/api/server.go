// Package api is the backend's HTTP layer: routing, authentication, and
// request handling for the ingestion endpoint.
package api

import (
	"net/http"

	"kepler/backend/internal/store"
)

// NewServer builds the backend's HTTP handler.
func NewServer(st *store.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/findings", requireAPIKey(st, ingestFindingsHandler(st)))
	return mux
}
