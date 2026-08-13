package api

import (
	"net/http"

	"kepler/web/internal/handlers"
	"kepler/web/internal/waitlist"
)

// NewLandingServer builds the marketing site's HTTP handler. Public, no
// auth — unlike NewServer (the dashboard), which requires it.
func NewLandingServer(st *waitlist.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handlers.Landing())
	mux.HandleFunc("POST /waitlist", handlers.Waitlist(st))
	return mux
}
