package api

import (
	"fmt"
	"net/http"

	"kepler/web/internal/handlers"
	"kepler/web/internal/waitlist"
)

// LandingOptions configures the optional frontend SPA this server can
// serve alongside the plain Go-rendered landing page. Both fields empty
// (the zero value) is a fully valid, supported configuration — the
// server just serves the html/template landing page, same as before the
// frontend existed.
type LandingOptions struct {
	// FrontendDistDir, if set, is a directory on disk holding the built
	// frontend (frontend/, built via `npm run build`) — served instead of
	// the html/template landing page, with SPA-style fallback routing.
	FrontendDistDir string
	// DashboardAPIURL, if set, is where /api/* requests get proxied —
	// kepler-web's address. Only meaningful alongside FrontendDistDir,
	// since the plain landing page makes no API calls of its own.
	DashboardAPIURL string
	// InsecureSkipVerify disables TLS verification on the proxy
	// connection to DashboardAPIURL — local dev against a self-signed
	// cert only, logged as a warning. Never set in production.
	InsecureSkipVerify bool
}

// NewLandingServer builds the marketing site's HTTP handler. Public, no
// auth — unlike NewServer (the dashboard), which requires it.
//
// Returns an error only for a malformed opts.DashboardAPIURL — an operator
// config mistake that should fail server startup loudly (main.go's job to
// decide how), not degrade into a confusing 404 once the server is
// already taking production traffic.
func NewLandingServer(st *waitlist.Store, opts LandingOptions) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /waitlist", handlers.Waitlist(st))

	if opts.FrontendDistDir == "" {
		mux.HandleFunc("GET /", handlers.Landing())
		return mux, nil
	}

	if opts.DashboardAPIURL != "" {
		proxy, err := dashboardAPIProxy(opts.DashboardAPIURL, opts.InsecureSkipVerify)
		if err != nil {
			return nil, fmt.Errorf("invalid KEPLER_DASHBOARD_API_URL %q: %w", opts.DashboardAPIURL, err)
		}
		mux.Handle("/api/", proxy)
	}
	mux.Handle("/", spaHandler(opts.FrontendDistDir))
	return mux, nil
}
