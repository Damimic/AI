// Command kepler-landing serves the public marketing site and waitlist
// signup form. Public, no auth — unlike kepler-web (the dashboard).
//
// Uses its own database (KEPLER_MARKETING_DB_URL, conventionally
// kepler_marketing — see web/db/waitlist_schema.sql), separate from the
// findings database, so a compromised or abused public signup form has no
// path to customer vulnerability data.
//
// TLS is required by default, same rule as the other services — collecting
// email addresses over plaintext HTTP isn't the quiet default here either.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"kepler/web/internal/api"
	"kepler/web/internal/waitlist"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	dbURL := os.Getenv("KEPLER_MARKETING_DB_URL")
	if dbURL == "" {
		return fmt.Errorf("KEPLER_MARKETING_DB_URL is required (e.g. postgres://user:pass@host:5432/kepler_marketing)")
	}

	st, err := waitlist.Open(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer st.Close()

	// Both optional: with neither set, this serves the plain
	// html/template landing page exactly as it always has. Set
	// KEPLER_FRONTEND_DIST_DIR to serve the built frontend/ SPA instead
	// (see frontend/README.md for the build step), and
	// KEPLER_DASHBOARD_API_URL alongside it so the SPA's /api/* calls
	// reach kepler-web — see web/README.md for why this proxy exists
	// instead of browser-side CORS.
	handler, err := api.NewLandingServer(st, api.LandingOptions{
		FrontendDistDir:    os.Getenv("KEPLER_FRONTEND_DIST_DIR"),
		DashboardAPIURL:    os.Getenv("KEPLER_DASHBOARD_API_URL"),
		InsecureSkipVerify: os.Getenv("KEPLER_INSECURE_SKIP_VERIFY") == "true",
	})
	if err != nil {
		return err
	}

	addr := os.Getenv("KEPLER_LISTEN_ADDR")
	if addr == "" {
		addr = ":8445"
	}

	certFile := os.Getenv("KEPLER_TLS_CERT")
	keyFile := os.Getenv("KEPLER_TLS_KEY")
	insecure := os.Getenv("KEPLER_INSECURE_HTTP") == "true"

	// Explicit timeouts, not the http.Server zero-value defaults (none) —
	// a slow or idle client shouldn't be able to hold a connection open
	// indefinitely and exhaust server connection slots. This is public,
	// unauthenticated, internet-facing surface, so it matters here too.
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if certFile == "" || keyFile == "" {
		if !insecure {
			return fmt.Errorf("KEPLER_TLS_CERT and KEPLER_TLS_KEY are required; this refuses to serve plaintext HTTP by default. Set KEPLER_INSECURE_HTTP=true to override for local development only")
		}
		log.Println("WARNING: KEPLER_INSECURE_HTTP=true — serving plaintext HTTP. Never use this outside local development.")
		log.Printf("kepler-landing listening on %s (HTTP, insecure)", addr)
		return srv.ListenAndServe()
	}

	log.Printf("kepler-landing listening on %s (HTTPS)", addr)
	return srv.ListenAndServeTLS(certFile, keyFile)
}
