// Command kepler-web serves the findings dashboard: a single
// Basic-Auth-protected page listing findings, filterable by host and
// severity. Read-only — all writes happen through kepler-backend's
// ingestion API.
//
// TLS is required by default, same rule and same reasoning as
// kepler-backend: findings are security-sensitive, and Basic Auth
// credentials are only as safe as the transport carrying them.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"kepler/web/internal/api"
	"kepler/web/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	dbURL := os.Getenv("KEPLER_DB_URL")
	if dbURL == "" {
		return fmt.Errorf("KEPLER_DB_URL is required (e.g. postgres://user:pass@host:5432/kepler)")
	}

	dashboardUser := os.Getenv("KEPLER_DASHBOARD_USER")
	dashboardPasswordHash := os.Getenv("KEPLER_DASHBOARD_PASSWORD_HASH")
	if dashboardUser == "" || dashboardPasswordHash == "" {
		return fmt.Errorf("KEPLER_DASHBOARD_USER and KEPLER_DASHBOARD_PASSWORD_HASH are required (generate a hash with: kepler-web-admin hash-password)")
	}

	st, err := store.Open(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer st.Close()

	handler := api.NewServer(st, dashboardUser, dashboardPasswordHash)

	addr := os.Getenv("KEPLER_LISTEN_ADDR")
	if addr == "" {
		addr = ":8444"
	}

	certFile := os.Getenv("KEPLER_TLS_CERT")
	keyFile := os.Getenv("KEPLER_TLS_KEY")
	insecure := os.Getenv("KEPLER_INSECURE_HTTP") == "true"

	if certFile == "" || keyFile == "" {
		if !insecure {
			return fmt.Errorf("KEPLER_TLS_CERT and KEPLER_TLS_KEY are required; the dashboard shows security-sensitive data and this refuses to serve plaintext HTTP by default. Set KEPLER_INSECURE_HTTP=true to override for local development only")
		}
		log.Println("WARNING: KEPLER_INSECURE_HTTP=true — serving plaintext HTTP. Never use this outside local development.")
		log.Printf("kepler-web listening on %s (HTTP, insecure)", addr)
		return http.ListenAndServe(addr, handler)
	}

	log.Printf("kepler-web listening on %s (HTTPS)", addr)
	return http.ListenAndServeTLS(addr, certFile, keyFile, handler)
}
