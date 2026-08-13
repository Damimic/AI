// Command kepler-backend serves the findings ingestion API.
//
// TLS is required by default — findings are security-sensitive (they map a
// customer's unpatched vulnerabilities), so serving them over plaintext
// HTTP is never the quiet default. KEPLER_INSECURE_HTTP=true overrides
// this explicitly, for local development only.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"kepler/backend/internal/api"
	"kepler/backend/internal/store"
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

	st, err := store.Open(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer st.Close()

	handler := api.NewServer(st)

	addr := os.Getenv("KEPLER_LISTEN_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	certFile := os.Getenv("KEPLER_TLS_CERT")
	keyFile := os.Getenv("KEPLER_TLS_KEY")
	insecure := os.Getenv("KEPLER_INSECURE_HTTP") == "true"

	// Explicit timeouts, not the http.Server zero-value defaults (none) —
	// a slow or idle client shouldn't be able to hold a connection open
	// indefinitely and exhaust server connection slots.
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
			return fmt.Errorf("KEPLER_TLS_CERT and KEPLER_TLS_KEY are required; findings are security-sensitive data and this refuses to serve plaintext HTTP by default. Set KEPLER_INSECURE_HTTP=true to override for local development only")
		}
		log.Println("WARNING: KEPLER_INSECURE_HTTP=true — serving plaintext HTTP. Never use this outside local development.")
		log.Printf("kepler-backend listening on %s (HTTP, insecure)", addr)
		return srv.ListenAndServe()
	}

	log.Printf("kepler-backend listening on %s (HTTPS)", addr)
	return srv.ListenAndServeTLS(certFile, keyFile)
}
