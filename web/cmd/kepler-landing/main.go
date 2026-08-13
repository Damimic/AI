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

	handler := api.NewLandingServer(st)

	addr := os.Getenv("KEPLER_LISTEN_ADDR")
	if addr == "" {
		addr = ":8445"
	}

	certFile := os.Getenv("KEPLER_TLS_CERT")
	keyFile := os.Getenv("KEPLER_TLS_KEY")
	insecure := os.Getenv("KEPLER_INSECURE_HTTP") == "true"

	if certFile == "" || keyFile == "" {
		if !insecure {
			return fmt.Errorf("KEPLER_TLS_CERT and KEPLER_TLS_KEY are required; this refuses to serve plaintext HTTP by default. Set KEPLER_INSECURE_HTTP=true to override for local development only")
		}
		log.Println("WARNING: KEPLER_INSECURE_HTTP=true — serving plaintext HTTP. Never use this outside local development.")
		log.Printf("kepler-landing listening on %s (HTTP, insecure)", addr)
		return http.ListenAndServe(addr, handler)
	}

	log.Printf("kepler-landing listening on %s (HTTPS)", addr)
	return http.ListenAndServeTLS(addr, certFile, keyFile, handler)
}
