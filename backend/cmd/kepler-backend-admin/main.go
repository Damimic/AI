// Command kepler-backend-admin provisions hosts.
//
// There's no self-service enrollment flow yet — v1 explicitly avoids
// multi-tenant/signup complexity beyond what's needed to prove the core
// loop. This is how a host gets an API key until that exists.
//
// Usage: kepler-backend-admin create-host <hostname>
package main

import (
	"context"
	"fmt"
	"os"

	"kepler/backend/internal/auth"
	"kepler/backend/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kepler-backend-admin:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 || os.Args[1] != "create-host" {
		return fmt.Errorf("usage: kepler-backend-admin create-host <hostname>")
	}
	hostname := os.Args[2]

	dbURL := os.Getenv("KEPLER_DB_URL")
	if dbURL == "" {
		return fmt.Errorf("KEPLER_DB_URL is required (e.g. postgres://user:pass@host:5432/kepler)")
	}

	ctx := context.Background()
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer st.Close()

	hostID, err := st.CreateHost(ctx, hostname)
	if err != nil {
		return fmt.Errorf("creating host: %w", err)
	}

	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		return fmt.Errorf("generating API key: %w", err)
	}
	if _, err := st.CreateAPIKey(ctx, hostID, keyHash); err != nil {
		return fmt.Errorf("storing API key: %w", err)
	}

	fmt.Printf("host_id: %s\n", hostID)
	fmt.Printf("api_key: %s\n", rawKey)
	fmt.Println()
	fmt.Println("Save this key now — it is not stored anywhere and cannot be recovered, only rotated.")
	return nil
}
