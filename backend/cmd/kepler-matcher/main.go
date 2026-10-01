// Command kepler-matcher is an offline debug tool: it reads a scan-report
// shaped JSON body (the same shape POST /v1/scan-reports accepts, from
// stdin) and matches it against a local Trivy vulnerability database,
// printing the resulting findings as JSON.
//
// This is not part of what ships to customer infrastructure, and it's not
// what a live agent uses either — a running kepler-backend does this same
// matching automatically as part of handling POST /v1/scan-reports. This
// exists for offline triage: feed it a captured scan report, see what
// would match, without a live backend or database connection.
//
// It expects a database already downloaded by the trivy CLI:
// `trivy image --download-db-only`.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kepler/backend/internal/matcher"
	"kepler/backend/internal/model"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kepler-matcher:", err)
		os.Exit(1)
	}
}

func run() error {
	dbDir, err := resolveDBDir()
	if err != nil {
		return err
	}

	if err := matcher.Init(dbDir); err != nil {
		return fmt.Errorf("opening vulnerability database at %s (run `trivy image --download-db-only` first): %w", dbDir, err)
	}
	defer matcher.Close()

	var report model.ScanReportInput
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return fmt.Errorf("reading scan report from stdin: %w", err)
	}

	findings, err := matcher.Match(context.Background(), report.Host, report.Packages)
	if err != nil {
		return fmt.Errorf("matching CVEs: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// resolveDBDir finds the Trivy-managed vulnerability database, following
// the same OS-appropriate cache location the trivy CLI itself uses
// (~/Library/Caches/trivy on macOS, ~/.cache/trivy on Linux), unless
// overridden explicitly.
func resolveDBDir() (string, error) {
	if dir := os.Getenv("KEPLER_TRIVY_DB_DIR"); dir != "" {
		return dir, nil
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving cache directory: %w", err)
	}
	return filepath.Join(cacheDir, "trivy", "db"), nil
}
