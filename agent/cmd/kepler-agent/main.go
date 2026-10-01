// Command kepler-agent collects package, OS, service, and open-port data
// from the local Linux host.
//
// By default it prints the scan report as JSON to stdout — useful for
// local debugging, or piping into something else. When KEPLER_BACKEND_URL
// and KEPLER_API_KEY are both set, it instead POSTs the report to that
// backend's POST /v1/scan-reports, authenticated with the API key, and
// prints a one-line confirmation to stderr. This is the real production
// mode: run on a schedule (see deploy/systemd/kepler-agent.timer), it
// reports on its own without a human running any step in between.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"kepler/agent/internal/collector"
	"kepler/agent/internal/model"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kepler-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	host, err := collector.CollectOSInfo(ctx)
	if err != nil {
		return fmt.Errorf("collecting OS info: %w", err)
	}

	packages, err := collector.CollectPackages(ctx)
	if err != nil {
		return fmt.Errorf("collecting packages: %w", err)
	}

	services, err := collector.CollectServices(ctx)
	if err != nil {
		return fmt.Errorf("collecting services: %w", err)
	}

	ports, err := collector.CollectPorts()
	if err != nil {
		return fmt.Errorf("collecting ports: %w", err)
	}

	report := model.ScanReport{
		Host:        host,
		CollectedAt: time.Now().UTC(),
		Packages:    packages,
		Services:    services,
		Ports:       ports,
	}

	backendURL := os.Getenv("KEPLER_BACKEND_URL")
	apiKey := os.Getenv("KEPLER_API_KEY")

	switch {
	case backendURL == "" && apiKey == "":
		return printReport(report)
	case backendURL == "" || apiKey == "":
		return fmt.Errorf("KEPLER_BACKEND_URL and KEPLER_API_KEY must both be set to report over the network (both unset: prints to stdout instead)")
	default:
		return reportToBackend(ctx, backendURL, apiKey, report)
	}
}

func printReport(report model.ScanReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// reportToBackend POSTs the scan report to <backendURL>/v1/scan-reports.
// KEPLER_INSECURE_SKIP_VERIFY=true disables TLS certificate verification —
// for local development against a self-signed cert only, same override
// pattern (explicit, logged, named for exactly what it does) as
// kepler-backend's own KEPLER_INSECURE_HTTP.
func reportToBackend(ctx context.Context, backendURL, apiKey string, report model.ScanReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding scan report: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if os.Getenv("KEPLER_INSECURE_SKIP_VERIFY") == "true" {
		fmt.Fprintln(os.Stderr, "WARNING: KEPLER_INSECURE_SKIP_VERIFY=true — not verifying the backend's TLS certificate. Never use this outside local development.")
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL+"/v1/scan-reports", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting scan report to %s: %w", backendURL, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("backend rejected scan report: %s: %s", resp.Status, respBody)
	}

	var ingestResp struct {
		IngestionID string `json:"ingestion_id"`
		Stored      int    `json:"stored"`
	}
	if err := json.Unmarshal(respBody, &ingestResp); err != nil {
		// Reported successfully (201 already returned above); a malformed
		// confirmation body isn't worth failing the run over.
		fmt.Fprintf(os.Stderr, "kepler-agent: reported %d packages, but couldn't parse the confirmation response\n", len(report.Packages))
		return nil
	}
	fmt.Fprintf(os.Stderr, "kepler-agent: reported %d packages to %s — ingestion %s, %d finding(s)\n",
		len(report.Packages), backendURL, ingestResp.IngestionID, ingestResp.Stored)
	return nil
}
