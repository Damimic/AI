// Command kepler-agent collects package, OS, service, and open-port data
// from the local Linux host and prints it as a JSON scan report.
//
// v1: local collection only. No network reporting yet — that arrives once
// the backend's authenticated ingestion endpoint exists.
package main

import (
	"context"
	"encoding/json"
	"fmt"
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

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
