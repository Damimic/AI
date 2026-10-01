// Package agent_test is not a real test — it's a compile-time tripwire for
// ARCHITECTURE.md's module-responsibility table. It references every
// symbol that table lists for this module, so renaming or removing one of
// them fails the build here instead of the doc silently going stale. See
// ARCHITECTURE.md's "Keeping this honest" section for why this exists per
// module rather than as one whole-repo version of the same check.
package agent_test

import (
	"context"
	"testing"

	"kepler/agent/internal/collector"
	"kepler/agent/internal/matcher"
	"kepler/agent/internal/model"
)

func TestArchitectureDoc_Agent(t *testing.T) {
	// internal/collector — ARCHITECTURE.md lists these four entry points.
	var (
		_ func(context.Context) (model.HostInfo, error)  = collector.CollectOSInfo
		_ func(context.Context) ([]model.Package, error) = collector.CollectPackages
		_ func(context.Context) ([]model.Service, error) = collector.CollectServices
		_ func() ([]model.Port, error)                   = collector.CollectPorts
	)

	// internal/matcher — Init, Match, Close.
	var (
		_ func(string) error                                                              = matcher.Init
		_ func(context.Context, model.HostInfo, []model.Package) ([]model.Finding, error) = matcher.Match
		_ func() error                                                                    = matcher.Close
	)

	// internal/model — the data shapes the table names.
	_ = model.ScanReport{}
	_ = model.Finding{}
	_ = model.HostInfo{}
	_ = model.Package{}
	_ = model.Service{}
	_ = model.Port{}
}
