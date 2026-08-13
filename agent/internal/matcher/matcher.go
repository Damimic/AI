// Package matcher matches a host's collected packages against a local CVE
// database and produces structured findings.
//
// This intentionally does not run on customer infrastructure — it's used by
// Kepler's own tooling/backend, where depending on Trivy's Go packages and
// on a locally-managed vulnerability database is acceptable. kepler-agent
// itself stays a dependency-free single binary; matching happens elsewhere.
//
// Kepler does not download or refresh the vulnerability database itself —
// that's Trivy's own well-tested job. Run `trivy image --download-db-only`
// (or let a plain `trivy` scan do it implicitly) to populate/update it
// before matching.
package matcher

import (
	"context"
	"fmt"
	"strings"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/debian"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/ubuntu"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	debVersion "github.com/knqyf263/go-deb-version"

	"kepler/agent/internal/model"
)

// Init opens the local trivy vulnerability database. dbDir must point at an
// existing database directory (see the package doc comment).
func Init(dbDir string) error {
	return trivydb.Init(dbDir)
}

// Close releases the database opened by Init.
func Close() error {
	return trivydb.Close()
}

// ospkgScanner is implemented by Trivy's per-distro OS package scanners
// (debian.Scanner, ubuntu.Scanner, ...). Matching against multiple distros
// is just a matter of selecting the right one for the host.
type ospkgScanner interface {
	Detect(ctx context.Context, osVer string, repo *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error)
}

// Match matches a host's collected packages against the open database and
// returns structured findings. Init must be called first.
func Match(ctx context.Context, host model.HostInfo, packages []model.Package) ([]model.Finding, error) {
	scanner, err := scannerFor(host.OSName)
	if err != nil {
		return nil, err
	}

	pkgs := toTrivyPackages(packages)

	detected, err := scanner.Detect(ctx, host.OSVersionID, nil, pkgs)
	if err != nil {
		return nil, fmt.Errorf("detecting vulnerabilities: %w", err)
	}

	vulnerability.NewClient(trivydb.Config{}).FillInfo(detected, []dbTypes.SourceID{"auto"})

	findings := make([]model.Finding, 0, len(detected))
	for _, d := range detected {
		findings = append(findings, model.Finding{
			Host:         host.Hostname,
			Package:      d.PkgName,
			Version:      d.InstalledVersion,
			CVEID:        d.VulnerabilityID,
			Severity:     d.Severity,
			FixedVersion: d.FixedVersion,
		})
	}
	return findings, nil
}

// toTrivyPackages converts collected packages into the form Trivy's
// scanners expect: Debian version strings split into epoch/version/release,
// using the source package name and version — CVE advisories for OS
// packages are keyed by source package, not binary package (e.g. the binary
// package "libssl3" is tracked under its source package "openssl").
// Packages whose version string doesn't parse as a Debian version are
// skipped rather than failing the whole match.
func toTrivyPackages(packages []model.Package) []ftypes.Package {
	pkgs := make([]ftypes.Package, 0, len(packages))
	for _, p := range packages {
		installed, err := debVersion.NewVersion(p.Version)
		if err != nil {
			continue
		}
		src, err := debVersion.NewVersion(p.SourceVersion)
		if err != nil {
			src = installed
		}
		pkgs = append(pkgs, ftypes.Package{
			Name:       p.Name,
			Version:    installed.Version(),
			Epoch:      installed.Epoch(),
			Release:    installed.Revision(),
			SrcName:    p.SourcePackage,
			SrcVersion: src.Version(),
			SrcEpoch:   src.Epoch(),
			SrcRelease: src.Revision(),
		})
	}
	return pkgs
}

// scannerFor picks the OS package scanner for a host's OS name. v1 collects
// packages via dpkg only, so only Debian-family distros are supported.
func scannerFor(osName string) (ospkgScanner, error) {
	switch {
	case strings.Contains(strings.ToLower(osName), "ubuntu"):
		return ubuntu.NewScanner(), nil
	case strings.Contains(strings.ToLower(osName), "debian"):
		return debian.NewScanner(), nil
	default:
		return nil, fmt.Errorf("unsupported OS for CVE matching: %q (v1 supports Debian/Ubuntu only)", osName)
	}
}
