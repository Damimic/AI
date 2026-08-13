package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"kepler/agent/internal/model"
)

// dpkgQueryFormat uses literal backslash-t / backslash-n escapes, which
// dpkg-query itself interprets and converts to real tabs/newlines in its
// output — this is dpkg-query's own format syntax, not a Go string escape.
const dpkgQueryFormat = `${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Status}\n`

// CollectPackages returns installed packages as reported by dpkg. It shells
// out to dpkg-query, a read-only query against the local package database —
// no root privileges required.
func CollectPackages(ctx context.Context) ([]model.Package, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", dpkgQueryFormat)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running dpkg-query: %w", err)
	}
	return parseDpkgQuery(strings.NewReader(string(out)))
}

// parseDpkgQuery parses dpkg-query -W output produced with dpkgQueryFormat,
// keeping only packages whose status is "install ok installed" — dpkg keeps
// entries around for removed-but-not-purged packages, which aren't
// installed software and shouldn't be reported as such.
func parseDpkgQuery(r io.Reader) ([]model.Package, error) {
	var pkgs []model.Package
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			continue
		}
		name, version, arch := fields[0], fields[1], fields[2]
		srcName, srcVersion, status := fields[3], fields[4], fields[5]
		if status != "install ok installed" {
			continue
		}
		pkgs = append(pkgs, model.Package{
			Name:          name,
			Version:       version,
			Architecture:  arch,
			Source:        "dpkg",
			SourcePackage: srcName,
			SourceVersion: srcVersion,
		})
	}
	return pkgs, scanner.Err()
}
