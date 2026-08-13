package matcher

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

	"kepler/agent/internal/model"
)

func TestToTrivyPackages(t *testing.T) {
	packages := []model.Package{
		{
			// binary package name differs from source package name/version —
			// the case that broke the first version of this integration.
			Name: "libssl3", Version: "3.0.2-0ubuntu1.15",
			SourcePackage: "openssl", SourceVersion: "3.0.2-0ubuntu1.15",
		},
		{
			// version with an epoch prefix.
			Name: "zlib1g", Version: "1:1.2.11.dfsg-2ubuntu9.2",
			SourcePackage: "zlib", SourceVersion: "1:1.2.11.dfsg-2ubuntu9.2",
		},
		{
			// unparseable version should be skipped, not crash the batch.
			Name: "bogus", Version: "not a debian version",
			SourcePackage: "bogus", SourceVersion: "not a debian version",
		},
	}

	got := toTrivyPackages(packages)

	want := []ftypes.Package{
		{Name: "libssl3", Version: "3.0.2", Release: "0ubuntu1.15", SrcName: "openssl", SrcVersion: "3.0.2", SrcRelease: "0ubuntu1.15"},
		{Name: "zlib1g", Version: "1.2.11.dfsg", Epoch: 1, Release: "2ubuntu9.2", SrcName: "zlib", SrcVersion: "1.2.11.dfsg", SrcEpoch: 1, SrcRelease: "2ubuntu9.2"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d (got: %+v)", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("package %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestScannerFor(t *testing.T) {
	cases := []struct {
		osName  string
		wantErr bool
	}{
		{"Ubuntu", false},
		{"Debian GNU/Linux", false},
		{"Fedora", true},
	}
	for _, c := range cases {
		_, err := scannerFor(c.osName)
		if (err != nil) != c.wantErr {
			t.Errorf("scannerFor(%q): err = %v, wantErr = %v", c.osName, err, c.wantErr)
		}
	}
}

// TestMatch_Integration exercises the real trivy-db lookup path against a
// deliberately outdated package version, confirming known CVEs are found
// with a resolved severity. It requires a real vulnerability database
// downloaded via `trivy image --download-db-only` and is skipped otherwise
// — this is real vulnerability data, not something to fixture/fake.
func TestMatch_Integration(t *testing.T) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("resolving cache dir: %v", err)
	}
	dbDir := filepath.Join(cacheDir, "trivy", "db")
	if _, err := os.Stat(filepath.Join(dbDir, "trivy.db")); err != nil {
		t.Skipf("trivy vulnerability DB not found at %s; run `trivy image --download-db-only` to enable this test", dbDir)
	}

	if err := Init(dbDir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer Close()

	host := model.HostInfo{Hostname: "test-host", OSName: "Ubuntu", OSVersionID: "22.04"}
	packages := []model.Package{
		{
			Name: "libssl3", Version: "3.0.2-0ubuntu1.1",
			SourcePackage: "openssl", SourceVersion: "3.0.2-0ubuntu1.1",
		},
	}

	findings, err := Match(context.Background(), host, packages)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for a deliberately outdated openssl, got none")
	}
	for _, f := range findings {
		if f.Host != "test-host" {
			t.Errorf("finding %s: host = %q, want %q", f.CVEID, f.Host, "test-host")
		}
		if f.CVEID == "" {
			t.Errorf("finding has empty CVE ID: %+v", f)
		}
		if f.Severity == "" {
			t.Errorf("finding %s has empty severity", f.CVEID)
		}
	}
}
