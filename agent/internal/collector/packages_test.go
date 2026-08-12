package collector

import (
	"os"
	"testing"

	"kepler/agent/internal/model"
)

func TestParseDpkgQuery(t *testing.T) {
	f, err := os.Open("testdata/dpkg_query.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	got, err := parseDpkgQuery(f)
	if err != nil {
		t.Fatalf("parseDpkgQuery: %v", err)
	}

	want := []model.Package{
		{Name: "adduser", Version: "3.118ubuntu5", Architecture: "all", Source: "dpkg"},
		{Name: "zlib1g", Version: "1:1.2.11.dfsg-2ubuntu9.2", Architecture: "amd64", Source: "dpkg"},
		{Name: "openssl", Version: "3.0.2-0ubuntu1.15", Architecture: "amd64", Source: "dpkg"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d (got: %+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("package %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
