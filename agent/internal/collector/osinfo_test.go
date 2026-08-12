package collector

import (
	"os"
	"testing"

	"kepler/agent/internal/model"
)

func TestParseOSRelease(t *testing.T) {
	f, err := os.Open("testdata/os_release.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	got, err := parseOSRelease(f)
	if err != nil {
		t.Fatalf("parseOSRelease: %v", err)
	}

	want := model.HostInfo{
		OSName:       "Ubuntu",
		OSVersionID:  "22.04",
		OSPrettyName: "Ubuntu 22.04.3 LTS",
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
