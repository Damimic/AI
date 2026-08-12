package collector

import (
	"os"
	"testing"

	"kepler/agent/internal/model"
)

func TestParseServiceUnits(t *testing.T) {
	f, err := os.Open("testdata/systemctl_units.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	got, err := parseServiceUnits(f)
	if err != nil {
		t.Fatalf("parseServiceUnits: %v", err)
	}

	want := []model.Service{
		{Name: "cron.service", ActiveState: "active", SubState: "running", Description: "Regular background program processing daemon"},
		{Name: "nginx.service", ActiveState: "active", SubState: "running", Description: "A high performance web server and a reverse proxy server"},
		{Name: "ssh.service", ActiveState: "active", SubState: "running", Description: "OpenBSD Secure Shell server"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d services, want %d (got: %+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("service %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
