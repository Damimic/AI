package collector

import (
	"os"
	"testing"

	"kepler/agent/internal/model"
)

func TestParseProcNetTCP(t *testing.T) {
	f, err := os.Open("testdata/proc_net_tcp.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	got, err := parseProcNet(f, "tcp")
	if err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}

	want := []model.Port{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 22, State: "LISTEN"},
		{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 80, State: "LISTEN"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d ports, want %d (got: %+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("port %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseProcNetUDP(t *testing.T) {
	f, err := os.Open("testdata/proc_net_udp.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	got, err := parseProcNet(f, "udp")
	if err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}

	want := []model.Port{
		{Protocol: "udp", LocalAddress: "0.0.0.0", LocalPort: 68},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d ports, want %d (got: %+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("port %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDecodeHexIP(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
	}
	for _, c := range cases {
		ip, err := decodeHexIP(c.hex)
		if err != nil {
			t.Fatalf("decodeHexIP(%q): %v", c.hex, err)
		}
		if ip.String() != c.want {
			t.Errorf("decodeHexIP(%q) = %s, want %s", c.hex, ip.String(), c.want)
		}
	}
}
