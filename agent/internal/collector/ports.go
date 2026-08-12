package collector

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"kepler/agent/internal/model"
)

const (
	tcpStateListen = "0A"
	udpStateUnconn = "07"
)

var procNetFiles = []struct {
	path     string
	protocol string
}{
	{"/proc/net/tcp", "tcp"},
	{"/proc/net/tcp6", "tcp"},
	{"/proc/net/udp", "udp"},
	{"/proc/net/udp6", "udp"},
}

// CollectPorts reads /proc/net/{tcp,tcp6,udp,udp6} to find listening (tcp)
// and bound (udp) ports. This requires no elevated privileges: any process
// can read these files. Ownership (which process holds a given socket) is
// only visible to that process's own user or root, so we deliberately don't
// attempt process attribution here — only that the port is open, which is
// enough for CVE-relevant exposure and keeps collection strictly read-only
// and low-privilege.
func CollectPorts() ([]model.Port, error) {
	var ports []model.Port
	for _, f := range procNetFiles {
		file, err := os.Open(f.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // e.g. IPv6 disabled on this host
			}
			return nil, fmt.Errorf("opening %s: %w", f.path, err)
		}
		parsed, err := parseProcNet(file, f.protocol)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f.path, err)
		}
		ports = append(ports, parsed...)
	}
	return ports, nil
}

// parseProcNet parses one /proc/net/{tcp,tcp6,udp,udp6} file. For tcp, only
// sockets in LISTEN state are returned. udp has no listen state, so bound
// (UNCONN) sockets are returned instead — that's the udp equivalent of "open".
func parseProcNet(r io.Reader, protocol string) ([]model.Port, error) {
	var ports []model.Port
	scanner := bufio.NewScanner(r)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // header line
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddr := fields[1] // "ADDR:PORT", both hex
		state := fields[3]

		if protocol == "tcp" && state != tcpStateListen {
			continue
		}
		if protocol == "udp" && state != udpStateUnconn {
			continue
		}

		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) != 2 {
			continue
		}
		ip, err := decodeHexIP(addrParts[0])
		if err != nil {
			continue
		}
		portNum, err := strconv.ParseUint(addrParts[1], 16, 16)
		if err != nil {
			continue
		}

		p := model.Port{
			Protocol:     protocol,
			LocalAddress: ip.String(),
			LocalPort:    uint16(portNum),
		}
		if protocol == "tcp" {
			p.State = "LISTEN"
		}
		ports = append(ports, p)
	}
	return ports, scanner.Err()
}

// decodeHexIP decodes the per-32-bit-word, host-byte-order hex address
// format used by /proc/net/{tcp,tcp6,udp,udp6} into a net.IP. On the
// little-endian hosts Kepler targets, each 4-byte word is stored reversed.
func decodeHexIP(hexAddr string) (net.IP, error) {
	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw)%4 != 0 {
		return nil, fmt.Errorf("unexpected address length %d", len(raw))
	}
	ip := make([]byte, len(raw))
	for word := 0; word < len(raw); word += 4 {
		for b := 0; b < 4; b++ {
			ip[word+b] = raw[word+3-b]
		}
	}
	return net.IP(ip), nil
}
