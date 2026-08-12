package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"kepler/agent/internal/model"
)

const osReleasePath = "/etc/os-release"

// CollectOSInfo reads OS identity from /etc/os-release and kernel version
// via `uname -r`. Both are plain read-only queries requiring no privileges.
func CollectOSInfo(ctx context.Context) (model.HostInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return model.HostInfo{}, fmt.Errorf("reading hostname: %w", err)
	}

	f, err := os.Open(osReleasePath)
	if err != nil {
		return model.HostInfo{}, fmt.Errorf("opening %s: %w", osReleasePath, err)
	}
	defer f.Close()

	info, err := parseOSRelease(f)
	if err != nil {
		return model.HostInfo{}, fmt.Errorf("parsing %s: %w", osReleasePath, err)
	}
	info.Hostname = hostname

	kernel, err := exec.CommandContext(ctx, "uname", "-r").Output()
	if err != nil {
		return model.HostInfo{}, fmt.Errorf("running uname -r: %w", err)
	}
	info.KernelVersion = strings.TrimSpace(string(kernel))

	return info, nil
}

// parseOSRelease parses the KEY=VALUE format used by /etc/os-release, as
// documented in os-release(5). Values may be double-quoted.
func parseOSRelease(r io.Reader) (model.HostInfo, error) {
	var info model.HostInfo
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "NAME":
			info.OSName = value
		case "VERSION_ID":
			info.OSVersionID = value
		case "PRETTY_NAME":
			info.OSPrettyName = value
		}
	}
	return info, scanner.Err()
}
