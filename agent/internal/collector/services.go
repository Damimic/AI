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

// CollectServices lists currently running systemd services via
// `systemctl list-units`, a read-only query requiring no root privileges.
func CollectServices(ctx context.Context) ([]model.Service, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "list-units",
		"--type=service", "--state=running", "--no-legend", "--no-pager", "--plain")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running systemctl list-units: %w", err)
	}
	return parseServiceUnits(strings.NewReader(string(out)))
}

// parseServiceUnits parses `systemctl list-units --no-legend --plain` output:
// whitespace-separated UNIT LOAD ACTIVE SUB, followed by a free-text
// DESCRIPTION that fills the rest of the line.
func parseServiceUnits(r io.Reader) ([]model.Service, error) {
	var services []model.Service
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		services = append(services, model.Service{
			Name:        fields[0],
			ActiveState: fields[2],
			SubState:    fields[3],
			Description: strings.Join(fields[4:], " "),
		})
	}
	return services, scanner.Err()
}
