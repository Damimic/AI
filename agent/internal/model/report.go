// Package model defines the data shapes produced by collectors and emitted
// as the agent's scan report.
package model

import "time"

// ScanReport is the full output of a single agent run on a host.
type ScanReport struct {
	Host        HostInfo  `json:"host"`
	CollectedAt time.Time `json:"collected_at"`
	Packages    []Package `json:"packages"`
	Services    []Service `json:"services"`
	Ports       []Port    `json:"ports"`
}

// HostInfo identifies the scanned host and its OS/kernel.
type HostInfo struct {
	Hostname      string `json:"hostname"`
	OSName        string `json:"os_name"`        // e.g. "Ubuntu"
	OSVersionID   string `json:"os_version_id"`  // e.g. "22.04"
	OSPrettyName  string `json:"os_pretty_name"` // e.g. "Ubuntu 22.04.3 LTS"
	KernelVersion string `json:"kernel_version"` // e.g. "5.15.0-91-generic"
}

// Package is a single installed package and its version, as reported by the
// host's package manager.
type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
	Source       string `json:"source"` // package manager that reported it, e.g. "dpkg"

	// SourcePackage and SourceVersion identify the source package this
	// binary package was built from (e.g. binary "libssl3" comes from
	// source "openssl"). Distro CVE advisories are keyed by source package
	// name, not binary package name, so this is required for accurate CVE
	// matching. dpkg defaults both to the binary package's own name/version
	// when a package has no separate source package.
	SourcePackage string `json:"source_package"`
	SourceVersion string `json:"source_version"`
}

// Service is a systemd service the collector observed as active.
type Service struct {
	Name        string `json:"name"` // unit name, e.g. "nginx.service"
	Description string `json:"description"`
	ActiveState string `json:"active_state"` // e.g. "active"
	SubState    string `json:"sub_state"`    // e.g. "running"
}

// Port is a listening (or otherwise open) network port observed on the host.
type Port struct {
	Protocol     string `json:"protocol"` // "tcp" or "udp"
	LocalAddress string `json:"local_address"`
	LocalPort    uint16 `json:"local_port"`
	State        string `json:"state,omitempty"` // e.g. "LISTEN" (tcp only)
}
