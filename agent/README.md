# agent

Linux-only collection agent. `kepler-agent` collects installed
packages/versions, OS/kernel version, running services, and open ports from
the local host and prints a structured JSON scan report — no network
reporting yet (that happens once its output is piped into `kepler-matcher`
and on to `backend`'s ingestion API).

`kepler-matcher` is separate: it matches a scan report against CVEs via an
embedded Trivy database. It's Kepler's own tooling, run wherever findings
are matched — not deployed to customer hosts alongside `kepler-agent`.

## Components

- `cmd/kepler-agent` — runs all four collectors, prints a `ScanReport` as
  JSON to stdout.
- `cmd/kepler-matcher` — reads a `ScanReport` and matches it against a
  local Trivy vulnerability database (`trivy image --download-db-only`
  first; see `internal/matcher`'s package comment).
- `internal/collector` — one file per data source: `packages.go` (dpkg),
  `osinfo.go` (`/etc/os-release`, `uname -r`), `services.go` (systemd),
  `ports.go` (`/proc/net/{tcp,udp}[6]`).
- `internal/model` — `ScanReport` (collection output) and `Finding`
  (matching output) shapes.

## Privilege model

`kepler-agent` needs **no elevated privileges** — every collector is a
read-only query against something already world-readable on a standard
Linux host:

- **Packages** — `dpkg-query -W`, a read-only query against `/var/lib/dpkg`
  (world-readable by default).
- **OS/kernel info** — reads `/etc/os-release` and runs `uname -r`; both
  are plain, unprivileged reads.
- **Services** — `systemctl list-units`, a read-only status query. Systemd
  exposes this over D-Bus with a policy that allows any local user to read
  unit status; it does not require root.
- **Ports** — reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`,
  `/proc/net/udp6` directly; these are world-readable procfs entries.

Nothing here writes to the host, opens a listening socket, or reads
anything outside these four sources — see [`../SECURITY.md`](../SECURITY.md)
for the broader "why" (an unpatched-vulnerability inventory is itself an
attractive attack target, so the agent's own footprint has to stay
minimal).

## Deploying as a dedicated non-root user

Because nothing above needs root, `kepler-agent` should run as a dedicated,
unprivileged system user in production — this is a deployment choice, not
something the binary enforces on its own, so it's the operator's
responsibility to wire up. Recommended `systemd` unit:

```ini
[Unit]
Description=Kepler vulnerability scanning agent
After=network.target

[Service]
Type=oneshot
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ExecStart=/usr/local/bin/kepler-agent
```

`DynamicUser=yes` allocates a throwaway, unprivileged UID for each run with
no shell, no home directory, and no standing account to compromise —
stronger than a static service account for a workload that doesn't need
persistent state. `ProtectSystem=strict` and `ProtectHome=yes` make the
rest of the filesystem read-only to the process even though it's already
not attempting to write anywhere.

## Local development

```
go build ./cmd/kepler-agent
./kepler-agent
```

Requires a real Linux host (or VM/container with systemd active) — the
collectors shell out to `dpkg-query` and `systemctl` and read Linux-only
procfs paths, so this doesn't run on macOS or Windows dev machines. Cross-compiles
cleanly from any OS for a Linux target:

```
GOOS=linux GOARCH=amd64 go build -o kepler-agent-linux ./cmd/kepler-agent
```

## Tests

```
go test ./...
```

`matcher`'s integration test (`TestMatch_Integration`) skips cleanly if a
Trivy vulnerability database isn't present locally — see its skip message
for how to fetch one.
