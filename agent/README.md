# agent

Linux-only collection agent, and genuinely dependency-free (stdlib only —
`go.sum` is empty). `kepler-agent` collects installed packages/versions,
OS/kernel version, running services, and open ports from the local host.

CVE matching no longer happens here — it used to (via an embedded Trivy
database), but that pulled in a sizeable dependency tree for a binary meant
to stay minimal, and matching only ever ran as separate offline tooling
anyway, never on a customer host. It now lives in
[`../backend/internal/matcher`](../backend/internal/matcher), run
automatically as part of handling `POST /v1/scan-reports`. See that
module's README for the operational side (the backend now needs its own
vulnerability database).

## Reporting modes

- **Default**: prints the scan report as JSON to stdout. Useful for local
  debugging or piping into something else.
- **Network reporting**: when `KEPLER_BACKEND_URL` and `KEPLER_API_KEY` are
  both set, POSTs the report to `<KEPLER_BACKEND_URL>/v1/scan-reports`
  instead, authenticated with the key, and prints a one-line confirmation
  to stderr. This is the production mode — see
  [`../deploy/install-agent.sh`](../deploy/install-agent.sh) and
  [`../deploy/systemd/kepler-agent.timer`](../deploy/systemd/kepler-agent.timer)
  for running it unattended on a schedule.

`KEPLER_INSECURE_SKIP_VERIFY=true` disables TLS certificate verification
on the reporting connection — for testing against a self-signed dev cert
only, same explicit-override pattern as the backend's own
`KEPLER_INSECURE_HTTP`. Never use this against a real deployment.

## Components

- `cmd/kepler-agent` — runs all four collectors, then either prints the
  resulting `ScanReport` (stdout mode) or POSTs it (network mode).
- `internal/collector` — one file per data source: `packages.go` (dpkg),
  `osinfo.go` (`/etc/os-release`, `uname -r`), `services.go` (systemd),
  `ports.go` (`/proc/net/{tcp,udp}[6]`).
- `internal/model` — the `ScanReport` shape collection produces.

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

Reporting adds one more thing: an outbound HTTPS connection to the
configured backend URL, carrying only the collected `ScanReport` and the
API key. Nothing here writes to the host, opens a listening socket, or
reads anything outside the four sources above — see
[`../SECURITY.md`](../SECURITY.md) for the broader "why" (an
unpatched-vulnerability inventory is itself an attractive attack target,
so the agent's own footprint has to stay minimal).

## Onboarding a host (recommended path)

1. An operator provisions the host and gets an API key:
   `kepler-backend-admin create-host <hostname>` (run against the
   backend — see `backend/README.md`).
2. Cross-compile the agent and copy it to the target host, alongside
   `deploy/install-agent.sh` and `deploy/systemd/`:
   ```
   GOOS=linux GOARCH=amd64 go build -o kepler-agent ./cmd/kepler-agent
   scp kepler-agent ../deploy/install-agent.sh -r ../deploy/systemd <host>:~/
   ```
3. On the target host: `sudo ./install-agent.sh <backend-url> <api-key>`.
   This installs the binary, writes the (root-only) env file with the
   backend URL and key, installs the systemd service and timer, and runs
   one report immediately so you know right away whether it worked.

No self-service enrollment flow yet (matches `backend/README.md`'s own
scope note) — an operator provisions each host, same as today, just
without the previously-manual "build a binary, copy it over, hand-write a
unit file" steps per host.

### Manual setup (what the install script automates)

If you'd rather not run the script: build the binary, copy
[`../deploy/systemd/kepler-agent.service`](../deploy/systemd/kepler-agent.service)
and
[`../deploy/systemd/kepler-agent.timer`](../deploy/systemd/kepler-agent.timer)
to `/etc/systemd/system/`, write `/etc/kepler/agent.env` (mode 600) with
`KEPLER_BACKEND_URL` and `KEPLER_API_KEY`, then
`systemctl enable --now kepler-agent.timer`.

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
procfs paths, so this doesn't run on macOS or Windows dev machines.
Cross-compiles cleanly from any OS for a Linux target:

```
GOOS=linux GOARCH=amd64 go build -o kepler-agent-linux ./cmd/kepler-agent
```

## Tests

```
go test ./...
```

The reporting logic (`reportToBackend`) is plain `net/http` code with no
OS dependency, so it's tested with a fake server (`cmd/kepler-agent`'s own
test file) — that part runs and passes on any OS, including whatever this
is being developed on. Only collection itself needs a real Linux host.
