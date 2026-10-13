# Kepler

Kepler is a vulnerability scanning product for SMBs and compliance-conscious
organizations. A lightweight agent installs on customer infrastructure,
collects package/version/config data locally, and reports findings to a
hosted backend that matches against CVE feeds and surfaces results via a
dashboard with severity scoring and alerting.

## Repo layout

- [`agent/`](agent/) — Linux collection agent (Go, zero third-party
  dependencies). Collects packages, OS/kernel, services, open ports
  (`kepler-agent`), then either prints the report or reports it over the
  network to the backend.
- [`backend/`](backend/) — findings ingestion API + Postgres store.
  API-key-authenticated. `POST /v1/scan-reports` does CVE matching
  server-side (via an embedded Trivy database) — what a live agent uses;
  `POST /v1/findings` accepts pre-matched findings for manual/offline use.
  No dashboard/query endpoints yet.
- [`web/`](web/) — findings dashboard (Basic-Auth-protected, filterable by
  host/severity) and the marketing/waitlist landing page. Two independent
  services with separate databases — a compromised public signup form has
  no path to findings data.
- [`frontend/`](frontend/) — the dashboard and landing page as a real UI
  (React/TypeScript/Vite), on top of the same two Go services above —
  see [ARCHITECTURE.md](ARCHITECTURE.md)'s "Serving the frontend" for how
  a public SPA and an authenticated dashboard coexist in one build.
- [`integration/`](integration/) — one end-to-end test that drives the real
  `kepler-backend` and `kepler-web` binaries as subprocesses over real
  HTTPS: ingests a findings payload with a real API key, then confirms it
  renders on the dashboard. Proves the seam between services, not just each
  one in isolation.
- [`deploy/`](deploy/) — production systemd units (including a timer for
  unattended agent reporting), an agent install script, a certbot renewal
  hook, and least-privilege Postgres roles for a real deployment. See
  [DEPLOYMENT.md](DEPLOYMENT.md) for the full runbook.

## Status

v1's core technical scope is built: agent → CVE matching → backend →
dashboard, plus the marketing/waitlist site, all verified working
end-to-end against real data. CI (`.github/workflows/ci.yml`) builds,
vets, and runs the test suite for all three modules plus the end-to-end
integration test — including the Postgres-backed store/API tests — on
every push and pull request. No AI assistant, compliance reporting, audit
log, billing, or multi-OS support yet — see the project brief for full
scope.

Everything so far has run locally (`localhost`, self-signed certs). CVE
matching moved from the agent to the backend, so a real `kepler-agent` can
now collect and report automatically on a schedule — see
[`deploy/install-agent.sh`](deploy/install-agent.sh) — with no manual
matching step in between. [DEPLOYMENT.md](DEPLOYMENT.md) is the runbook
for a real deployment — real domain, real Let's Encrypt certs, real
(encrypted) Postgres — not yet exercised against actual infrastructure.

## Security principles

These apply from the first line of code, not added later. See
[SECURITY.md](SECURITY.md) for the reasoning behind specific tradeoffs
(API-key vs mTLS, dashboard auth, encryption at rest).

- The agent only ever needs read access to scanned systems, never write
  access to production.
- Data is encrypted in transit (TLS, enforced by default on every service).
  Encryption at rest applies once real infrastructure exists — see
  SECURITY.md for why that's a deployment-layer decision, not something
  local dev can meaningfully implement yet.
- Collection is minimal: package name/version and config state only, never
  full file contents or sensitive data dumps.
- Agent↔backend auth and backend access control are first-class design
  concerns, because Kepler itself becomes an attack target — it maps every
  customer's unpatched vulnerabilities.
