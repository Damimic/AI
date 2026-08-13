# Kepler

Kepler is a vulnerability scanning product for SMBs and compliance-conscious
organizations. A lightweight agent installs on customer infrastructure,
collects package/version/config data locally, and reports findings to a
hosted backend that matches against CVE feeds and surfaces results via a
dashboard with severity scoring and alerting.

## Repo layout

- [`agent/`](agent/) — Linux collection agent (Go). Collects packages,
  OS/kernel, services, open ports (`kepler-agent`), and matches them
  against CVEs via an embedded Trivy database (`kepler-matcher`, run as
  Kepler's own tooling, not deployed to customer hosts).
- [`backend/`](backend/) — findings ingestion API + Postgres store.
  API-key-authenticated `POST /v1/findings`. No dashboard/query endpoints
  yet.
- [`web/`](web/) — findings dashboard (Basic-Auth-protected, filterable by
  host/severity). The marketing/waitlist landing page hasn't been built
  yet.

## Status

v1 is in progress. See the project brief for full scope — in short: Linux-only
agent, CVE matching via an existing engine (not built from scratch), a minimal
authenticated backend, and a plain findings dashboard. No AI assistant,
compliance reporting, audit log, billing, or multi-OS support yet.

## Security principles

These apply from the first line of code, not added later:

- The agent only ever needs read access to scanned systems, never write
  access to production.
- Data is encrypted in transit (TLS) and at rest.
- Collection is minimal: package name/version and config state only, never
  full file contents or sensitive data dumps.
- Agent↔backend auth and backend access control are first-class design
  concerns, because Kepler itself becomes an attack target — it maps every
  customer's unpatched vulnerabilities.
