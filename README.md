# Kepler

Kepler is a vulnerability scanning product for SMBs and compliance-conscious
organizations. A lightweight agent installs on customer infrastructure,
collects package/version/config data locally, and reports findings to a
hosted backend that matches against CVE feeds and surfaces results via a
dashboard with severity scoring and alerting.

## Repo layout

- [`agent/`](agent/) — Linux collection agent (Go). Currently: package,
  OS/kernel, service, and open-port collection. Not yet: CVE matching,
  backend reporting.
- [`backend/`](backend/) — not started yet. Will provide the ingestion API
  and Postgres-backed findings store.
- [`web/`](web/) — not started yet. Will provide the findings dashboard and
  the marketing/waitlist landing page.

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
