# Security notes

Design decisions and requirements that are easy to silently skip under
deployment pressure, collected here instead of scattered across commit
messages. Kepler itself is a valuable attack target — it maps every
customer's unpatched vulnerabilities — so these aren't optional polish.

## Threat surface

A map from attack vector to the specific thing that stops it, so this is
auditable at a glance rather than requiring a read of every module's
source to answer "what happens if someone tries X."

| Vector | Mitigation |
|---|---|
| SQL injection | Every query across all three modules uses parameterized placeholders (pgx) — no string-built SQL anywhere in the codebase. |
| Plaintext credential storage | API keys are SHA-256 hashed before storage (raw key shown once, never persisted); the dashboard password is bcrypt-hashed. Neither is ever stored or logged in plaintext. |
| Auth timing side-channel | Dashboard Basic Auth runs bcrypt unconditionally whenever credentials are present, regardless of whether the username matches, so a wrong username and a wrong password take the same time to reject (fixed after an earlier version short-circuited on username mismatch, which leaked which usernames were valid via response timing). |
| Cross-host impersonation | An authenticated ingestion request's host identity is resolved server-side from the API key alone, never from anything in the request body — an agent authenticated as one host cannot claim findings for another. |
| Unbounded ingestion requests | Request bodies are capped at 10 MiB (`http.MaxBytesReader`) and batches at 10,000 findings per request — a valid (or leaked) API key can't force an unbounded body or a multi-million-row insert. |
| XSS via finding data | The dashboard uses `html/template`, not `text/template` — context-aware auto-escaping, verified against a literal `<script>` tag injected through finding data, not just assumed to work. |
| Plaintext transport | `kepler-backend` and `kepler-web` both refuse to start over HTTP unless `KEPLER_INSECURE_HTTP=true` is set explicitly — there is no quiet plaintext default. |
| Agent privilege escalation | `kepler-agent` needs no elevated privileges (every collector is a read-only query against already world-readable data) and the recommended production deployment runs it under a `DynamicUser` systemd unit with no standing account — see `agent/README.md`. |
| Database over-privilege | Production deployment uses one least-privilege Postgres role per service (`deploy/db/production-roles-*.sql`) — the dashboard's role, for instance, has `SELECT` only, enforced by Postgres itself. Local dev uses a single shared role for simplicity, a deliberate simplification since it only ever holds disposable test data. |
| Ambiguous "no filter" sentinel | The dashboard's host filter treats an empty string as "no filter." `CreateHost` rejects empty/whitespace-only hostnames so a host can never actually be named `""`, which would otherwise be silently indistinguishable from "show everything." |
| Breaking an existing deployment by adding a feature | `POST /v1/scan-reports` (server-side CVE matching) needs a vulnerability database; `POST /v1/findings` (pre-matched submissions) never did. The backend treats the database as a soft dependency — missing or unreachable, the server still starts and `/v1/findings` keeps working exactly as before; only the new endpoint returns a clear `503`. Adding capability was not allowed to silently raise the bar for what every deployment must now provide. |

## What Kepler does NOT do

- Does not execute code derived from collected data. Every collector shells
  out to a fixed command with fixed arguments (`dpkg-query -W -f <format>`,
  `systemctl list-units --type=service ...`) or reads a fixed file path —
  nothing about *what* a command runs is ever built from package data, a
  hostname, or any other value Kepler doesn't control.
- Does not make outbound network calls to any third party. The only
  outbound connection any service makes is to the Postgres instance an
  operator configures — no telemetry, no external APIs, no phone-home.
- Does not store or transmit API keys or the dashboard password in
  plaintext, anywhere, ever.
- Does not trust client-supplied identity for anything security-relevant —
  see "Cross-host impersonation" above.
- Does not collect file contents, environment variables, command history,
  or any other sensitive data dump — only package name/version and basic
  config state (see the project brief's "don't collect more than needed"
  principle).

## Encryption at rest — required before any real deployment

**Status: not yet applicable. No production infrastructure exists yet.**
This is not a "todo, eventually" note — it's a hard requirement for
whoever provisions the first real Postgres instance, called out now so it
can't be quietly skipped later.

Postgres has no built-in transparent data encryption. "Encrypted at rest"
has to come from the layer underneath it:

- **Managed Postgres (recommended)** — AWS RDS / GCP Cloud SQL / Azure
  Database for PostgreSQL all support storage encryption (KMS-backed,
  AES-256), enabled as a single option at instance creation. It **cannot**
  be turned on retroactively without a snapshot-and-restore into a new
  encrypted instance — it must be enabled at creation time, not patched in
  after the fact.
- **Self-hosted Postgres** — the data directory must sit on an encrypted
  block device or filesystem (e.g. LUKS on Linux, an encrypted cloud disk).

**Local development** (`backend/docker-compose.yml`) holds disposable test
findings, not customer data, and inherits whatever disk encryption the
host machine already has (verified: FileVault is on for this machine).
There's no additional Kepler-specific setup for local dev — building
parallel encrypted-volume infrastructure to protect throwaway test data
would be effort spent on the wrong risk. If you're setting up local dev
on a machine without full-disk encryption, turn that on first.

## Agent ↔ backend auth: API-key, not mTLS (v1)

Chosen deliberately over mTLS for v1: mTLS is stronger (no shared secret
to leak) but requires certificate issuance, rotation, and revocation
infrastructure before the ingestion endpoint could even be tested —
significant scope for a product with no real customers yet.

Mitigations: one key per host (not a shared secret), keys are hashed at
rest (never stored plaintext), a dedicated `api_keys` table makes
rotation/revocation a day-one capability rather than a later rewrite, and
TLS is required by default on `kepler-backend`.

**Revisit before this handles real customer data** — mTLS remains the
stronger option long-term.

## Dashboard auth: single operator credential (v1)

`kepler-web` uses HTTP Basic Auth against one bcrypt-hashed
username/password, not per-user accounts. Deliberate for v1: there's no
multi-tenant/multi-user model yet, so a shared operator credential is
proportionate. TLS is required by default here too, since Basic Auth
credentials are only as safe as the transport carrying them.

**Revisit before this needs to support more than one real operator.**

## What's already enforced, not just documented

- `kepler-agent` runs read-only against scanned hosts — no write access.
- `kepler-agent` needs no elevated privileges to run — every collector is
  a read-only query against something already world-readable (`dpkg-query`,
  `systemctl list-units`, `/proc/net/*`, `/etc/os-release`). See
  [`agent/README.md`](agent/README.md) for the deployment pattern (a
  dedicated non-root systemd user) that actually puts this into practice.
- Both `kepler-backend` and `kepler-web` refuse to start over plaintext
  HTTP unless `KEPLER_INSECURE_HTTP=true` is set explicitly.
- All SQL is parameterized (no string-built queries) across every
  service.
- `kepler-web`'s templates use `html/template` (auto-escaping), verified
  against a literal `<script>` tag in finding data, not just assumed.
- `kepler-agent`'s network reporting verifies the backend's TLS certificate
  by default; skipping verification requires explicitly setting
  `KEPLER_INSECURE_SKIP_VERIFY=true`, logged as a warning, same pattern as
  every other insecure-override in this codebase.
- `kepler-backend` degrades gracefully, not catastrophically, when its
  vulnerability database is missing — see the threat surface table's
  "breaking an existing deployment by adding a feature" row. Verified by a
  real test (`TestScanReports_UnavailableWithoutDB`), not just asserted.
