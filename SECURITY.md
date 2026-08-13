# Security notes

Design decisions and requirements that are easy to silently skip under
deployment pressure, collected here instead of scattered across commit
messages. Kepler itself is a valuable attack target — it maps every
customer's unpatched vulnerabilities — so these aren't optional polish.

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
