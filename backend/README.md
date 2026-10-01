# backend

Findings ingestion API. Two ways in, both authenticated the same way:

- `POST /v1/scan-reports` — a host's raw collected package data; the
  backend matches it against CVEs itself and stores the result. This is
  what a live `kepler-agent` uses (see `agent/README.md`).
- `POST /v1/findings` — pre-matched findings, stored as-is. Kept for
  manual/offline submissions and debugging; a live agent doesn't need it.

## Components

- `cmd/kepler-backend` — the API server.
- `cmd/kepler-backend-admin` — provisions hosts (`create-host <hostname>`),
  since there's no self-service enrollment flow yet. Prints a one-time API
  key that isn't stored anywhere else — save it, it can't be recovered.
- `cmd/kepler-matcher` — offline debug tool: feed it a scan-report-shaped
  JSON file on stdin, see what would match, without a live backend or
  database connection. Not what a live agent uses — that happens
  automatically inside `kepler-backend` itself.
- `internal/store` — Postgres access (plain SQL via pgx, no ORM).
- `internal/auth` — API key generation/hashing.
- `internal/matcher` — CVE matching via an embedded Trivy database. Moved
  here from the agent module — it only ever ran as separate tooling, never
  on a customer host, so it belongs wherever it's actually managed in
  production: here, as part of handling `POST /v1/scan-reports`.
- `internal/api` — HTTP routing, auth middleware, both ingestion handlers.
- `db/schema.sql` — the schema. Applied manually for now (see below); no
  migration tooling yet since the schema doesn't need to evolve across
  environments at this stage.

## Auth model

Each host has its own API key, sent as `Authorization: Bearer <key>`. Only
a hash of the key is ever stored. The backend resolves which host a request
is acting on **from the authenticated key**, never from anything in the
request body — this is deliberate: it's what stops an authenticated agent
for one host from being able to claim to be another. Neither endpoint's
request body even has a field for host identity.

This is API-key auth, not mTLS — a conscious v1 tradeoff (see the top-level
project history/commit messages for the reasoning). The schema (one key per
host, a dedicated `api_keys` table supporting rotation/revocation) is built
so mTLS could be added later without a rewrite, not because API-key auth is
considered a finished, permanent answer.

TLS is **required by default** — `kepler-backend` refuses to start without
`KEPLER_TLS_CERT`/`KEPLER_TLS_KEY` unless `KEPLER_INSECURE_HTTP=true` is set
explicitly. Findings are security-sensitive data; there's no quiet plaintext
default.

## The vulnerability database is a soft dependency, not a hard one

`kepler-backend` tries to open a Trivy vulnerability database at startup
(`KEPLER_TRIVY_DB_DIR`, defaulting to the same cache location the `trivy`
CLI itself uses). If that fails — not configured, or the database doesn't
exist yet — the server **still starts**, logs a warning, and
`POST /v1/findings` keeps working exactly as before. Only
`POST /v1/scan-reports` is affected: it returns a clear `503` instead of
attempting to match against nothing. This is deliberate backward
compatibility — an existing deployment that only ever used
`/v1/findings` must not break just because this endpoint was added.

**Only one process can have the database open at a time** — it's an
embedded single-writer store (bbolt), not a server you connect to. Running
`kepler-matcher` (the debug CLI) against the same `KEPLER_TRIVY_DB_DIR`
while `kepler-backend` is already running against it will fail to open —
stop the backend first, or point the CLI at a separate copy of the
database.

To actually enable scan-report matching, populate the database once
(`trivy image --download-db-only`) and keep it refreshed — new CVEs are
published continuously, so this needs a periodic job, not a one-time
setup step. See `DEPLOYMENT.md` for the production setup.

## Local development

1. Start Postgres:
   ```
   docker compose up -d
   ```
2. Apply the schema:
   ```
   docker compose exec -T postgres psql -U kepler -d kepler -f - < db/schema.sql
   ```
3. Generate a local dev TLS cert (self-signed, gitignored, dev-only —
   production needs a cert from a real CA):
   ```
   ./scripts/gen-dev-cert.sh
   ```
4. (Optional, needed for `/v1/scan-reports`) Fetch a vulnerability
   database: `trivy image --download-db-only`.
5. Run the server:
   ```
   KEPLER_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler" \
   KEPLER_TLS_CERT=dev-certs/dev.crt \
   KEPLER_TLS_KEY=dev-certs/dev.key \
   go run ./cmd/kepler-backend
   ```
6. Provision a host in another terminal:
   ```
   KEPLER_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler" \
   go run ./cmd/kepler-backend-admin create-host my-test-host
   ```
7. Feed it a scan report (this is what a real `kepler-agent` sends; the
   backend does the matching):
   ```
   curl -k -X POST https://localhost:8443/v1/scan-reports \
     -H "Authorization: Bearer <api_key from step 6>" \
     -d '{"host":{"os_name":"Ubuntu","os_version_id":"22.04"},"packages":[{"name":"libssl3","version":"3.0.2-0ubuntu1.1","source_package":"openssl","source_version":"3.0.2-0ubuntu1.1"}]}'
   ```
   Or, for pre-matched findings instead:
   ```
   curl -k -X POST https://localhost:8443/v1/findings \
     -H "Authorization: Bearer <api_key from step 6>" \
     -d '{"findings":[{"package":"openssl","version":"1.1.1f","cve_id":"CVE-2023-0286","severity":"HIGH"}]}'
   ```

## Tests

Store and API tests run against a real local Postgres, not a mock — for a
security product, the actual SQL and the actual auth-rejection paths are
what need verifying. Tests skip cleanly if `KEPLER_TEST_DB_URL` isn't set.
The scan-report matching integration test additionally skips cleanly if no
vulnerability database is present locally, same convention as
`internal/matcher`'s own test.

**Point this at a dedicated `kepler_test` database, not the `kepler` dev
database above.** Tests insert real, permanent rows and don't clean up
after themselves (they rely on random suffixes to avoid collisions between
runs, not transaction rollback) — pointed at your dev database, every test
run permanently pollutes whatever you're looking at in the dashboard.

One-time setup:
```
docker compose exec -T postgres psql -U kepler -d kepler -c "CREATE DATABASE kepler_test;"
docker compose exec -T postgres psql -U kepler -d kepler_test -f - < db/schema.sql
```

Then:
```
KEPLER_TEST_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler_test" go test ./...
```
