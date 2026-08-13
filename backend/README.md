# backend

Findings ingestion API: receives CVE findings (produced by `kepler-matcher`)
over authenticated HTTPS and stores them in Postgres.

## Components

- `cmd/kepler-backend` — the API server. `POST /v1/findings` (authenticated)
  is the only endpoint so far. No dashboard/query endpoints yet.
- `cmd/kepler-backend-admin` — provisions hosts (`create-host <hostname>`),
  since there's no self-service enrollment flow yet. Prints a one-time API
  key that isn't stored anywhere else — save it, it can't be recovered.
- `internal/store` — Postgres access (plain SQL via pgx, no ORM).
- `internal/auth` — API key generation/hashing.
- `internal/api` — HTTP routing, auth middleware, the ingestion handler.
- `db/schema.sql` — the schema. Applied manually for now (see below); no
  migration tooling yet since the schema doesn't need to evolve across
  environments at this stage.

## Auth model

Each host has its own API key, sent as `Authorization: Bearer <key>`. Only
a hash of the key is ever stored. The backend resolves which host a request
is acting on **from the authenticated key**, never from anything in the
request body — this is deliberate: it's what stops an authenticated agent
for one host from being able to claim to be another.

This is API-key auth, not mTLS — a conscious v1 tradeoff (see the top-level
project history/commit messages for the reasoning). The schema (one key per
host, a dedicated `api_keys` table supporting rotation/revocation) is built
so mTLS could be added later without a rewrite, not because API-key auth is
considered a finished, permanent answer.

TLS is **required by default** — `kepler-backend` refuses to start without
`KEPLER_TLS_CERT`/`KEPLER_TLS_KEY` unless `KEPLER_INSECURE_HTTP=true` is set
explicitly. Findings are security-sensitive data; there's no quiet plaintext
default.

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
4. Run the server:
   ```
   KEPLER_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler" \
   KEPLER_TLS_CERT=dev-certs/dev.crt \
   KEPLER_TLS_KEY=dev-certs/dev.key \
   go run ./cmd/kepler-backend
   ```
5. Provision a host in another terminal:
   ```
   KEPLER_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler" \
   go run ./cmd/kepler-backend-admin create-host my-test-host
   ```
6. Feed it findings, e.g. from the agent + matcher pipeline:
   ```
   kepler-agent | kepler-matcher | <reshape into {"findings": [...]}> | \
   curl -k -X POST https://localhost:8443/v1/findings \
     -H "Authorization: Bearer <api_key from step 5>" \
     -d @-
   ```

## Tests

Store and API tests run against a real local Postgres, not a mock — for a
security product, the actual SQL and the actual auth-rejection paths are
what need verifying. Tests skip cleanly if `KEPLER_TEST_DB_URL` isn't set.

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
