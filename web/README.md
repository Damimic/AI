# web

Findings dashboard: a single Basic-Auth-protected page listing findings,
filterable by host and severity. Read-only — all writes happen through
`backend`'s ingestion API. The marketing/waitlist landing page hasn't been
built yet.

## Components

- `cmd/kepler-web` — the dashboard server.
- `cmd/kepler-web-admin` — `hash-password` generates the bcrypt hash
  `kepler-web` needs for `KEPLER_DASHBOARD_PASSWORD_HASH`.
- `internal/store` — read-only Postgres queries (no writes; ingestion is
  `backend`'s job).
- `internal/auth` — HTTP Basic Auth against a single operator credential.
- `internal/handlers`, `internal/templates`, `internal/api` — the HTTP
  layer and the findings-list page itself.

## Auth model

A single operator username/password (env-configured), checked via HTTP
Basic Auth, password bcrypt-hashed. Deliberately minimal for v1 — no user
accounts, no multi-tenancy, consistent with the rest of v1's scope. Revisit
before this needs to support multiple real operators.

TLS is **required by default**, same rule as `backend`: this shows
security-sensitive data (a customer's unpatched vulnerabilities), and Basic
Auth credentials are only as safe as the transport carrying them.

## Local development

Assumes `backend`'s local Postgres is already running (`docker compose up
-d` in `backend/`) and has some findings in it (see `backend/README.md`).

1. Generate a dashboard password hash:
   ```
   go run ./cmd/kepler-web-admin hash-password
   ```
2. Run the server (reusing backend's dev TLS cert, or generate your own
   with `backend/scripts/gen-dev-cert.sh`):
   ```
   KEPLER_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler" \
   KEPLER_DASHBOARD_USER="operator" \
   KEPLER_DASHBOARD_PASSWORD_HASH="<hash from step 1>" \
   KEPLER_TLS_CERT=../backend/dev-certs/dev.crt \
   KEPLER_TLS_KEY=../backend/dev-certs/dev.key \
   go run ./cmd/kepler-web
   ```
3. Visit `https://localhost:8444/` (self-signed dev cert — your browser
   will warn, that's expected locally).

## Tests

Same convention as `backend`: store tests run against a real local
Postgres, skipped cleanly if `KEPLER_TEST_DB_URL` isn't set.

```
KEPLER_TEST_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler" go test ./...
```
