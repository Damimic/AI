# web

Two independent services:

- The **findings dashboard** (`kepler-web`) — a single Basic-Auth-protected
  page listing findings, filterable by host and severity. Read-only — all
  writes happen through `backend`'s ingestion API.
- The **marketing site** (`kepler-landing`) — a public landing page with a
  waitlist signup form. No auth (it's meant to be public), and its own
  database, separate from the findings database.

They don't share a database or a store package on purpose — a compromised
or abused public signup form should have no path to customer vulnerability
data.

## Components

- `cmd/kepler-web` — the dashboard server.
- `cmd/kepler-web-admin` — `hash-password` generates the bcrypt hash
  `kepler-web` needs for `KEPLER_DASHBOARD_PASSWORD_HASH`.
- `cmd/kepler-landing` — the marketing site + waitlist server.
- `internal/store` — read-only findings queries (dashboard only).
- `internal/waitlist` — waitlist signups (landing site only; no import path
  to `internal/store`, and never should have one).
- `internal/auth` — HTTP Basic Auth for the dashboard.
- `internal/handlers`, `internal/templates`, `internal/api` — the HTTP
  layer for both services.
- `db/waitlist_schema.sql` — schema for the separate `kepler_marketing`
  database.

## Auth model

**Dashboard**: a single operator username/password (env-configured),
checked via HTTP Basic Auth, password bcrypt-hashed. Deliberately minimal
for v1 — no user accounts, no multi-tenancy. Revisit before this needs to
support multiple real operators.

**Landing site**: no auth — it's public by design. Anti-abuse is a hidden
honeypot field on the signup form, not a CAPTCHA: real users never fill it
in, so a naive bot that autofills every field trips it, and the submission
is silently discarded (not confirmed to the bot as rejected).

TLS is **required by default** on both services — the dashboard shows
security-sensitive data, and even the public landing site shouldn't collect
email addresses over plaintext HTTP as a quiet default.

## Local development

Assumes `backend`'s local Postgres is already running (`docker compose up
-d` in `backend/`).

### Dashboard

Needs findings in the database already (see `backend/README.md`).

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

### Landing site

1. Create the marketing database and apply its schema (once):
   ```
   docker compose -f ../backend/docker-compose.yml exec -T postgres \
     psql -U kepler -d kepler -c "CREATE DATABASE kepler_marketing;"
   docker compose -f ../backend/docker-compose.yml exec -T postgres \
     psql -U kepler -d kepler_marketing -f - < db/waitlist_schema.sql
   ```
2. Run the server:
   ```
   KEPLER_MARKETING_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler_marketing" \
   KEPLER_TLS_CERT=../backend/dev-certs/dev.crt \
   KEPLER_TLS_KEY=../backend/dev-certs/dev.key \
   go run ./cmd/kepler-landing
   ```
3. Visit `https://localhost:8445/`.

## Tests

Same convention as `backend`: tests run against real local databases,
skipped cleanly if the relevant env var isn't set.

**Point these at dedicated `kepler_test` / `kepler_marketing_test`
databases, not the dev databases above** — tests don't clean up after
themselves, so running them against your dev databases permanently
pollutes whatever you're looking at in the dashboard or waitlist table.

One-time setup:
```
docker compose -f ../backend/docker-compose.yml exec -T postgres \
  psql -U kepler -d kepler -c "CREATE DATABASE kepler_test;"
docker compose -f ../backend/docker-compose.yml exec -T postgres \
  psql -U kepler -d kepler_test -f - < ../backend/db/schema.sql

docker compose -f ../backend/docker-compose.yml exec -T postgres \
  psql -U kepler -d kepler -c "CREATE DATABASE kepler_marketing_test;"
docker compose -f ../backend/docker-compose.yml exec -T postgres \
  psql -U kepler -d kepler_marketing_test -f - < db/waitlist_schema.sql
```

Then:
```
KEPLER_TEST_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler_test" \
KEPLER_TEST_MARKETING_DB_URL="postgres://kepler:kepler_dev_only@localhost:5432/kepler_marketing_test" \
go test ./...
```
