-- Least-privilege Postgres roles for production, one per long-running
-- network service. Local dev deliberately doesn't bother with this (a
-- single shared role keeps docker-compose simple for throwaway data), but
-- a real deployment should: if kepler-web is ever compromised, it should
-- be physically incapable of writing or deleting findings, not just
-- "trusted" not to. Each role's grants match exactly what its service's
-- SQL actually does — see the queries in backend/internal/store and
-- web/internal/store this was derived from.
--
-- kepler-backend-admin (the operator CLI, not a network service) keeps
-- using the full-privilege `kepler` role — it's invoked manually by a
-- human with real credentials each time, not a standing internet-facing
-- process, so it doesn't need the same scoping.
--
-- Replace the CHANGEME passwords before running. Run the first block
-- while connected to `kepler`, the second while connected to
-- `kepler_marketing`.

-- ============================================================
-- Run while connected to: kepler
-- ============================================================

-- Postgres grants CONNECT on every new database to PUBLIC by default —
-- revoke it so only roles explicitly granted access can connect at all,
-- not just at the table level.
REVOKE CONNECT ON DATABASE kepler FROM PUBLIC;

CREATE ROLE kepler_backend LOGIN PASSWORD 'CHANGEME';
GRANT CONNECT ON DATABASE kepler TO kepler_backend;
GRANT SELECT ON api_keys TO kepler_backend;          -- auth lookup only
GRANT UPDATE (last_seen_at) ON hosts TO kepler_backend; -- nothing else on hosts
GRANT INSERT ON ingestions TO kepler_backend;
GRANT INSERT ON findings TO kepler_backend;

CREATE ROLE kepler_dashboard LOGIN PASSWORD 'CHANGEME';
GRANT CONNECT ON DATABASE kepler TO kepler_dashboard;
GRANT SELECT ON hosts TO kepler_dashboard;
GRANT SELECT ON findings TO kepler_dashboard;
-- No INSERT/UPDATE/DELETE grants anywhere — the dashboard is read-only in
-- code today; this makes it read-only at the database level too, so a
-- bug or a compromised process can't write regardless.

-- ============================================================
-- Run while connected to: kepler_marketing
-- ============================================================

REVOKE CONNECT ON DATABASE kepler_marketing FROM PUBLIC;

CREATE ROLE kepler_landing LOGIN PASSWORD 'CHANGEME';
GRANT CONNECT ON DATABASE kepler_marketing TO kepler_landing;
GRANT SELECT, INSERT ON waitlist_signups TO kepler_landing;
-- kepler_landing has no grants on the kepler database at all (it can't
-- even CONNECT to it) — a compromised or abused signup form has no path
-- to findings data, enforced by Postgres, not just by which URL the code
-- happens to use.
