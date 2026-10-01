-- Least-privilege Postgres role for kepler-landing, production only (see
-- production-roles-kepler.sql for the kepler/kepler_backend/kepler_dashboard
-- counterpart and the full rationale — these are two separate files rather
-- than one, since `psql -f` runs a whole file against a single connection
-- and the grant below targets a table that only exists in kepler_marketing).
--
-- Replace the CHANGEME password before running.
--
-- Run this file while connected to `kepler_marketing`.

REVOKE CONNECT ON DATABASE kepler_marketing FROM PUBLIC;

CREATE ROLE kepler_landing LOGIN PASSWORD 'CHANGEME';
GRANT CONNECT ON DATABASE kepler_marketing TO kepler_landing;
GRANT SELECT, INSERT ON waitlist_signups TO kepler_landing;
-- kepler_landing has no grants on the kepler database at all (it can't
-- even CONNECT to it) — a compromised or abused signup form has no path
-- to findings data, enforced by Postgres, not just by which URL the code
-- happens to use.
