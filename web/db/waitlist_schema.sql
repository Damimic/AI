-- Schema for the marketing/waitlist database (kepler_marketing) — kept as
-- a separate database from the findings database, not just a separate
-- table, so a compromised marketing-site credential can't reach any
-- customer vulnerability data. Same local Postgres container, different
-- database name.

CREATE TABLE waitlist_signups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
