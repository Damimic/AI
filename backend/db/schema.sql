-- Kepler backend schema, v1.
--
-- Scope: store findings reported by agents (via kepler-matcher output),
-- authenticated per-host by API key. No multi-tenant/org model yet — one
-- host maps to one API key, which is all v1 needs to prove the core loop.
--
-- The ingestions table exists so each batch of reported findings has a
-- natural anchor (who reported what, when) — this isn't audit logging
-- (nothing here is immutable/tamper-evident), but it means an audit log
-- could be added later by making this table append-only, rather than
-- requiring a schema rewrite.

CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);

-- One host can have multiple keys over its lifetime (rotation): old keys
-- are revoked, not deleted, so history is preserved.
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id),
    key_hash TEXT NOT NULL UNIQUE, -- SHA-256 hex digest; the raw key is never stored
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_host_id ON api_keys(host_id);

CREATE TABLE ingestions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ingestions_host_id ON ingestions(host_id);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ingestion_id UUID NOT NULL REFERENCES ingestions(id),
    host_id UUID NOT NULL REFERENCES hosts(id), -- denormalized from ingestions for simpler per-host queries
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    fixed_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_host_id ON findings(host_id);
CREATE INDEX idx_findings_cve_id ON findings(cve_id);
CREATE INDEX idx_findings_ingestion_id ON findings(ingestion_id);
