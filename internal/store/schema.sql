CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS le_accounts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email            TEXT NOT NULL,
    private_key_enc  TEXT NOT NULL,
    registration_uri TEXT NOT NULL DEFAULT '',
    directory_url    TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (directory_url)
);

CREATE TABLE IF NOT EXISTS access_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash    TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT '',
    revoked_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS certificates (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    common_name      TEXT NOT NULL,
    sans             TEXT[] NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'pending',
    private_key_enc  TEXT,
    certificate_pem  TEXT,
    chain_pem        TEXT,
    not_before       TIMESTAMPTZ,
    not_after        TIMESTAMPTZ,
    serial           TEXT,
    issuer           TEXT,
    dns_zone         TEXT,
    access_key_id    UUID REFERENCES access_keys(id),
    acme_order_url   TEXT,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    renewed_at       TIMESTAMPTZ
);

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS dns_zone TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS access_key_id UUID REFERENCES access_keys(id);

CREATE INDEX IF NOT EXISTS certificates_status_not_after_idx
    ON certificates (status, not_after)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS certificates_common_name_idx ON certificates (common_name);
CREATE INDEX IF NOT EXISTS certificates_access_key_id_idx ON certificates (access_key_id);
CREATE INDEX IF NOT EXISTS access_keys_revoked_at_idx ON access_keys (revoked_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id             BIGSERIAL PRIMARY KEY,
    action         TEXT NOT NULL,
    certificate_id UUID REFERENCES certificates(id) ON DELETE SET NULL,
    actor          TEXT NOT NULL DEFAULT '',
    detail         TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
