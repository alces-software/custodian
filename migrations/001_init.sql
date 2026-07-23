-- +migrate Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE le_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL,
    private_key_enc TEXT NOT NULL,
    registration_uri TEXT NOT NULL DEFAULT '',
    directory_url   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (directory_url)
);

CREATE TABLE certificates (
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
    acme_order_url   TEXT,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    renewed_at       TIMESTAMPTZ
);

CREATE INDEX certificates_status_not_after_idx
    ON certificates (status, not_after)
    WHERE status = 'active';

CREATE INDEX certificates_common_name_idx ON certificates (common_name);

CREATE TABLE audit_events (
    id             BIGSERIAL PRIMARY KEY,
    action         TEXT NOT NULL,
    certificate_id UUID REFERENCES certificates(id) ON DELETE SET NULL,
    actor          TEXT NOT NULL DEFAULT '',
    detail         TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +migrate Down
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS le_accounts;
