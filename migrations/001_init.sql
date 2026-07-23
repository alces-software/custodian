-- =============================================================================
-- Copyright (C) 2026-present Alces Software Ltd.
--
-- This file is part of Custodian.
--
-- This program and the accompanying materials are made available under
-- the terms of the Eclipse Public License 2.0 which is available at
-- <https://www.eclipse.org/legal/epl-2.0>, or alternative license
-- terms made available by Alces Software Ltd - please direct inquiries
-- about licensing to licensing@alces-flight.com.
--
-- Custodian is distributed in the hope that it will be useful, but
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
-- IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
-- OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
-- PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
-- details.
--
-- You should have received a copy of the Eclipse Public License 2.0
-- along with Custodian. If not, see:
--
--  https://opensource.org/licenses/EPL-2.0
--
-- For more information on Custodian, please visit:
-- https://github.com/alces-software/custodian
-- ==============================================================================

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

CREATE TABLE access_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash    TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT '',
    revoked_at  TIMESTAMPTZ
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
    access_key_id    UUID REFERENCES access_keys(id),
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
