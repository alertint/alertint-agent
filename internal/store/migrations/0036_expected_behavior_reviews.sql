-- SPDX-License-Identifier: FSL-1.1-ALv2

ALTER TABLE expected_behavior_envelope_heads ADD COLUMN last_review_prompt_at TEXT;

CREATE TABLE expected_behavior_review_intents (
    id                TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    envelope_id       TEXT    NOT NULL REFERENCES expected_behavior_envelope_heads(envelope_id) ON DELETE RESTRICT,
    envelope_version  INTEGER NOT NULL CHECK (envelope_version >= 1),
    cycle_started_at  TEXT    NOT NULL CHECK (cycle_started_at <> ''),
    payload_json      TEXT    NOT NULL CHECK (json_valid(payload_json) AND json_type(payload_json) = 'object'),
    status            TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','superseded')),
    created_at        TEXT    NOT NULL CHECK (created_at <> ''),
    retry_at          TEXT,
    attempt_count     INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class  TEXT CHECK (last_error_class IS NULL OR (last_error_class <> '' AND length(last_error_class) <= 64)),
    claim_owner       TEXT,
    claim_token       INTEGER NOT NULL DEFAULT 0 CHECK (claim_token >= 0),
    lease_expires_at  TEXT,
    delivered_at      TEXT,
    channel           TEXT,
    message_ts        TEXT,
    UNIQUE(envelope_id,envelope_version,cycle_started_at),
    CHECK ((claim_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((status='delivered')=(delivered_at IS NOT NULL AND channel IS NOT NULL AND message_ts IS NOT NULL)),
    CHECK (status='pending' OR (claim_owner IS NULL AND lease_expires_at IS NULL))
) STRICT;
CREATE INDEX expected_behavior_review_pending_idx ON expected_behavior_review_intents(status,retry_at,lease_expires_at,created_at);

CREATE TRIGGER expected_behavior_review_identity_immutable BEFORE UPDATE OF
    envelope_id,envelope_version,cycle_started_at,payload_json,created_at
    ON expected_behavior_review_intents
BEGIN SELECT RAISE(ABORT, 'expected behavior review identity is immutable'); END;
CREATE TRIGGER expected_behavior_review_no_delete BEFORE DELETE ON expected_behavior_review_intents
BEGIN SELECT RAISE(ABORT, 'expected behavior review intents are durable'); END;
