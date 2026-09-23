-- SPDX-License-Identifier: FSL-1.1-ALv2

CREATE TABLE situation_judgments (
    id                 TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id       TEXT    NOT NULL REFERENCES situations(id) ON DELETE RESTRICT,
    revision           INTEGER NOT NULL CHECK (revision >= 1),
    operation          TEXT    NOT NULL CHECK (operation IN ('record','replace','revoke','restore')),
    state              TEXT    NOT NULL CHECK (state IN ('expected','revoked')),
    asserted_operator  TEXT    NOT NULL CHECK (asserted_operator <> ''),
    trust_domain       TEXT    NOT NULL CHECK (trust_domain = 'authenticated_mcp'),
    request_id         TEXT    NOT NULL UNIQUE CHECK (request_id <> ''),
    request_hash       TEXT    NOT NULL CHECK (request_hash <> ''),
    result_input_version INTEGER NOT NULL CHECK (result_input_version >= 1),
    valid_until        TEXT    NOT NULL CHECK (valid_until <> ''),
    coverage_json      TEXT    NOT NULL CHECK (json_valid(coverage_json) AND json_type(coverage_json) = 'object'),
    created_at         TEXT    NOT NULL CHECK (created_at <> ''),
    UNIQUE (situation_id, revision),
    CHECK ((operation = 'revoke') = (state = 'revoked'))
) STRICT;

CREATE TABLE situation_judgment_heads (
    situation_id       TEXT    NOT NULL PRIMARY KEY REFERENCES situations(id) ON DELETE RESTRICT,
    judgment_id        TEXT    NOT NULL UNIQUE REFERENCES situation_judgments(id) ON DELETE RESTRICT,
    revision           INTEGER NOT NULL CHECK (revision >= 1),
    updated_at         TEXT    NOT NULL CHECK (updated_at <> ''),
    invalidated_at     TEXT,
    invalidation_reason TEXT,
    CHECK ((invalidated_at IS NULL) = (invalidation_reason IS NULL))
) STRICT;

CREATE INDEX situation_judgments_history_idx
    ON situation_judgments(situation_id, revision);

CREATE TRIGGER situation_judgments_immutable BEFORE UPDATE ON situation_judgments
BEGIN SELECT RAISE(ABORT, 'situation judgment revisions are immutable'); END;
CREATE TRIGGER situation_judgments_no_delete BEFORE DELETE ON situation_judgments
BEGIN SELECT RAISE(ABORT, 'situation judgment history is immutable'); END;
CREATE TRIGGER situation_judgment_heads_no_delete BEFORE DELETE ON situation_judgment_heads
BEGIN SELECT RAISE(ABORT, 'situation judgment heads are durable'); END;
