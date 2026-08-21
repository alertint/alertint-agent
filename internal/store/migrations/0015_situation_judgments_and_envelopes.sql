-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Append-only operator judgments, versioned Expected-behaviour envelopes,
-- and their deterministic evaluation audit trail. Every write here is
-- explicitly confirmed and attributed (authenticated trust domain kept
-- separate from the asserted operator); free text never appears as an
-- authority-bearing column.

CREATE TABLE situation_judgments (
    id                    TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id          TEXT    NOT NULL REFERENCES situations(id) ON DELETE CASCADE,
    judged_input_version  INTEGER NOT NULL CHECK (judged_input_version >= 1),
    covered_fact_hash     TEXT    NOT NULL CHECK (covered_fact_hash <> ''),
    covered_symptoms_json TEXT    NOT NULL CHECK (json_valid(covered_symptoms_json) AND json_type(covered_symptoms_json) = 'array'),
    covered_impact_json   TEXT    NOT NULL CHECK (json_valid(covered_impact_json) AND json_type(covered_impact_json) = 'array'),
    judgment              TEXT    NOT NULL CHECK (judgment IN ('expected_this_episode', 'unexpected', 'inconclusive')),
    basis                 TEXT    NOT NULL CHECK (basis IN ('operator_knowledge', 'alertint_evidence')),
    workload              TEXT,
    valid_until           TEXT,
    evidence_refs_json    TEXT    NOT NULL CHECK (json_valid(evidence_refs_json) AND json_type(evidence_refs_json) = 'array'),
    authenticated_as      TEXT    NOT NULL CHECK (authenticated_as <> ''),
    asserted_operator     TEXT    NOT NULL CHECK (asserted_operator <> ''),
    created_at            TEXT    NOT NULL CHECK (created_at <> '')
) STRICT;

CREATE INDEX situation_judgments_situation_idx
    ON situation_judgments(situation_id, created_at);

CREATE TRIGGER situation_judgments_no_update
BEFORE UPDATE ON situation_judgments
BEGIN
    SELECT RAISE(ABORT, 'situation judgments are immutable');
END;

CREATE TRIGGER situation_judgments_no_delete
BEFORE DELETE ON situation_judgments
BEGIN
    SELECT RAISE(ABORT, 'situation judgments are immutable');
END;

CREATE TABLE expected_behavior_envelopes (
    id                    TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    current_version       INTEGER NOT NULL DEFAULT 0 CHECK (current_version >= 0),
    source_judgment_id    TEXT    NOT NULL REFERENCES situation_judgments(id),
    last_review_prompt_at TEXT,
    created_at            TEXT    NOT NULL CHECK (created_at <> ''),
    updated_at            TEXT    NOT NULL CHECK (updated_at <> '')
) STRICT;

CREATE UNIQUE INDEX expected_behavior_envelopes_source_judgment_idx
    ON expected_behavior_envelopes(source_judgment_id);

CREATE TABLE expected_behavior_envelope_versions (
    envelope_id       TEXT    NOT NULL REFERENCES expected_behavior_envelopes(id) ON DELETE CASCADE,
    version           INTEGER NOT NULL CHECK (version >= 1),
    status            TEXT    NOT NULL CHECK (status IN ('active', 'revoked', 'invalidated')),
    scope_json        TEXT    NOT NULL CHECK (length(scope_json) <= 16384 AND json_valid(scope_json) AND json_type(scope_json) = 'object'),
    conditions_json   TEXT    NOT NULL CHECK (length(conditions_json) <= 65536 AND json_valid(conditions_json) AND json_type(conditions_json) = 'object'),
    review_due_at     TEXT    NOT NULL CHECK (review_due_at <> ''),
    authenticated_as  TEXT    NOT NULL CHECK (authenticated_as <> ''),
    asserted_operator TEXT    NOT NULL CHECK (asserted_operator <> ''),
    reason            TEXT,
    created_at        TEXT    NOT NULL CHECK (created_at <> ''),
    PRIMARY KEY (envelope_id, version)
) STRICT;

CREATE TRIGGER expected_behavior_envelope_versions_no_update
BEFORE UPDATE ON expected_behavior_envelope_versions
BEGIN
    SELECT RAISE(ABORT, 'expected behavior envelope versions are immutable');
END;

CREATE TRIGGER expected_behavior_envelope_versions_no_delete
BEFORE DELETE ON expected_behavior_envelope_versions
BEGIN
    SELECT RAISE(ABORT, 'expected behavior envelope versions are immutable');
END;

CREATE TABLE envelope_evaluations (
    id                  TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    envelope_id         TEXT    NOT NULL REFERENCES expected_behavior_envelopes(id) ON DELETE CASCADE,
    envelope_version    INTEGER NOT NULL CHECK (envelope_version >= 1),
    situation_id        TEXT    NOT NULL REFERENCES situations(id) ON DELETE CASCADE,
    input_version       INTEGER NOT NULL CHECK (input_version >= 1),
    result              TEXT    NOT NULL CHECK (result IN ('match', 'violation', 'authority_removed', 'not_applicable')),
    matched_fields_json TEXT    NOT NULL CHECK (json_valid(matched_fields_json) AND json_type(matched_fields_json) = 'array'),
    violations_json     TEXT    NOT NULL CHECK (json_valid(violations_json) AND json_type(violations_json) = 'array'),
    observability_json  TEXT    NOT NULL CHECK (json_valid(observability_json) AND json_type(observability_json) = 'array'),
    -- Resolved UTC schedule window a configured Schedule condition evaluated
    -- against, persisted rather than re-derived so a DST-sensitive
    -- determination stays independently auditable. Both NULL when the
    -- evaluated version carries no Schedule condition.
    schedule_window_start TEXT,
    schedule_window_end   TEXT,
    quieting_authority  INTEGER NOT NULL CHECK (quieting_authority IN (0, 1)),
    created_at          TEXT    NOT NULL CHECK (created_at <> ''),
    CHECK ((schedule_window_start IS NULL) = (schedule_window_end IS NULL))
) STRICT;

CREATE INDEX envelope_evaluations_situation_idx
    ON envelope_evaluations(situation_id, input_version, created_at);

CREATE INDEX envelope_evaluations_envelope_idx
    ON envelope_evaluations(envelope_id, created_at);

CREATE TRIGGER envelope_evaluations_no_update
BEFORE UPDATE ON envelope_evaluations
BEGIN
    SELECT RAISE(ABORT, 'envelope evaluations are immutable');
END;

CREATE TRIGGER envelope_evaluations_no_delete
BEFORE DELETE ON envelope_evaluations
BEGIN
    SELECT RAISE(ABORT, 'envelope evaluations are immutable');
END;
