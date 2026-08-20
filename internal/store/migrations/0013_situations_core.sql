-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Durable Situation aggregate, immutable primary Incident membership, the
-- explicit acute-analysis gate, and the correlator-to-controller input outbox.

CREATE TABLE situations (
    id                         TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    previous_situation_id      TEXT    REFERENCES situations(id),
    group_key                  TEXT    NOT NULL CHECK (group_key <> ''),
    public_handle              TEXT    CHECK (public_handle IS NULL OR public_handle <> ''),
    title                      TEXT,
    lifecycle                  TEXT    NOT NULL CHECK (lifecycle IN ('active', 'recovery_pending', 'recovered', 'closed_unknown')),
    attention                  TEXT    NOT NULL CHECK (attention IN ('observe', 'investigate', 'urgent')),
    input_version              INTEGER NOT NULL CHECK (input_version >= 1),
    fact_hash                  TEXT,
    current_assessment_id      TEXT,
    opened_at                  TEXT    NOT NULL CHECK (opened_at <> ''),
    effective_started_at       TEXT    NOT NULL CHECK (effective_started_at <> ''),
    effective_started_at_basis TEXT    NOT NULL CHECK (effective_started_at_basis IN ('source_payload', 'source_api', 'receipt_fallback', 'mixed')),
    first_received_at          TEXT    NOT NULL CHECK (first_received_at <> ''),
    last_lifecycle_observed_at TEXT    NOT NULL CHECK (last_lifecycle_observed_at <> ''),
    recovery_observed_at       TEXT,
    grace_until                TEXT,
    terminal_at                TEXT,
    terminal_reason            TEXT    CHECK (terminal_reason IS NULL OR terminal_reason IN ('observation_deadline', 'resolution_missing', 'source_unavailable', 'budget_exhausted')),
    next_assessment_at         TEXT    NOT NULL CHECK (next_assessment_at <> ''),
    due_reasons_json           TEXT    NOT NULL CHECK (json_valid(due_reasons_json) AND json_type(due_reasons_json) = 'array'),
    lease_owner                TEXT,
    lease_expires_at           TEXT,
    attempt_count              INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class           TEXT,
    retry_at                   TEXT,
    created_at                 TEXT    NOT NULL CHECK (created_at <> ''),
    updated_at                 TEXT    NOT NULL CHECK (updated_at <> ''),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (
        (lifecycle IN ('active', 'recovery_pending') AND terminal_at IS NULL AND terminal_reason IS NULL)
        OR (lifecycle = 'recovered' AND terminal_at IS NOT NULL AND terminal_reason IS NULL)
        OR (lifecycle = 'closed_unknown' AND terminal_at IS NOT NULL AND terminal_reason IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX situations_one_nonterminal_group_idx
    ON situations(group_key)
    WHERE lifecycle IN ('active', 'recovery_pending');

CREATE UNIQUE INDEX situations_public_handle_nocase_idx
    ON situations(public_handle COLLATE NOCASE)
    WHERE public_handle IS NOT NULL;

CREATE INDEX situations_due_idx
    ON situations(next_assessment_at, retry_at)
    WHERE lifecycle IN ('active', 'recovery_pending');

CREATE TRIGGER situations_legal_lifecycle_update
BEFORE UPDATE OF lifecycle ON situations
WHEN NOT (
    (OLD.lifecycle = 'active' AND NEW.lifecycle IN ('active', 'recovery_pending', 'closed_unknown'))
    OR (OLD.lifecycle = 'recovery_pending' AND NEW.lifecycle IN ('recovery_pending', 'active', 'recovered', 'closed_unknown'))
    OR (OLD.lifecycle = 'recovered' AND NEW.lifecycle = 'recovered')
    OR (OLD.lifecycle = 'closed_unknown' AND NEW.lifecycle = 'closed_unknown')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid situation lifecycle transition');
END;

CREATE TRIGGER situations_public_handle_immutable
BEFORE UPDATE OF public_handle ON situations
WHEN OLD.public_handle IS NOT NULL AND NEW.public_handle IS NOT OLD.public_handle
BEGIN
    SELECT RAISE(ABORT, 'situation public handles are immutable');
END;

CREATE TABLE situation_incidents (
    situation_id TEXT NOT NULL REFERENCES situations(id) ON DELETE CASCADE,
    incident_id  TEXT NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    attached_at  TEXT NOT NULL CHECK (attached_at <> ''),
    PRIMARY KEY (situation_id, incident_id)
) STRICT;

CREATE INDEX situation_incidents_situation_idx
    ON situation_incidents(situation_id, attached_at);

CREATE TRIGGER situation_incidents_no_update
BEFORE UPDATE ON situation_incidents
BEGIN
    SELECT RAISE(ABORT, 'situation membership is immutable');
END;

CREATE TRIGGER situation_incidents_no_delete
BEFORE DELETE ON situation_incidents
BEGIN
    SELECT RAISE(ABORT, 'situation membership is immutable');
END;

CREATE TABLE incident_analysis_state (
    incident_id       TEXT NOT NULL PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
    status            TEXT NOT NULL CHECK (status IN ('not_requested', 'planned', 'running', 'complete', 'blocked', 'exhausted')),
    decision_reason   TEXT NOT NULL CHECK (decision_reason <> ''),
    latest_attempt_id TEXT,
    updated_at        TEXT NOT NULL CHECK (updated_at <> '')
) STRICT;

INSERT INTO incident_analysis_state (incident_id, status, decision_reason, updated_at)
SELECT id,
       CASE
           WHEN status IN ('analyzed', 'resolved') AND output_json IS NOT NULL AND trim(output_json) <> '' THEN 'complete'
           WHEN status IN ('ready', 'processing') THEN 'planned'
           WHEN status = 'failed' THEN 'exhausted'
           ELSE 'not_requested'
       END,
       'upgrade_backfill',
       updated_at
FROM incidents;

CREATE TABLE situation_input_outbox (
    id               TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    idempotency_key  TEXT    NOT NULL UNIQUE CHECK (idempotency_key <> ''),
    incident_id      TEXT    NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    delivery_id      TEXT    REFERENCES alert_deliveries(id),
    kind             TEXT    NOT NULL CHECK (kind IN ('incident_created', 'membership_changed', 'incident_ready', 'incident_resolved')),
    group_key        TEXT    NOT NULL CHECK (group_key <> ''),
    occurred_at      TEXT    NOT NULL CHECK (occurred_at <> ''),
    status           TEXT    NOT NULL CHECK (status IN ('pending', 'claimed', 'applied', 'failed')),
    lease_owner      TEXT,
    lease_expires_at TEXT,
    attempt_count    INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class TEXT,
    retry_at         TEXT,
    applied_at       TEXT,
    CHECK ((status = 'claimed') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((status = 'applied') = (applied_at IS NOT NULL)),
    CHECK (status <> 'failed' OR retry_at IS NULL)
) STRICT;

CREATE INDEX situation_input_outbox_claim_idx
    ON situation_input_outbox(status, retry_at, occurred_at);
