-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 2 gates the shipped `incident_triage` schedule (0011) behind the
-- controller: every ready Incident now starts in `awaiting_decision` and
-- requires a versioned controller decision (request | skip) before it may
-- dispatch. This migration rebuilds `incident_triage` in place — SQLite
-- cannot add a CHECK-constrained enum value or the phase-linked lease
-- invariant via ALTER TABLE — preserving every existing row's phase,
-- attempts, due/start/error values exactly, then backfills `awaiting_decision`
-- for `ready` Incidents that never acquired a schedule row. It does not
-- backfill situation_id/decision metadata onto retained rows — that
-- Situation-ownership backfill is Task 6's startup-only Go logic, run after
-- Plan 1 reconstruction has established ownership.

-- incident_triage_attempts is the durable per-attempt Acute Triage ledger
-- (spec: "Attempt identity and completion"). A claim inserts the row with
-- its frozen identity/digests/member-delivery snapshot; completion is the
-- one legal follow-up UPDATE that sets the result columns exactly once.
-- Created before the incident_triage rebuild below so that table's
-- current_attempt_id FK can reference it.
CREATE TABLE incident_triage_attempts (
    id                      TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    incident_id             TEXT    NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    attempt_number          INTEGER NOT NULL CHECK (attempt_number >= 1 AND attempt_number <= 5),
    situation_id            TEXT    NOT NULL REFERENCES situations(id),
    decision_input_version  INTEGER NOT NULL CHECK (decision_input_version >= 1),
    -- Both digests are frozen at claim time — the worker loads exactly this
    -- recorded input, never a later current membership view.
    membership_digest       TEXT    NOT NULL CHECK (membership_digest <> ''),
    incident_input_digest   TEXT    NOT NULL CHECK (incident_input_digest <> ''),
    -- Bounded immutable member/delivery identities claimed for analysis.
    member_delivery_ids_json TEXT   NOT NULL CHECK (json_valid(member_delivery_ids_json) AND json_type(member_delivery_ids_json) = 'array'),
    started_at              TEXT    NOT NULL CHECK (started_at <> ''),
    -- result_code is an open bounded code (e.g. success, stale_membership,
    -- stale_incident_input, a typed failure class); Task 6 owns its exact
    -- closed set and the transition logic that sets it.
    result_code             TEXT,
    output_digest           TEXT,
    finding_id              TEXT,
    evidence_pack_digest    TEXT,
    completed_at            TEXT,
    CHECK ((completed_at IS NULL) = (result_code IS NULL)),
    UNIQUE (incident_id, attempt_number)
) STRICT;
-- Deliberately no claimable-work index: this ledger is never independently
-- claimable (spec: "not a second scheduler"). incident_triage alone is the
-- claimable schedule.

-- Claim-time identity/snapshot columns are immutable for the life of the
-- row, including across the one legal completing UPDATE.
CREATE TRIGGER incident_triage_attempts_claim_immutable BEFORE UPDATE ON incident_triage_attempts
WHEN NEW.incident_id != OLD.incident_id
  OR NEW.attempt_number != OLD.attempt_number
  OR NEW.situation_id != OLD.situation_id
  OR NEW.decision_input_version != OLD.decision_input_version
  OR NEW.membership_digest != OLD.membership_digest
  OR NEW.incident_input_digest != OLD.incident_input_digest
  OR NEW.member_delivery_ids_json != OLD.member_delivery_ids_json
  OR NEW.started_at != OLD.started_at
BEGIN SELECT RAISE(ABORT, 'incident triage attempt claim identity is immutable'); END;
-- A completed attempt is fully frozen: no further update of any kind,
-- including a second "completion".
CREATE TRIGGER incident_triage_attempts_completed_immutable BEFORE UPDATE ON incident_triage_attempts
WHEN OLD.completed_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'completed incident triage attempt is immutable'); END;
CREATE TRIGGER incident_triage_attempts_no_delete BEFORE DELETE ON incident_triage_attempts
BEGIN SELECT RAISE(ABORT, 'incident triage attempt history is immutable'); END;

-- ----------------------------------------------------------------------
-- Rebuild incident_triage (0011) to add the awaiting_decision phase, the
-- Situation/input/basis/decision metadata, both Incident coverage digests,
-- and fenced lease fields.
-- ----------------------------------------------------------------------

CREATE TABLE incident_triage_new (
    incident_id            TEXT    NOT NULL PRIMARY KEY,
    phase                  TEXT    NOT NULL CHECK (phase IN ('awaiting_decision', 'pending', 'in_flight', 'backoff', 'skipped', 'exhausted')),
    -- 5 = len(triageRetryDelays)+1 in internal/correlator/triage_retry.go —
    -- keep both in sync if the retry schedule ever changes attempt count.
    attempts               INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
    next_at                TEXT,
    started_at             TEXT,
    last_error_code        TEXT,
    last_error_detail      TEXT,
    -- Situation ownership and the controller's versioned request/skip
    -- decision (spec: "B+ Acute Triage gate"). Left null by this migration
    -- for every retained row; Task 6 startup backfills situation_id/
    -- decision_input_version/membership_digest onto retained schedulable
    -- rows with decision_origin='upgrade_existing_schedule' and never sets
    -- decision/decision_reason/material_fact_hash/incident_input_digest/
    -- assessment_id/decided_at for them, matching the spec's preserved-row
    -- example (only situation_id, decision_origin, decision_input_version,
    -- and membership_digest are backfilled for pre-Plan-2 work).
    situation_id            TEXT REFERENCES situations(id),
    decision                TEXT CHECK (decision IS NULL OR decision IN ('request', 'skip')),
    decision_reason         TEXT CHECK (decision_reason IS NULL OR decision_reason <> ''),
    decision_origin         TEXT CHECK (decision_origin IS NULL OR decision_origin <> ''),
    decision_input_version  INTEGER,
    -- material_fact_hash is the decision's basis: the exact material fact
    -- hash the controller's request/skip judgment was made against.
    material_fact_hash      TEXT CHECK (material_fact_hash IS NULL OR material_fact_hash <> ''),
    membership_digest       TEXT CHECK (membership_digest IS NULL OR membership_digest <> ''),
    incident_input_digest   TEXT CHECK (incident_input_digest IS NULL OR incident_input_digest <> ''),
    assessment_id           TEXT REFERENCES situation_assessment_attempts(id),
    decided_at               TEXT,
    -- Fenced lease fields for an in-flight claim. New in-flight rows always
    -- require owner+expiry+attempt identity; a migrated legacy in-flight
    -- row may remain temporarily ownerless — either straight out of this
    -- migration (decision_origin still null, before Task 6 startup
    -- backfills it) or after that backfill sets decision_origin=
    -- 'upgrade_existing_schedule' — until Task 6 startup recovery
    -- normalizes it, before any worker starts.
    lease_owner              TEXT,
    lease_expires_at         TEXT,
    claim_token              INTEGER NOT NULL DEFAULT 0 CHECK (claim_token >= 0),
    current_attempt_id       TEXT REFERENCES incident_triage_attempts(id),
    updated_at                TEXT    NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    -- NOTE for Task 6 (the only future writer of fresh in_flight rows):
    -- decision_origin IS NULL is accepted here only to let this migration's
    -- own copy-forward INSERT commit before the startup backfill runs. Any
    -- *live* controller-driven claim must set decision_origin to a non-null
    -- value (something other than 'upgrade_existing_schedule') in the same
    -- transaction that sets phase='in_flight', or this CHECK stops
    -- distinguishing a genuinely fresh unleased row from a migrated one.
    CHECK (
        (phase != 'in_flight' AND lease_owner IS NULL AND lease_expires_at IS NULL AND current_attempt_id IS NULL)
        OR (phase = 'in_flight' AND (decision_origin IS NULL OR decision_origin = 'upgrade_existing_schedule'))
        OR (phase = 'in_flight' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND current_attempt_id IS NOT NULL)
    )
) STRICT;

INSERT INTO incident_triage_new (incident_id, phase, attempts, next_at, started_at, last_error_code, last_error_detail, updated_at)
SELECT incident_id, phase, attempts, next_at, started_at, last_error_code, last_error_detail, updated_at
FROM incident_triage;

DROP TABLE incident_triage;
ALTER TABLE incident_triage_new RENAME TO incident_triage;

-- Partial due index: only pending/backoff rows are ever claimable work
-- (awaiting_decision requires a controller decision first; in_flight/
-- skipped/exhausted are never due).
CREATE INDEX incident_triage_due_idx ON incident_triage(next_at)
    WHERE phase IN ('pending', 'backoff');
-- Partial expired-lease index for interrupted-claim recovery scans.
CREATE INDEX incident_triage_expired_lease_idx ON incident_triage(lease_expires_at)
    WHERE phase = 'in_flight' AND lease_expires_at IS NOT NULL;

-- Upgrade mapping: a `ready` Incident with no Triage row enters
-- awaiting_decision at attempt zero (spec's Upgrade mapping table). Every
-- other pre-upgrade phase is already preserved verbatim by the copy above.
INSERT INTO incident_triage (incident_id, phase, attempts, updated_at)
SELECT i.id, 'awaiting_decision', 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM incidents i
WHERE i.status = 'ready'
  AND NOT EXISTS (SELECT 1 FROM incident_triage t WHERE t.incident_id = i.id);
