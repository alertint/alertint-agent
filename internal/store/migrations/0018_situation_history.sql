-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 3 history schema: the immutable Transition ledger, the current
-- Episode-summary projection, the stdout transition-stream outbox, and the
-- situation_input_outbox rebuild that adds exact operator-artifact input
-- provenance and the R1/R2 journaling cursor. This migration never
-- fabricates historical Transitions for a Plan 1/2 Situation that predates
-- it: an existing nonterminal or terminal Situation simply gains zero
-- situation_transitions rows and a NULL current_transition_id/0
-- current_transition_sequence, and remains fully readable. Deciding what to
-- do about that gap (spec: an idempotent "upgrade_reconstruction" due
-- reason so the next fenced reconciliation creates the first truthful
-- Transition) is application-level controller logic for a later task, not
-- a blind migration-time SQL backfill.

-- ----------------------------------------------------------------------
-- situation_transitions: the immutable Transition ledger (model.Transition).
-- Exactly one controller-state Transition per material reconciliation, plus
-- one per newly journaled operator artifact (R1). Typed identity/lifecycle/
-- attention/reason/actor columns for querying and guards; bounded canonical
-- JSON for the Operator contract, the journal render payload, the
-- projection facts, and the evidence-reference list. Rows are inserted
-- once and never touched again — no application ever needs to UPDATE or
-- DELETE a Transition.
-- ----------------------------------------------------------------------
CREATE TABLE situation_transitions (
    id                          TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id                TEXT    NOT NULL REFERENCES situations(id),
    sequence                    INTEGER NOT NULL CHECK (sequence >= 1),
    input_version               INTEGER NOT NULL CHECK (input_version >= 1),
    material_fact_hash          TEXT    NOT NULL CHECK (material_fact_hash <> ''),
    assessment_id               TEXT    REFERENCES situation_assessment_attempts(id),
    lifecycle                   TEXT    NOT NULL CHECK (lifecycle IN ('active','recovery_pending','recovered','closed_unknown')),
    attention                   TEXT    NOT NULL CHECK (attention IN ('observe','investigate','urgent')),
    action_contract_json        TEXT    NOT NULL CHECK (json_valid(action_contract_json) AND json_type(action_contract_json) = 'object'),
    sufficient_reason_id        TEXT    CHECK (sufficient_reason_id IS NULL OR sufficient_reason_id <> ''),
    interruption_priority       TEXT    CHECK (interruption_priority IS NULL OR interruption_priority IN ('low','medium','high','critical')),
    reason                      TEXT    NOT NULL CHECK (reason IN (
                                    'first_authoritative_state','material_assessment_changed','attention_changed',
                                    'operator_contract_changed','investigation_started','investigation_concluded',
                                    'recovery_observed','recovery_failed','recovered','closed_unknown',
                                    'recurrence_milestone','triage_state_changed','operator_artifact_recorded'
                                )),
    journal_kind                TEXT    NOT NULL CHECK (journal_kind IN (
                                    'none','publication','investigation_started','investigation_changed',
                                    'evidence_conclusion','operator_contract_changed','recovery_pending',
                                    'recovery_refired','recurrence_milestone','recovered','closed_unknown',
                                    'operator_note','captured_verdict'
                                )),
    journal_json                 TEXT    NOT NULL CHECK (json_valid(journal_json) AND json_type(journal_json) = 'object'),
    projection_json              TEXT    NOT NULL CHECK (json_valid(projection_json) AND json_type(projection_json) = 'object'),
    -- R1: the exact situation_input_outbox row this Transition journals,
    -- required exactly when reason='operator_artifact_recorded'.
    operator_artifact_input_id   TEXT    REFERENCES situation_input_outbox(id),
    evidence_refs_json           TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_refs_json) AND json_type(evidence_refs_json) = 'array'),
    -- Plan 3 may only ever write these three actors; operator_policy is a
    -- model.TransitionActor constant reserved for Plan 5 and unconditionally
    -- rejected by TransitionActor.Validate, so it is deliberately absent
    -- from this CHECK too (a later plan widens this the way 0015 widened
    -- llm_health_capabilities' capability enum: rebuild, never edit here).
    actor                        TEXT    NOT NULL CHECK (actor IN ('deterministic_controller','llm','attributed_operator')),
    drill                        INTEGER NOT NULL DEFAULT 0 CHECK (drill IN (0, 1)),
    created_at                   TEXT    NOT NULL CHECK (created_at <> ''),
    CHECK ((reason = 'operator_artifact_recorded') = (operator_artifact_input_id IS NOT NULL)),
    UNIQUE (situation_id, sequence)
) STRICT;
CREATE INDEX situation_transitions_operator_artifact_idx ON situation_transitions(operator_artifact_input_id)
    WHERE operator_artifact_input_id IS NOT NULL;
CREATE TRIGGER situation_transitions_no_update BEFORE UPDATE ON situation_transitions
BEGIN SELECT RAISE(ABORT, 'situation transition history is immutable'); END;
CREATE TRIGGER situation_transitions_no_delete BEFORE DELETE ON situation_transitions
BEGIN SELECT RAISE(ABORT, 'situation transition history is immutable'); END;
-- Same-Situation authoritative-Assessment guard, mirroring 0015's
-- situations_current_assessment_guard: a Transition may only cite an
-- authoritative Assessment attempt that belongs to its own Situation.
CREATE TRIGGER situation_transitions_assessment_guard BEFORE INSERT ON situation_transitions
WHEN NEW.assessment_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM situation_assessment_attempts a
    WHERE a.id = NEW.assessment_id AND a.situation_id = NEW.situation_id AND a.status = 'authoritative'
)
BEGIN SELECT RAISE(ABORT, 'transition assessment_id must reference an authoritative attempt owned by the same situation'); END;

-- ----------------------------------------------------------------------
-- situations: the current Transition pointer and its sequence (spec:
-- "current Transition pointer and transition sequence on situations"). A
-- freshly upgraded Plan 1/2 Situation gets NULL/0 (no Transition exists
-- yet); a fresh Plan 3 Situation sets both in the same commit that inserts
-- its first Transition.
-- ----------------------------------------------------------------------
ALTER TABLE situations ADD COLUMN current_transition_id TEXT REFERENCES situation_transitions(id);
ALTER TABLE situations ADD COLUMN current_transition_sequence INTEGER NOT NULL DEFAULT 0 CHECK (current_transition_sequence >= 0);
-- Same-Situation current-pointer guard, mirroring 0015's
-- situations_current_assessment_guard: current_transition_id must reference
-- a Transition owned by this exact Situation, at the exact sequence this
-- row also claims as current.
CREATE TRIGGER situations_current_transition_guard BEFORE UPDATE OF current_transition_id, current_transition_sequence ON situations
WHEN NEW.current_transition_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM situation_transitions tr
    WHERE tr.id = NEW.current_transition_id AND tr.situation_id = NEW.id AND tr.sequence = NEW.current_transition_sequence
)
BEGIN SELECT RAISE(ABORT, 'current_transition_id must reference a transition owned by the same situation with matching sequence'); END;

-- ----------------------------------------------------------------------
-- situation_episode_summaries: one CURRENT Episode-summary projection per
-- Situation (model.EpisodeSummary), folded once per Transition in sequence
-- order (Task 4/5's job — this migration only builds the schema and its
-- monotonic guard). Typed identity (situation_id, the table's own PRIMARY
-- KEY), version, and source-transition-sequence fence columns; everything
-- else — title, reasons, evidence conclusion, investigation work, the
-- Operator contract, final outcome, and so on — lives in the bounded
-- canonical summary_json projection.
-- ----------------------------------------------------------------------
CREATE TABLE situation_episode_summaries (
    situation_id                 TEXT    NOT NULL PRIMARY KEY REFERENCES situations(id),
    version                      INTEGER NOT NULL CHECK (version >= 1),
    source_transition_sequence   INTEGER NOT NULL CHECK (source_transition_sequence >= 1),
    summary_json                 TEXT    NOT NULL CHECK (json_valid(summary_json) AND json_type(summary_json) = 'object'),
    updated_at                   TEXT    NOT NULL CHECK (updated_at <> ''),
    FOREIGN KEY (situation_id, source_transition_sequence) REFERENCES situation_transitions(situation_id, sequence)
) STRICT;
-- A fold always advances the summary by exactly one version, sourced from a
-- strictly later Transition than the summary it replaces — never a skip,
-- never a replay of an already-summarized (or earlier) Transition.
CREATE TRIGGER situation_episode_summaries_monotonic BEFORE UPDATE ON situation_episode_summaries
WHEN NEW.version != OLD.version + 1 OR NEW.source_transition_sequence <= OLD.source_transition_sequence
BEGIN SELECT RAISE(ABORT, 'episode summary version and source transition sequence must both advance monotonically'); END;

-- ----------------------------------------------------------------------
-- situation_transition_stream: the durable stdout-stream outbox, one row
-- per Transition (Task 4/5 inserts it in the same fenced commit that
-- inserts the Transition). status is the STREAM's own closed 3-value set —
-- distinct from both Task 1's NotificationIntent.IntentStatus and this
-- migration's own situation_input_outbox.journal_state — and is never
-- 'claimed': a worker leases a pending row by setting lease_owner/
-- lease_expires_at (status stays 'pending'), the same shape
-- ClaimDueSituations already uses on situations itself, rather than adding
-- a fourth status value.
-- ----------------------------------------------------------------------
CREATE TABLE situation_transition_stream (
    id                TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    transition_id     TEXT    NOT NULL UNIQUE REFERENCES situation_transitions(id),
    situation_id      TEXT    NOT NULL REFERENCES situations(id),
    sequence          INTEGER NOT NULL CHECK (sequence >= 1),
    status            TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','failed')),
    lease_owner       TEXT,
    lease_expires_at  TEXT,
    claim_token       INTEGER NOT NULL DEFAULT 0 CHECK (claim_token >= 0),
    attempt_count     INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class  TEXT,
    retry_at          TEXT,
    delivered_at      TEXT,
    created_at        TEXT    NOT NULL CHECK (created_at <> ''),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK (status != 'failed' OR retry_at IS NULL)
) STRICT;
CREATE INDEX situation_transition_stream_situation_idx ON situation_transition_stream(situation_id, sequence);
CREATE INDEX situation_transition_stream_claim_idx ON situation_transition_stream(status, lease_expires_at, retry_at, created_at)
    WHERE status = 'pending';
-- The row's identity (which Transition/Situation/sequence/created_at it
-- records) is immutable; a worker may still freely update lease/status/
-- attempt/retry/delivered_at as delivery proceeds.
CREATE TRIGGER situation_transition_stream_identity_immutable BEFORE UPDATE ON situation_transition_stream
WHEN NEW.transition_id IS NOT OLD.transition_id OR NEW.situation_id IS NOT OLD.situation_id
  OR NEW.sequence IS NOT OLD.sequence OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'situation transition stream identity is immutable'); END;
CREATE TRIGGER situation_transition_stream_no_delete BEFORE DELETE ON situation_transition_stream
BEGIN SELECT RAISE(ABORT, 'situation transition stream history is immutable'); END;

-- ----------------------------------------------------------------------
-- situation_input_outbox rebuild (Plan 1's 0014, Plan 2 left it untouched):
-- add exact operator-artifact input provenance and the R1/R2 journaling
-- cursor. STRICT table, so this is create-copy-drop-rename, preserving
-- every existing Plan 1/2 row, index, and CHECK exactly — the new columns
-- are additive and every new CHECK is satisfied by every existing row's
-- default values (journal_state defaults 'not_applicable', which is
-- correct for every kind this table has ever accepted before today).
--
-- applied_input_version is deliberately NOT paired with status='applied' by
-- any CHECK: only ApplySituationInput's writes going forward stamp it (this
-- migration does not fabricate it for the Plan 1/2 rows it copies forward,
-- so those keep it NULL even though status='applied').
-- ----------------------------------------------------------------------
CREATE TABLE situation_input_outbox_new (
    id                      TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    idempotency_key         TEXT    NOT NULL UNIQUE CHECK (idempotency_key <> ''),
    incident_id             TEXT    NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    delivery_id             TEXT    REFERENCES alert_deliveries(id),
    kind                    TEXT    NOT NULL CHECK (kind IN (
                                'incident_created','membership_changed','incident_ready','finding_persisted',
                                'triage_skipped','triage_retry_changed','triage_exhausted','incident_resolved',
                                'operator_annotation_recorded','captured_verdict_recorded'
                            )),
    group_key               TEXT    NOT NULL CHECK (group_key <> ''),
    occurred_at             TEXT    NOT NULL CHECK (occurred_at <> ''),
    status                  TEXT    NOT NULL CHECK (status IN ('pending','claimed','applied','failed')),
    lease_owner             TEXT,
    lease_expires_at        TEXT,
    claim_token             INTEGER NOT NULL DEFAULT 0 CHECK (claim_token >= 0),
    attempt_count           INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class        TEXT,
    retry_at                TEXT,
    applied_situation_id    TEXT    REFERENCES situations(id),
    applied_at              TEXT,
    -- The exact situations.input_version this input's application landed
    -- (or, for R2's owner-terminal outcome, the terminal owner's own
    -- unchanged input_version) stamped. Never fabricated for a pre-Plan-3
    -- row; only ApplySituationInput writes it, going forward.
    applied_input_version   INTEGER CHECK (applied_input_version IS NULL OR applied_input_version >= 1),
    -- The exact durable artifact this row carries — set on exactly the
    -- matching kind, never on the other, never on a non-artifact kind.
    annotation_id           INTEGER REFERENCES incident_annotations(id),
    verdict_id              INTEGER REFERENCES incident_verdicts(id),
    -- R1/R2's journaling cursor: not_applicable for every non-artifact
    -- kind; pending from the moment an artifact-kind row is enqueued until
    -- either journaled (a Transition consumed it) or owner_terminal (R2:
    -- applied to an already-terminal owner, recorded but never journaled).
    journal_state           TEXT    NOT NULL DEFAULT 'not_applicable'
                            CHECK (journal_state IN ('not_applicable','pending','journaled','owner_terminal')),
    journaled_transition_id TEXT    REFERENCES situation_transitions(id),
    CHECK ((status = 'claimed') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((status = 'applied') = (applied_situation_id IS NOT NULL AND applied_at IS NOT NULL)),
    CHECK (status != 'failed' OR retry_at IS NULL),
    CHECK (
        (kind = 'operator_annotation_recorded' AND annotation_id IS NOT NULL AND verdict_id IS NULL) OR
        (kind = 'captured_verdict_recorded' AND verdict_id IS NOT NULL AND annotation_id IS NULL) OR
        (kind NOT IN ('operator_annotation_recorded','captured_verdict_recorded') AND annotation_id IS NULL AND verdict_id IS NULL)
    ),
    CHECK ((journal_state = 'not_applicable') = (kind NOT IN ('operator_annotation_recorded','captured_verdict_recorded'))),
    CHECK ((journal_state = 'journaled') = (journaled_transition_id IS NOT NULL)),
    CHECK (journal_state != 'owner_terminal' OR status = 'applied')
) STRICT;

INSERT INTO situation_input_outbox_new (
    id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at,
    status, lease_owner, lease_expires_at, claim_token, attempt_count,
    last_error_class, retry_at, applied_situation_id, applied_at
)
SELECT id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at,
       status, lease_owner, lease_expires_at, claim_token, attempt_count,
       last_error_class, retry_at, applied_situation_id, applied_at
FROM situation_input_outbox;

DROP TABLE situation_input_outbox;
ALTER TABLE situation_input_outbox_new RENAME TO situation_input_outbox;

CREATE INDEX situation_input_outbox_claim_idx ON situation_input_outbox(status, retry_at, occurred_at, id);
-- Supports the controller's R1 read: a Situation's applied, unjournaled
-- artifact rows in (applied_input_version, occurred_at, id) order.
CREATE INDEX situation_input_outbox_pending_journal_idx ON situation_input_outbox(applied_situation_id, journal_state, applied_input_version, occurred_at, id)
    WHERE journal_state = 'pending';
