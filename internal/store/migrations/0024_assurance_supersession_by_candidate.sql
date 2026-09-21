-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- D1 (lead reviews 2026-09-10, rounds 2 and 3): the schema guard 0022 added
-- for a superseded thread_append keys off the wrong fact. It requires the
-- reply's own Transition to be journalled `investigation_started`, but that
-- LABEL is not the record of an execution start. `selectControllerReason`
-- reaches ReasonInvestigationStarted only when the PRIOR contract was not
-- already an investigation, and `investigationCurrent` treats
-- run_acute_triage/planned exactly like run_acute_triage/running — so a
-- Situation that REQUESTS triage in one cycle and STARTS it in the next
-- records the real start as `operator_contract_changed`, and 0022 refuses
-- to retire it. The operator then receives a content-free start claim after
-- the finding that replaced it has already landed.
--
-- The recorded fact that actually means "execution began" is the B3
-- candidate `first_execution_assurance` on the Transition's own projection
-- (§4; internal/situation/model/briefing.go: "marks Work.ExecutionStarted's
-- false -> true edge for this Situation — never a request/decision alone").
-- `transitionConveysAssurance` already reads the candidate list and keeps
-- the journal label only as the legacy fallback for a projection that
-- carries no candidate list at all. This migration applies that same,
-- already-accepted correction to the one authority where it was not made.
--
-- SCOPE. A trigger replacement, and nothing else. No table rebuild, no
-- CHECK change, no column, no index, no row rewritten and no journal_kind
-- relabelled. Migrations 0001-0022 are untouched. Every existing row keeps
-- exactly the bytes it has; the guard's *question* changes, not the data it
-- reads. `projection_json` is already NOT NULL and CHECKed
-- `json_valid(...) AND json_type(...) = 'object'` by 0017, and
-- `$.operator_delta.candidates` is already the persisted shape
-- (ProjectionFacts / OperatorDelta / MaterialCandidate JSON tags).
--
-- PARITY. The predicate below is the exact SQL twin of
-- `purelyTransientAssurance` in internal/store/situation_notifications.go,
-- and internal/store/situation_assurance_candidate_parity_test.go drives
-- both from the same JSON so they cannot drift:
--
--   * candidates absent, JSON null, or an empty array -> legacy projection,
--     so the old `journal_kind = 'investigation_started'` rule stands. This
--     is the ONLY branch the label survives in; 0022's unconditional label
--     rule would otherwise let a mixed member/scope/finding row disappear
--     the moment it happened to be journalled investigation_started.
--   * a non-empty candidates array -> every element must be an object whose
--     `kind` is exactly `first_execution_assurance`. One member, scope,
--     finding, limitation or action candidate makes the row material
--     history (ADR 0042/0052) and is refused, whatever its label says.
--   * a missing, JSON-null or unrecognised `kind`, a non-object element, or
--     a `candidates` value that is not an array at all -> refused outright,
--     with no label fallback. SQL `<>` does not reject NULL, so the
--     comparison is the null-safe `IS NOT` inside a CASE that never
--     evaluates json_extract on a non-object element.
--
-- 0020's live-only rule (`notification_intents_supersede_from_live_only`)
-- is NOT touched: a DELIVERED assurance is still material history and can
-- never be superseded. Nor is 0018's rule that a broadcast_handoff is
-- immutable. This guard only ever narrows or widens WHICH live
-- thread_append may be retired, never whether a delivered one may be.
-- ----------------------------------------------------------------------

DROP TRIGGER notification_intents_thread_supersession_guard;

CREATE TRIGGER notification_intents_thread_supersession_guard BEFORE UPDATE OF status ON notification_intents
WHEN NEW.status = 'superseded' AND NEW.effect_class = 'thread_append' AND NOT EXISTS (
    SELECT 1 FROM situation_transitions tr
    WHERE tr.id = NEW.transition_id
      AND CASE
            -- Legacy projection: nothing recorded to inspect, so the
            -- original journal-label rule stands unchanged.
            WHEN json_type(tr.projection_json, '$.operator_delta.candidates') IS NULL
                 OR json_type(tr.projection_json, '$.operator_delta.candidates') = 'null'
              THEN tr.journal_kind = 'investigation_started'
            -- Recorded but malformed: refuse, never fall back to the label.
            WHEN json_type(tr.projection_json, '$.operator_delta.candidates') <> 'array'
              THEN 0
            WHEN json_array_length(tr.projection_json, '$.operator_delta.candidates') = 0
              THEN tr.journal_kind = 'investigation_started'
            -- Recorded: every candidate must be the transient assurance.
            ELSE NOT EXISTS (
                   SELECT 1
                     FROM json_each(tr.projection_json, '$.operator_delta.candidates') c
                    WHERE CASE
                            WHEN c.type = 'object'
                              THEN json_extract(c.value, '$.kind') IS NOT 'first_execution_assurance'
                            ELSE 1
                          END
                 )
          END
)
BEGIN SELECT RAISE(ABORT, 'a superseded thread_append must be a purely transient first_execution_assurance reply'); END;
