// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// D1 (lead reviews 2026-09-10, rounds 2 and 3): eligibility to retire a
// live start-assurance reply is decided TWICE — once in Go by
// purelyTransientAssurance, once in SQLite by migration 0023's
// notification_intents_thread_supersession_guard. Two authorities asking
// the same question in two languages is exactly how D1 survived a whole
// chunk, so this file drives BOTH from the same projection JSON and fails
// the moment their verdicts differ.
//
// The Go side is called directly. The SQL side is the real installed
// trigger on a real migrated database, exercised by attempting the actual
// UPDATE the store would run — not a re-typed copy of the predicate, which
// would prove only that a string matches itself.
//
// The lead independently reproduced two SQLite predicate failures in the
// round-3 design proposal, and both are cases here: an unconditional
// journal-label branch admits mixed candidate lists that Go rejects
// ("mixed material under the legacy label"), and SQL `<>` does not reject
// NULL, so an assurance beside an object with no kind is admitted while Go
// rejects it ("assurance beside a kindless object").
// ----------------------------------------------------------------------

// assuranceParityCase is one recorded projection, the journal label it was
// committed under, and whether §5.3 may retire its reply.
type assuranceParityCase struct {
	name string
	// journalKind is a real situation_transitions.journal_kind value.
	journalKind string
	// projectionJSON is the exact projection_json bytes both authorities
	// read. Every value here is a shape the column's own CHECK admits
	// (json_valid, json_type = 'object').
	projectionJSON string
	// wantEligible is the single expected verdict. Go and SQL must BOTH
	// reach it; a case where they agree with each other but disagree with
	// this field is still a failure.
	wantEligible bool
	// wantGoDecodeError marks a projection Go cannot even load — a
	// malformed candidate list. The store never reaches the predicate for
	// such a row, and SQL must refuse it rather than fall back to the
	// label.
	wantGoDecodeError bool
	why               string
}

func assuranceParityCases() []assuranceParityCase {
	return []assuranceParityCase{
		{
			name:           "pure assurance under the canonical operator_contract_changed label",
			journalKind:    "operator_contract_changed",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"}]}}`,
			wantEligible:   true,
			why:            "D1 itself: the real execution start on the planned-then-running order",
		},
		{
			name:           "pure assurance under the investigation_started label",
			journalKind:    "investigation_started",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"}]}}`,
			wantEligible:   true,
			why:            "the pre-D1 path, unchanged",
		},
		{
			name:           "two assurance candidates and nothing else",
			journalKind:    "operator_contract_changed",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"},{"kind":"first_execution_assurance"}]}}`,
			wantEligible:   true,
			why:            "every recorded fact is still the disposable one",
		},
		{
			name:           "mixed material under the legacy label",
			journalKind:    "investigation_started",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"},{"kind":"members_changed"}]}}`,
			wantEligible:   false,
			why:            "lead round-3 reproduction 1: the label must not readmit mixed material history",
		},
		{
			name:           "mixed material under operator_contract_changed",
			journalKind:    "operator_contract_changed",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"},{"kind":"ability_changed"}]}}`,
			wantEligible:   false,
			why:            "ADR 0042/0052: a limitation on the row is durable history",
		},
		{
			name:           "assurance beside a kindless object",
			journalKind:    "operator_contract_changed",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"},{}]}}`,
			wantEligible:   false,
			why:            "lead round-3 reproduction 2: SQL <> does not reject NULL",
		},
		{
			name:           "assurance beside an explicitly null kind",
			journalKind:    "operator_contract_changed",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"},{"kind":null}]}}`,
			wantEligible:   false,
			why:            "same null-safety hole, spelled with an explicit JSON null",
		},
		{
			name:           "assurance beside an unrecognised kind",
			journalKind:    "operator_contract_changed",
			projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"},{"kind":"kind_from_a_newer_build"}]}}`,
			wantEligible:   false,
			why:            "an unknown fact is still a fact; neither authority may assume it is disposable",
		},
		{
			name:           "no candidate list at all, legacy label",
			journalKind:    "investigation_started",
			projectionJSON: `{}`,
			wantEligible:   true,
			why:            "the legacy fallback, the ONLY branch the journal label still decides",
		},
		{
			name:           "no candidate list at all, other label",
			journalKind:    "evidence_conclusion",
			projectionJSON: `{}`,
			wantEligible:   false,
			why:            "legacy fallback refuses everything else, exactly as 0022 did",
		},
		{
			name:           "null operator_delta, legacy label",
			journalKind:    "investigation_started",
			projectionJSON: `{"operator_delta":null}`,
			wantEligible:   true,
			why:            "a nil OperatorDelta is the same absent-list case",
		},
		{
			name:           "null candidates, legacy label",
			journalKind:    "investigation_started",
			projectionJSON: `{"operator_delta":{"candidates":null}}`,
			wantEligible:   true,
			why:            "omitempty means a nil slice can also arrive spelled out",
		},
		{
			name:           "empty candidates array, legacy label",
			journalKind:    "investigation_started",
			projectionJSON: `{"operator_delta":{"candidates":[]}}`,
			wantEligible:   true,
			why:            "len 0 is the absent-list case on both sides",
		},
		{
			name:           "empty candidates array, other label",
			journalKind:    "recovered",
			projectionJSON: `{"operator_delta":{"candidates":[]}}`,
			wantEligible:   false,
			why:            "an empty list does not make a recovery notice disposable",
		},
		{
			name:              "candidates is a string, legacy label",
			journalKind:       "investigation_started",
			projectionJSON:    `{"operator_delta":{"candidates":"first_execution_assurance"}}`,
			wantEligible:      false,
			wantGoDecodeError: true,
			why:               "malformed shape must be refused outright, never fall through to the label",
		},
		{
			name:              "candidates is an object",
			journalKind:       "operator_contract_changed",
			projectionJSON:    `{"operator_delta":{"candidates":{"kind":"first_execution_assurance"}}}`,
			wantEligible:      false,
			wantGoDecodeError: true,
			why:               "an object is not a list, however assurance-shaped it looks",
		},
		{
			name:              "candidates is an array of bare strings",
			journalKind:       "investigation_started",
			projectionJSON:    `{"operator_delta":{"candidates":["first_execution_assurance"]}}`,
			wantEligible:      false,
			wantGoDecodeError: true,
			why:               "json_each's value column is not JSON text for a scalar element",
		},
	}
}

// goAssuranceVerdict decodes projectionJSON exactly as scanTransition does
// and answers the Go authority's question, or reports that the projection
// could not be loaded at all.
func goAssuranceVerdict(journalKind, projectionJSON string) (eligible bool, decodeErr error) {
	var facts situationmodel.ProjectionFacts
	if err := json.Unmarshal([]byte(projectionJSON), &facts); err != nil {
		return false, err
	}
	return purelyTransientAssurance(situationmodel.Transition{
		JournalKind: situationmodel.JournalKind(journalKind),
		Projection:  facts,
	}), nil
}

// seedAssuranceParityRow inserts one Transition carrying the case's exact
// projection bytes plus a live pending thread_append reply for it, and
// returns that reply's id. seq must be unique per Situation: 0018's
// thread_broadcast_uniq_idx is on (situation_id, transition_sequence,
// effect_class).
func seedAssuranceParityRow(ctx context.Context, t *testing.T, st *Store, situationID string, seq int, c assuranceParityCase) string {
	t.Helper()
	now := time.Now().UTC()
	transitionID := fmt.Sprintf("tr-parity-%d", seq)
	intentID := fmt.Sprintf("intent-parity-%d", seq)
	// reason is deliberately held at a value every journal_kind here is
	// allowed to pair with: 0017 constrains the two columns independently,
	// and this file's subject is the guard, not reason derivation.
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
			action_contract_json, reason, journal_kind, journal_json, projection_json,
			evidence_refs_json, actor, created_at
		) VALUES (?, ?, ?, 1, ?, 'active', 'observe', '{}', 'operator_contract_changed', ?, '{}', ?, '[]',
		          'deterministic_controller', ?)`,
		transitionID, situationID, seq, fmt.Sprintf("sha256:parity-%d", seq), c.journalKind,
		c.projectionJSON, canonicalTime(now)); err != nil {
		t.Fatalf("seed transition for %q: %v", c.name, err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			requires_root, main_channel_poke, client_message_id, status, created_at
		) VALUES (?, ?, 'thread_append', ?, ?, ?, 1, 0, ?, 'pending', ?)`,
		intentID, "key:"+intentID, situationID, transitionID, seq, "client:"+intentID,
		canonicalTime(now)); err != nil {
		t.Fatalf("seed reply intent for %q: %v", c.name, err)
	}
	return intentID
}

// TestAssuranceCandidateGoSQLParity is the D1 anti-drift regression: for
// every recorded projection shape, purelyTransientAssurance and migration
// 0023's installed trigger must return the SAME verdict, and that verdict
// must be the one §5.3 intends.
func TestAssuranceCandidateGoSQLParity(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	situationID := "sit-assurance-parity"
	insertOperationalIncident(ctx, t, st, "inc-assurance-parity", "group-assurance-parity")
	if err := insertSituation(ctx, st, situationRow{
		id: situationID, groupKey: "group-assurance-parity", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}

	cases := assuranceParityCases()
	// One replacement row every case can point at, seeded from a shape both
	// authorities refuse, so it can never itself be retired by accident.
	replacementID := seedAssuranceParityRow(ctx, t, st, situationID, 1, assuranceParityCase{
		name: "replacement", journalKind: "evidence_conclusion", projectionJSON: `{}`,
	})

	for i, c := range cases {
		seq := i + 2
		intentID := seedAssuranceParityRow(ctx, t, st, situationID, seq, c)

		goEligible, decodeErr := goAssuranceVerdict(c.journalKind, c.projectionJSON)
		if c.wantGoDecodeError {
			if decodeErr == nil {
				t.Errorf("%s: Go decoded a projection this case calls malformed; the case, not the product, is wrong", c.name)
			}
		} else if decodeErr != nil {
			t.Errorf("%s: Go could not decode the projection: %v", c.name, decodeErr)
		}
		if !c.wantGoDecodeError && goEligible != c.wantEligible {
			t.Errorf("%s: purelyTransientAssurance = %v, want %v (%s)", c.name, goEligible, c.wantEligible, c.why)
		}

		_, err := st.db.ExecContext(ctx, `
			UPDATE notification_intents
			   SET status = 'superseded', supersession_reason = 'superseded_by_finding', replacement_intent_id = ?
			 WHERE id = ?`, replacementID, intentID)
		sqlEligible := err == nil
		if !sqlEligible && !strings.Contains(err.Error(), "purely transient first_execution_assurance") {
			t.Fatalf("%s: the UPDATE failed for a reason that is not the supersession guard: %v", c.name, err)
		}
		if sqlEligible != c.wantEligible {
			t.Errorf("%s: migration 0023's guard permits = %v, want %v (%s)", c.name, sqlEligible, c.wantEligible, c.why)
		}

		// The parity claim itself, stated separately so a failure says
		// which authority drifted rather than only which case broke.
		if !c.wantGoDecodeError && goEligible != sqlEligible {
			t.Errorf("%s: Go says %v and SQL says %v — the two authorities have drifted (%s)",
				c.name, goEligible, sqlEligible, c.why)
		}
		if c.wantGoDecodeError && sqlEligible {
			t.Errorf("%s: SQL admitted a projection Go cannot even load (%s)", c.name, c.why)
		}
	}
}

// TestAssuranceSupersessionGuardStillRefusesADeliveredReply pins the part
// of the guard family 0023 deliberately does NOT touch: 0020's live-only
// rule. A delivered assurance is material history whatever its candidates
// say.
func TestAssuranceSupersessionGuardStillRefusesADeliveredReply(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	situationID := "sit-delivered-assurance"
	insertOperationalIncident(ctx, t, st, "inc-delivered-assurance", "group-delivered-assurance")
	if err := insertSituation(ctx, st, situationRow{
		id: situationID, groupKey: "group-delivered-assurance", lifecycle: "active",
	}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	replacementID := seedAssuranceParityRow(ctx, t, st, situationID, 1, assuranceParityCase{
		journalKind: "evidence_conclusion", projectionJSON: `{}`,
	})
	deliveredID := seedAssuranceParityRow(ctx, t, st, situationID, 2, assuranceParityCase{
		journalKind:    "operator_contract_changed",
		projectionJSON: `{"operator_delta":{"candidates":[{"kind":"first_execution_assurance"}]}}`,
	})
	if _, err := st.db.ExecContext(ctx, `
		UPDATE notification_intents
		   SET status = 'delivered', delivered_as = 'thread', channel = 'C', message_ts = '1.1', delivered_at = ?
		 WHERE id = ?`, canonicalTime(now), deliveredID); err != nil {
		t.Fatalf("mark the assurance delivered: %v", err)
	}
	_, err := st.db.ExecContext(ctx, `
		UPDATE notification_intents
		   SET status = 'superseded', supersession_reason = 'superseded_by_finding', replacement_intent_id = ?,
		       delivered_as = NULL, channel = NULL, message_ts = NULL, delivered_at = NULL
		 WHERE id = ?`, replacementID, deliveredID)
	if err == nil || !strings.Contains(err.Error(), "live root_sync or thread_append") {
		t.Fatalf("superseding a DELIVERED pure assurance = %v, want 0020's live-only rejection", err)
	}
}
