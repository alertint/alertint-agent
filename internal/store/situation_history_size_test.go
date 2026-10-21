// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// insertHistoryFactsTransition inserts one Transition with the given journal
// kind and raw projection JSON.
func insertHistoryFactsTransition(t *testing.T, db *sql.DB, situationID string, sequence int, journal situationmodel.JournalKind, projection string) string {
	t.Helper()
	id := fmt.Sprintf("tr-facts-%04d", sequence)
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash, assessment_id,
			lifecycle, attention, action_contract_json, reason, journal_kind, journal_json,
			projection_json, operator_artifact_input_id, evidence_refs_json, actor, drill, created_at
		) VALUES (?, ?, ?, ?, ?, NULL, 'active', 'investigate', '{}', 'triage_state_changed',
			?, '{}', ?, NULL, '[]', 'deterministic_controller', 0, ?)`,
		id, situationID, sequence, sequence, "sha256:facts-"+id, string(journal), projection,
		time.Date(2026, 10, 21, 8, 0, sequence, 0, time.UTC).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert transition %d: %v", sequence, err)
	}
	return id
}

// TestCommunicatedHistoryCostDoesNotGrowWithProjectionSize is issue #99's
// regression guard. A long-lived Situation repeats its whole alert list in
// every Transition's projection; the deliverer's history read must cost the
// same whether those rows are small or a few hundred KiB.
func TestCommunicatedHistoryCostDoesNotGrowWithProjectionSize(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	sitID := seedReconcileSituation(t, st, "group-history-size", now)
	if _, err := st.db.ExecContext(ctx, `UPDATE situations SET slack_channel = 'C0HIST', slack_root_ts = '1760947200.000100' WHERE id = ?`, sitID); err != nil {
		t.Fatal(err)
	}

	const replies = 60
	firing := make([]string, 4000)
	for i := range firing {
		firing[i] = fmt.Sprintf("KubePodCrashLooping/payments-%04d/container-restarts", i)
	}
	members := situationmodel.MaterialCandidate{Kind: situationmodel.CandidateMembersChanged,
		Members: &situationmodel.MemberFacts{StillFiring: firing, FiringCount: len(firing), Total: len(firing)}}
	insertIntent := func(id, class string, transitionID string, sequence int, status string, summaryVersion any) {
		t.Helper()
		var deliveredAs, channel, ts, deliveredAt any
		if status == "delivered" {
			deliveredAs, channel, ts, deliveredAt = "thread", "C0HIST", fmt.Sprintf("1760947200.%06d", sequence), now.Format(time.RFC3339Nano)
			if class == "root_sync" {
				deliveredAs, ts = "root", "1760947200.000100"
			}
		}
		requiresRoot := 1
		if class == "root_sync" {
			requiresRoot = 0
		}
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO notification_intents (
				id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
				summary_version, requires_root, main_channel_poke, interruption_priority,
				client_message_id, status, delivered_as, channel, message_ts, created_at, delivered_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, ?, ?, ?, ?)`,
			id, "idem-"+id, class, sitID, transitionID, sequence, summaryVersion, requiresRoot,
			"cmid-"+id, status, deliveredAs, channel, ts, now.Format(time.RFC3339Nano), deliveredAt); err != nil {
			t.Fatalf("insert %s intent %s: %v", class, id, err)
		}
	}

	var projectionBytes, lastDelivered, pending int
	for i := 1; i <= replies+1; i++ {
		sequence := 100 + i
		cs := []situationmodel.MaterialCandidate{members}
		if i%10 == 0 {
			cs = append(cs, situationmodel.MaterialCandidate{Kind: situationmodel.CandidateAbilityChanged,
				Limitation: &situationmodel.LimitationFacts{Code: fmt.Sprintf("source_unavailable_%d", i/10%3)}})
		}
		// The start assurance reached the operator only through the root:
		// the delivered-root read has to run too.
		p := situationmodel.ProjectionFacts{OperatorDelta: &situationmodel.OperatorDelta{Candidates: cs}, Briefing: &situationmodel.OperatorBriefing{}}
		p.Briefing.Work.ExecutionStarted = true
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		projectionBytes += len(raw)
		id := insertHistoryFactsTransition(t, st.db, sitID, sequence, situationmodel.JournalInvestigationChanged, string(raw))
		if i > replies {
			pending = sequence
			insertIntent(fmt.Sprintf("ni-reply-%d", sequence), "thread_append", id, sequence, "pending", nil)
			continue
		}
		lastDelivered = sequence
		insertIntent(fmt.Sprintf("ni-reply-%d", sequence), "thread_append", id, sequence, "delivered", nil)
		insertIntent(fmt.Sprintf("ni-root-%d", sequence), "root_sync", id, sequence, "delivered", i)
	}
	if projectionBytes < replies*200<<10 {
		t.Fatalf("fixture projections average %d bytes, want at least 200 KiB", projectionBytes/(replies+1))
	}

	if _, err := st.GetCommunicatedHistory(ctx, sitID, pending); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	h, err := st.GetCommunicatedHistory(ctx, sitID, pending)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if !h.AssuranceConveyed || h.LastDeliveredSequence != lastDelivered || len(h.CommunicatedLimitationCodes) != 3 {
		t.Fatalf("history = %+v, want the root-conveyed assurance, last delivered %d and 3 limitation codes", h, lastDelivered)
	}
	// Each delivered row is read three times (delivered, standing, root),
	// so decoding the projections would allocate several times their size.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Fatalf("one history read allocated %d KiB over %d KiB of projections; it must not decode them", alloc>>10, projectionBytes>>10)
	}
}
