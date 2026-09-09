// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-6 regressions (lead decisions, 2026-09-10, §46/2), against the
// real store, derivation and fenced commit.
//
// A recorded operator note or captured verdict is journalled as its own
// Transition. It carries this cycle's contract verbatim — an annotation
// "never alters the Assessment, Attention, or Operator contract" — and no
// material candidate of its own, so a selection-gated history read skips
// it entirely. Delivered late, behind a finding, that row is exactly the
// one whose recorded investigation is no longer where the work is.
// ----------------------------------------------------------------------

// b5r6Artifact commits one applied operator artifact through the real
// reconciliation path and returns its stored journal Transition.
func b5r6Artifact(t *testing.T, st *Store, sitID, group, inputID, kind string, now time.Time) model.Transition {
	t.Helper()
	ctx := context.Background()
	shMakeDue(t, st, sitID, now.Add(-time.Second))
	claim := claimSituation(t, st, sitID, osOwner, now)
	shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, inputID, kind,
		claim.Situation.InputVersion, now.Add(-time.Second))

	in, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	if len(in.PendingArtifacts) != 1 {
		t.Fatalf("fixture: pending artifacts = %d, want 1", len(in.PendingArtifacts))
	}
	cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		model.LifecycleActive, model.AttentionObserve, now)
	cycle.Change.PriorTransition = in.PriorTransition
	cycle.Change.PriorSummary = in.CurrentSummary
	cycle.Change.Projection.Briefing = b5r4Mixed()
	cycle.Change.OperatorArtifacts = in.PendingArtifacts
	cycle.Publish.RootPublished = true
	cycle.Publish.DeliveredHistory = in.DeliveredHistory
	if in.PriorTransition != nil {
		cycle.Publish.PriorTransition = in.PriorTransition
	}
	commit := shDerive(t, cycle)
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}
	for _, tr := range commit.History.Transitions {
		if tr.OperatorArtifactInputID == nil || *tr.OperatorArtifactInputID != inputID {
			continue
		}
		stored, err := st.GetSituationTransition(ctx, tr.ID)
		if err != nil {
			t.Fatalf("GetSituationTransition: %v", err)
		}
		return stored
	}
	t.Fatalf("fixture: no journal transition was derived for artifact %s", inputID)
	return model.Transition{}
}

// b5r6History is the delivery-time read the deliverer now performs for
// EVERY reply, bounded below that reply's own sequence exactly as before.
func b5r6History(t *testing.T, st *Store, sitID string, tr model.Transition) situation.DeliveredHistory {
	t.Helper()
	h, err := st.GetCommunicatedHistory(context.Background(), sitID, tr.Sequence)
	if err != nil {
		t.Fatalf("GetCommunicatedHistory: %v", err)
	}
	return h
}

// R1: a delayed operator note and a delayed captured verdict each learn,
// from durable rows alone, that the investigation their own contract
// records has been overtaken — although neither carries a candidate that
// any selection would have asked about.
func TestB5ADelayedOperatorArtifactLearnsItsExecutionWasSuperseded(t *testing.T) {
	for kind, group := range map[string]string{
		"operator_annotation_recorded": "b5r6-note",
		"captured_verdict_recorded":    "b5r6-verdict",
	} {
		t.Run(kind, func(t *testing.T) {
			st := newTestStore(t)
			now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
			id := newSituationForGroup(t, st, group, now)

			b5r4MixedStart(t, st, id, now)
			note := b5r6Artifact(t, st, id, group, "artifact-"+group, kind, now.Add(2*time.Minute))
			if d := note.Projection.OperatorDelta; d != nil && len(d.Candidates) > 0 {
				t.Fatalf("fixture: the artifact row must carry no material candidate: %+v", d)
			}
			if before := b5r6History(t, st, id, note); before.AssuranceSuperseded {
				t.Fatalf("nothing had overtaken the execution yet: %+v", before)
			}

			osCycle(t, st, id, now.Add(4*time.Minute), osMonitoringContract(now.Add(5*time.Minute)),
				model.LifecycleActive, b5r4Settled(), true)

			if h := b5r6History(t, st, id, note); !h.AssuranceSuperseded {
				t.Errorf("the delayed %s reply was never told its recorded investigation had been overtaken: %+v", kind, h)
			}
		})
	}
}

// R2: the artifact row's own recorded contract is untouched by any of
// this. The correction is a presentation answer about one message, never a
// rewrite of what the ledger recorded.
func TestB5ADelayedOperatorNoteKeepsItsRecordedContract(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "b5r6-contract", now)

	b5r4MixedStart(t, st, id, now)
	note := b5r6Artifact(t, st, id, "b5r6-contract", "artifact-b5r6-contract",
		"operator_annotation_recorded", now.Add(2*time.Minute))
	osCycle(t, st, id, now.Add(4*time.Minute), osMonitoringContract(now.Add(5*time.Minute)),
		model.LifecycleActive, b5r4Settled(), true)

	reread, err := st.GetSituationTransition(context.Background(), note.ID)
	if err != nil {
		t.Fatalf("GetSituationTransition: %v", err)
	}
	if reread.ActionContract.AlertINTStatus == nil || note.ActionContract.AlertINTStatus == nil {
		t.Fatalf("fixture: both rows must record an AlertINT status: %+v", reread.ActionContract)
	}
	if *reread.ActionContract.AlertINTStatus != *note.ActionContract.AlertINTStatus {
		t.Errorf("the later finding rewrote the note's recorded status: %v -> %v",
			*note.ActionContract.AlertINTStatus, *reread.ActionContract.AlertINTStatus)
	}
	if reread.JournalKind != model.JournalOperatorNote {
		t.Errorf("journal kind = %v, want the recorded operator note", reread.JournalKind)
	}
}
