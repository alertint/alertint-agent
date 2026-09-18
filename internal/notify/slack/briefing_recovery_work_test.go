// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// §63 (lead review of the retry disclosure, 2026-09-10): lifecycle recovery
// and outstanding investigation must compose in PRESENTATION.
//
// deriveAlertINTBranch ranks every triage phase above the recovery-pending
// lifecycle, and ControllerState.TriagePhase is aggregateTriagePhase over
// the very incidents BuildWorkProjection reduces — so a Situation that is
// confirming recovery WHILE work is outstanding always derives a triage or
// assessment contract, and the persisted grace deadline, rendered only
// under verify_recovery, never reached the operator. The canonical
// "recovery-with-work" example is exactly that state: "Watching for
// sustained recovery through [recorded grace deadline]. One investigation
// is still running; next status check: [recorded checkpoint]", under its
// own rule that "Recovery grace and investigation coexist. Lifecycle sets
// orientation; activity describes remaining work."
//
// Every fixture here derives the contract with the real
// situation.DeriveActionContract over a real ControllerState and builds the
// projection with the real situation.BuildWorkProjection: a handcrafted
// verify_recovery contract proves renderer capability and never production
// reachability, which is the mistake §63 names. Both operator-visible
// surfaces are asserted — the fallback text and the decoded Block Kit — and
// the composed activity line is pinned whole, so a clause cannot be
// duplicated, dropped or reordered without failing here.
// ----------------------------------------------------------------------

// brwDerived derives one case exactly as the controller does: the real
// contract for this ControllerState, then the real projection over the same
// incidents the state's TriagePhase aggregates, carrying the persisted grace
// and the contract's own checkpoint (CommittedOperatorBriefing's arguments).
func brwDerived(t *testing.T, state situation.ControllerState, incidents []situation.IncidentState,
	grace *time.Time, now time.Time) (model.ActionContract, model.WorkProjection) {
	t.Helper()
	c := situation.DeriveActionContract(state, situation.DeriveCadence(state), now)
	return c, situation.BuildWorkProjection(incidents, grace, c.NextUpdateAt)
}

// brwSurfaces renders the whole root and returns both surfaces an operator
// can read. mutate applies the facts CommittedOperatorBriefing overlays
// after BuildWorkProjection — the contract-selected RetryAt, and the
// Assessment-level retry merged into Work.RetryEligibleAt.
func brwSurfaces(t *testing.T, lifecycle model.Lifecycle, c model.ActionContract,
	w model.WorkProjection, mutate func(*model.OperatorBriefing)) map[string]string {
	t.Helper()
	b := bcBriefing()
	b.Firing, b.Resolved = 0, 4
	b.Work = w
	if mutate != nil {
		mutate(b)
	}
	msg, err := RenderSituationRoot(bcRoot(t, lifecycle, model.AttentionObserve, c, b))
	if err != nil {
		t.Fatalf("RenderSituationRoot: %v", err)
	}
	return map[string]string{"fallback text": msg.Text, "block kit": rsFallbackBlocksText(msg)}
}

// brwActivity is the one *AlertINT:* line of a rendered surface. The whole
// message is the wrong scope for an activity assertion: the orientation
// chain names every phase this Situation could be in, and the title and
// footer carry recorded facts of their own.
func brwActivity(t *testing.T, surface, text string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "*AlertINT:*") {
			return line
		}
	}
	t.Fatalf("%s carries no *AlertINT:* line:\n%s", surface, text)
	return ""
}

// brwActivityIs pins the composed activity line on both surfaces.
func brwActivityIs(t *testing.T, surfaces map[string]string, want string) {
	t.Helper()
	for surface, out := range surfaces {
		if got := brwActivity(t, surface, out); got != want {
			t.Errorf("%s activity line\n  got:  %s\n  want: %s", surface, got, want)
		}
	}
}

// brwActivityNever forbids copy on both surfaces' activity lines.
func brwActivityNever(t *testing.T, surfaces map[string]string, never []string) {
	t.Helper()
	for surface, out := range surfaces {
		line := brwActivity(t, surface, out)
		for _, n := range never {
			if strings.Contains(line, n) {
				t.Errorf("%s activity line states %q, which the record does not support:\n%s", surface, n, line)
			}
		}
	}
}

// TestBriefingDerivedRecoveryStatesGraceBesideOutstandingWork drives the
// four triage dispositions and the Assessment retry that each outrank the
// recovery-pending lifecycle in deriveAlertINTBranch. Every one must state
// the persisted grace deadline, its own recorded work truth and the status
// checkpoint as three distinct clauses of one line.
func TestBriefingDerivedRecoveryStatesGraceBesideOutstandingWork(t *testing.T) {
	now := bcNow(t)
	queue, retry, grace := now.Add(5*time.Minute), now.Add(9*time.Minute), now.Add(12*time.Minute)
	watch := "Watching for sustained recovery through " + SlackDateToken(grace, "{time}") + "."

	for _, tc := range []struct {
		name      string
		state     situation.ControllerState
		incidents []situation.IncidentState
		mutate    func(*model.OperatorBriefing)
		work      string
	}{
		{
			name:      "an investigation in flight",
			state:     situation.ControllerState{TriagePhase: situation.TriagePhaseInFlight},
			incidents: []situation.IncidentState{{ID: "inc-running", Triage: situation.TriageState{Phase: "in_flight", Attempts: 1}}},
			work:      "Investigating.",
		},
		{
			name:      "a queued schedule that has never executed",
			state:     situation.ControllerState{TriagePhase: situation.TriagePhaseAwaitingDecision, TriageDueAt: &queue},
			incidents: []situation.IncidentState{{ID: "inc-queued", Triage: situation.TriageState{Phase: "pending", NextAt: &queue}}},
			work: "Investigation is queued; it has not started yet. It becomes eligible after " +
				SlackDateToken(queue, "{time}") + "; eligibility is not an execution guarantee.",
		},
		{
			name:      "an undecided schedule",
			state:     situation.ControllerState{TriagePhase: situation.TriagePhaseAwaitingDecision},
			incidents: []situation.IncidentState{{ID: "inc-undecided", Triage: situation.TriageState{Phase: "awaiting_decision"}}},
			work:      briefingAwaitingDecision,
		},
		{
			name:      "a schedule waiting in back-off",
			state:     situation.ControllerState{TriagePhase: situation.TriagePhaseBackoff, TriageDueAt: &retry},
			incidents: []situation.IncidentState{{ID: "inc-backoff", Triage: situation.TriageState{Phase: "backoff", Attempts: 1, NextAt: &retry}}},
			// CommittedOperatorBriefing selects RetryAt from the member
			// back-off schedules for exactly this contract, so the fixture
			// carries the value production would have loaded.
			mutate: func(b *model.OperatorBriefing) { b.RetryAt = &retry },
			work:   "Investigation retry scheduled for " + SlackDateToken(retry, "{time}") + ".",
		},
		{
			name:   "an Assessment retry with no triage schedule left",
			state:  situation.ControllerState{SemanticRetry: situation.SemanticRetryPhaseDue, SemanticRetryAt: &retry},
			mutate: func(b *model.OperatorBriefing) { b.RetryAt = &retry },
			work:   "Assessment retry scheduled for " + SlackDateToken(retry, "{time}") + ".",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := tc.state
			state.Lifecycle, state.Attention = model.LifecycleRecoveryPending, model.AttentionObserve
			state.RecoveryGraceUntil = &grace
			c, w := brwDerived(t, state, tc.incidents, &grace, now)
			if c.AlertINTAction != nil && *c.AlertINTAction == model.AlertINTActionVerifyRecovery {
				t.Fatalf("this state no longer derives a work contract; the case proves nothing about composition")
			}
			if c.NextUpdateAt == nil || c.NextUpdateAt.Equal(grace) {
				t.Fatalf("derived checkpoint %v cannot be told apart from the grace deadline", c.NextUpdateAt)
			}
			brwActivityIs(t, brwSurfaces(t, model.LifecycleRecoveryPending, c, w, tc.mutate),
				"*AlertINT:* "+watch+" "+tc.work+" Next status check: "+SlackDateToken(*c.NextUpdateAt, "{time}")+".")
		})
	}
}

// TestBriefingDerivedRecoveryGraceGuards holds the composition to what the
// record actually says: it adds nothing when the contract already watches
// recovery, invents no deadline when none is persisted, never reaches an
// active lifecycle, and never reopens a terminal one.
func TestBriefingDerivedRecoveryGraceGuards(t *testing.T) {
	now := bcNow(t)
	queue, grace := now.Add(5*time.Minute), now.Add(12*time.Minute)
	graceToken := SlackDateToken(grace, "{time}")
	queued := []situation.IncidentState{{ID: "inc-queued", Triage: situation.TriageState{Phase: "pending", NextAt: &queue}}}
	eligible := " It becomes eligible after " + SlackDateToken(queue, "{time}") + "; eligibility is not an execution guarantee."

	t.Run("recovery with no outstanding work states the grace exactly once", func(t *testing.T) {
		state := situation.ControllerState{Lifecycle: model.LifecycleRecoveryPending,
			Attention: model.AttentionObserve, RecoveryGraceUntil: &grace}
		c, w := brwDerived(t, state, nil, &grace, now)
		if c.AlertINTAction == nil || *c.AlertINTAction != model.AlertINTActionVerifyRecovery {
			t.Fatal("recovery with no outstanding work must still derive verify_recovery")
		}
		brwActivityIs(t, brwSurfaces(t, model.LifecycleRecoveryPending, c, w, nil),
			"*AlertINT:* Watching for sustained recovery through "+graceToken+". Next status check: "+
				SlackDateToken(*c.NextUpdateAt, "{time}")+".")
	})

	t.Run("an unrecorded grace deadline is not invented", func(t *testing.T) {
		state := situation.ControllerState{Lifecycle: model.LifecycleRecoveryPending,
			Attention: model.AttentionObserve, TriagePhase: situation.TriagePhaseAwaitingDecision, TriageDueAt: &queue}
		c, w := brwDerived(t, state, queued, nil, now)
		surfaces := brwSurfaces(t, model.LifecycleRecoveryPending, c, w, nil)
		brwActivityIs(t, surfaces,
			"*AlertINT:* Watching for sustained recovery; the next check will reassess whether alerts remain clear. "+
				"Investigation is queued; it has not started yet."+eligible+" Next status check: "+
				SlackDateToken(*c.NextUpdateAt, "{time}")+".")
		for surface, out := range surfaces {
			line := brwActivity(t, surface, out)
			if got := strings.Count(line, "<!date^"); got != 2 {
				t.Errorf("%s states %d recorded time(s) with no grace persisted, want the queue readiness and the checkpoint only:\n%s", surface, got, line)
			}
		}
	})

	t.Run("an active lifecycle gains no recovery clause", func(t *testing.T) {
		state := situation.ControllerState{Lifecycle: model.LifecycleActive,
			Attention: model.AttentionObserve, TriagePhase: situation.TriagePhaseAwaitingDecision, TriageDueAt: &queue}
		c, w := brwDerived(t, state, queued, &grace, now)
		surfaces := brwSurfaces(t, model.LifecycleActive, c, w, nil)
		brwActivityIs(t, surfaces, "*AlertINT:* Investigation is queued; it has not started yet."+eligible+
			" Next status check: "+SlackDateToken(*c.NextUpdateAt, "{time}")+".")
		brwActivityNever(t, surfaces, []string{"Watching for sustained recovery", graceToken})
	})

	t.Run("a terminal lifecycle keeps its recorded ending", func(t *testing.T) {
		state := situation.ControllerState{Lifecycle: model.LifecycleRecovered,
			Attention: model.AttentionObserve, TriagePhase: situation.TriagePhaseAwaitingDecision}
		c, w := brwDerived(t, state, queued, &grace, now)
		surfaces := brwSurfaces(t, model.LifecycleRecovered, c, w, nil)
		brwActivityIs(t, surfaces,
			"*AlertINT:* Recovery confirmed after the observation period; monitoring for this episode has ended.")
		brwActivityNever(t, surfaces, []string{"Watching for sustained recovery", graceToken,
			"Next status check", "Investigation is queued"})
	})
}

// TestBriefingRecoveryWorkKeepsEveryRecordedTimeDistinct pins all four
// independently recorded instants of the mixed queued/back-off record
// (§60/§62) once the recovery lifecycle composes with it, and holds the
// disclosed retry to what its provenance supports. Work.RetryEligibleAt is
// the earliest of the member triage back-offs AND the committed
// Assessment-level retry (CommittedOperatorBriefing's earliestNonNil
// overlay), so no surface may name which of the two it belongs to.
func TestBriefingRecoveryWorkKeepsEveryRecordedTimeDistinct(t *testing.T) {
	now := bcNow(t)
	queue, triageRetry, grace := now.Add(5*time.Minute), now.Add(9*time.Minute), now.Add(12*time.Minute)
	assessmentRetry := now.Add(7 * time.Minute)
	mixed := []situation.IncidentState{
		{ID: "inc-queued-77", Triage: situation.TriageState{Phase: "pending", NextAt: &queue}},
		{ID: "inc-backoff-88", Triage: situation.TriageState{Phase: "backoff", Attempts: 1, NextAt: &triageRetry}},
	}

	for _, tc := range []struct {
		name     string
		overlay  *time.Time
		disclose time.Time
	}{
		{
			name:     "a triage back-off keeps its own retry beside the queue readiness",
			disclose: triageRetry,
		},
		{
			// CommittedOperatorBriefing merges the committed Assessment
			// retry into the same field and the earliest wins, so the
			// disclosed time is then the Assessment's — with nothing
			// recorded anywhere in the projection to say so.
			name:     "an Assessment retry earlier than the back-off becomes the disclosed time",
			overlay:  &assessmentRetry,
			disclose: assessmentRetry,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := situation.ControllerState{Lifecycle: model.LifecycleRecoveryPending,
				Attention: model.AttentionObserve, TriagePhase: situation.TriagePhaseAwaitingDecision,
				TriageDueAt: &queue, RecoveryGraceUntil: &grace}
			c, w := brwDerived(t, state, mixed, &grace, now)
			if w.Phase != model.WorkPhaseQueued || !w.ExecutionStarted || w.RemainingIncidents != 2 {
				t.Fatalf("fixture is not the mixed queued/back-off record: %+v", w)
			}
			surfaces := brwSurfaces(t, model.LifecycleRecoveryPending, c, w, func(b *model.OperatorBriefing) {
				if tc.overlay != nil {
					b.Work.RetryEligibleAt = tc.overlay
				}
			})
			brwActivityIs(t, surfaces, "*AlertINT:* Watching for sustained recovery through "+
				SlackDateToken(grace, "{time}")+". Investigation is queued. The earliest queued investigation becomes eligible after "+
				SlackDateToken(queue, "{time}")+"; eligibility is not an execution guarantee."+
				" A separately recorded retry becomes eligible after "+SlackDateToken(tc.disclose, "{time}")+
				". Next status check: "+SlackDateToken(*c.NextUpdateAt, "{time}")+".")
			brwActivityNever(t, surfaces, append([]string{"has not started yet"}, briefingRetryAttributions...))
		})
	}
}

// TestBriefingOutstandingRetryWaitStatesTheTimeWithoutAnOwner is §63's
// second correction. briefingOutstandingWork's retry-wait clause called
// Work.RetryEligibleAt an investigation retry, but that field merges the
// member triage back-offs with the committed Assessment retry and records
// nothing that separates them. The waiting SCHEDULE is a triage back-off —
// the aggregate phase proves that much — while the TIME may belong to
// either, so the phase keeps its attribution and the instant loses one.
func TestBriefingOutstandingRetryWaitStatesTheTimeWithoutAnOwner(t *testing.T) {
	now := bcNow(t)
	retry, earlier := now.Add(9*time.Minute), now.Add(-3*time.Minute)
	backoff := func(id string, attempts int, at *time.Time) situation.IncidentState {
		return situation.IncidentState{ID: id, Triage: situation.TriageState{Phase: "backoff", Attempts: attempts, NextAt: at}}
	}

	for _, tc := range []struct {
		name      string
		incidents []situation.IncidentState
		overlay   *time.Time
		want      string
	}{
		{
			name:      "one schedule in back-off",
			incidents: []situation.IncidentState{backoff("inc-a", 1, &retry)},
			want:      "One investigation is waiting in back-off. A recorded retry becomes eligible after " + SlackDateToken(retry, "{time}") + ".",
		},
		{
			name:      "two schedules in back-off",
			incidents: []situation.IncidentState{backoff("inc-a", 1, &retry), backoff("inc-b", 2, &retry)},
			want: "An investigation is waiting in back-off. The earliest recorded retry becomes eligible after " +
				SlackDateToken(retry, "{time}") + ". In total, 2 member investigations have outstanding work.",
		},
		{
			name:      "an already-due retry is stated as a fact, not a promise",
			incidents: []situation.IncidentState{backoff("inc-a", 1, &retry)},
			overlay:   &earlier,
			want:      "One investigation is waiting in back-off. A recorded retry is eligible as of " + SlackDateToken(earlier, "{time}") + ".",
		},
		{
			name:      "no recorded retry at all",
			incidents: []situation.IncidentState{backoff("inc-a", 1, nil)},
			want:      "One investigation is waiting in back-off; no retry time is recorded.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := situation.BuildWorkProjection(tc.incidents, nil, nil)
			if w.Phase != model.WorkPhaseRetryWait {
				t.Fatalf("fixture aggregates to %s, not retry_wait", w.Phase)
			}
			if tc.overlay != nil {
				w.RetryEligibleAt = tc.overlay
			}
			got := briefingOutstandingWork(&model.OperatorBriefing{Work: w}, now)
			if got != tc.want {
				t.Errorf("outstanding-work line\n  got:  %s\n  want: %s", got, tc.want)
			}
			for _, never := range briefingRetryAttributions {
				if strings.Contains(got, never) {
					t.Errorf("outstanding-work line attributes the merged retry time as %q: %s", never, got)
				}
			}
		})
	}
}

// TestBriefingSupersededRecoveryReplyKeepsNoCurrentPromise holds §63's
// preservation requirement. A historical reply whose execution has since
// been overtaken must not regain a work or timing promise through the new
// composition — and a recovery watch the row's own contract still records
// is not an overtaken execution claim, so supersession must not silence it
// either.
func TestBriefingSupersededRecoveryReplyKeepsNoCurrentPromise(t *testing.T) {
	now := bcNow(t)
	queue, grace := now.Add(5*time.Minute), now.Add(12*time.Minute)
	graceToken := SlackDateToken(grace, "{time}")
	queued := []situation.IncidentState{{ID: "inc-queued", Triage: situation.TriageState{Phase: "pending", NextAt: &queue}}}

	reply := func(t *testing.T, incidents []situation.IncidentState, superseded bool) map[string]string {
		t.Helper()
		state := situation.ControllerState{Lifecycle: model.LifecycleRecoveryPending,
			Attention: model.AttentionObserve, RecoveryGraceUntil: &grace}
		if len(incidents) > 0 {
			state.TriagePhase, state.TriageDueAt = situation.TriagePhaseAwaitingDecision, &queue
		}
		c, w := brwDerived(t, state, incidents, &grace, now)
		b := bcBriefing()
		b.Firing, b.Resolved = 0, 4
		b.Work = w
		tr := bcRoot(t, model.LifecycleRecoveryPending, model.AttentionObserve, c, b).SourceTransition
		return bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: superseded})
	}

	t.Run("an overtaken investigation keeps neither its work nor its times", func(t *testing.T) {
		for surface, out := range reply(t, queued, true) {
			if !strings.Contains(out, supersededExecutionStep) {
				t.Errorf("%s does not state that the recorded status was superseded:\n%s", surface, out)
			}
			for _, never := range []string{graceToken, "Investigation is queued", "Next status check", "Watching for sustained recovery"} {
				if strings.Contains(out, never) {
					t.Errorf("%s replays %q on a superseded row:\n%s", surface, never, out)
				}
			}
		}
	})

	t.Run("the same row states both facts while it is current", func(t *testing.T) {
		for surface, out := range reply(t, queued, false) {
			for _, want := range []string{"Watching for sustained recovery through " + graceToken, "Investigation is queued"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s lacks %q while the row is current:\n%s", surface, want, out)
				}
			}
		}
	})

	t.Run("supersession does not silence a recovery watch that claims no execution", func(t *testing.T) {
		for surface, out := range reply(t, nil, true) {
			if !strings.Contains(out, "Watching for sustained recovery through "+graceToken) {
				t.Errorf("%s dropped the current recovery watch:\n%s", surface, out)
			}
		}
	})
}
