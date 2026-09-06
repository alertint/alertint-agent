// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// hsTransitionFor builds one controller-state Transition from a mutated
// baseline change — the unit both the priority rank table and the poke
// classifier are exercised against.
func hsTransitionFor(t *testing.T, mut func(c *AuthoritativeChange)) model.Transition {
	t.Helper()
	c := hsNext(t)
	if mut != nil {
		mut(&c)
	}
	return hsOnly(t, c)
}

func TestInterruptionPriorityRanks(t *testing.T) {
	cases := []struct {
		name string
		mut  func(c *AuthoritativeChange)
		want model.InterruptionPriority
	}{
		{
			name: "unquieted deterministic critical floor",
			mut: func(c *AuthoritativeChange) {
				c.Situation.Attention = model.AttentionUrgent
				c.Assessment.Attention = model.AttentionUrgent
			},
			want: model.InterruptionCritical,
		},
		{
			name: "urgent attention without a critical floor",
			mut: func(c *AuthoritativeChange) {
				c.Situation.Attention = model.AttentionUrgent
				c.Assessment.Attention = model.AttentionUrgent
				hsUseReason(c, reasonCodeDurationOutlier)
			},
			want: model.InterruptionHigh,
		},
		{
			name: "operator action required",
			mut: func(c *AuthoritativeChange) {
				c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
				hsUseReason(c, reasonCodeDurationOutlier)
			},
			want: model.InterruptionHigh,
		},
		{
			name: "actionable terminal uncertainty",
			mut: func(c *AuthoritativeChange) {
				hsClosedUnknown(c)
			},
			want: model.InterruptionHigh,
		},
		{
			name: "warranted investigation while AlertINT acts next",
			mut: func(c *AuthoritativeChange) {
				hsUseReason(c, reasonCodeDurationOutlier)
				c.Assessment.ActionContract = hsMonitoringContract(c.Now.Add(time.Minute))
			},
			want: model.InterruptionMedium,
		},
		{
			name: "informational observe state",
			mut: func(c *AuthoritativeChange) {
				c.Situation.Attention = model.AttentionObserve
				c.Assessment.Attention = model.AttentionObserve
				hsUseReason(c, reasonCodeDurationOutlier)
				c.Assessment.ActionContract = hsMonitoringContract(c.Now.Add(time.Minute))
			},
			want: model.InterruptionLow,
		},
		{
			name: "a quieted critical floor after recovery",
			mut:  hsRecovered,
			want: model.InterruptionLow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveInterruptionPriority(hsTransitionFor(t, tc.mut))
			if got != tc.want {
				t.Errorf("priority = %q, want %q", got, tc.want)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("derived priority rejected by the model: %v", err)
			}
		})
	}
}

func TestInterruptionPriorityPokeClasses(t *testing.T) {
	// Baseline prior: a published, non-critical Situation — duration_outlier
	// Sufficient reason, investigate Attention, AlertINT running Acute
	// Triage — so "newly crossed criticality" is a real crossing.
	priorChange := hsChange(t)
	hsUseReason(&priorChange, reasonCodeDurationOutlier)
	prior := hsOnly(t, priorChange)
	priorSum := hsPriorSummary(t, prior)

	next := func(t *testing.T, mut func(c *AuthoritativeChange)) model.Transition {
		t.Helper()
		c := hsChange(t)
		hsUseReason(&c, reasonCodeDurationOutlier)
		c.Now = prior.CreatedAt.Add(time.Minute)
		c.Situation.InputVersion = 8
		c.PriorTransition = &prior
		c.PriorSummary = &priorSum
		c.Assessment.ActionContract = hsRunningTriageContract(c.Now.Add(time.Minute))
		if mut != nil {
			mut(&c)
		}
		return hsOnly(t, c)
	}

	cases := []struct {
		name       string
		firstEver  bool
		mut        func(c *AuthoritativeChange)
		want       PokeClass
		wantCooled bool
	}{
		{
			name:      "first warranted publication",
			firstEver: true,
			want:      PokeFirstPublication,
		},
		{
			name: "newly crossed deterministic criticality",
			mut: func(c *AuthoritativeChange) {
				hsUseReason(c, reasonCodeCriticalAnchor)
			},
			want: PokeCriticalityCrossed,
		},
		{
			name: "valid urgent Attention",
			mut: func(c *AuthoritativeChange) {
				c.Situation.Attention = model.AttentionUrgent
				c.Assessment.Attention = model.AttentionUrgent
			},
			want: PokeUrgentAttention,
		},
		{
			name: "no-action to operator handoff",
			mut: func(c *AuthoritativeChange) {
				c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
			},
			want: PokeOperatorHandoff,
		},
		{
			name: "ordinary investigation progress is never a poke",
			mut: func(c *AuthoritativeChange) {
				c.Assessment.ActionContract = hsMonitoringContract(c.Now.Add(time.Minute))
			},
			want: PokeNone,
		},
		{
			name: "recurrence milestones never poke",
			mut: func(c *AuthoritativeChange) {
				c.RecurrenceCount = 25
			},
			want: PokeNone,
		},
		{
			name: "recovery never pokes",
			mut:  hsRecovered,
			want: PokeNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tr model.Transition
			var priorArg *model.Transition
			if tc.firstEver {
				c := hsChange(t)
				hsUseReason(&c, reasonCodeDurationOutlier)
				if tc.mut != nil {
					tc.mut(&c)
				}
				tr = hsOnly(t, c)
			} else {
				priorArg = &prior
				tr = next(t, tc.mut)
			}
			if got := ClassifyPoke(priorArg, tr); got != tc.want {
				t.Errorf("poke class = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInterruptionPriorityRequiredActionChangeIsCooldownGated(t *testing.T) {
	handedOffChange := hsChange(t)
	handedOffChange.Assessment.ActionContract = hsOperatorContract(handedOffChange.Now.Add(time.Minute))
	handedOff := hsOnly(t, handedOffChange)
	sum, err := ProjectEpisode(nil, handedOff)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}

	// AlertINT's own machinery moves (a different reconsideration trigger)
	// while the operator is asked for exactly the same thing: material,
	// journaled, but never a poke — a cooldown restricts a changed action,
	// it does not turn an unchanged one into one (review round 3, R3-F1).
	changed := hsChange(t)
	changed.Now = handedOff.CreatedAt.Add(time.Minute)
	changed.Situation.InputVersion = 9
	changed.PriorTransition = &handedOff
	changed.PriorSummary = &sum
	contract := hsOperatorContract(changed.Now.Add(time.Minute))
	contract.NextUpdateOn = []model.NextUpdateOn{model.NextUpdateOnSourceResolution}
	changed.Assessment.ActionContract = contract
	next := hsOnly(t, changed)
	if next.Reason != model.ReasonOperatorContractChanged {
		t.Fatalf("fixture: reason = %q, want operator_contract_changed (still material)", next.Reason)
	}
	if got := ClassifyPoke(&handedOff, next); got != PokeNone {
		t.Fatalf("poke class for internal work progress = %q, want %q", got, PokeNone)
	}

	// The reserved class itself: gated by the cooldown, unlike every
	// escalation class. Reachable only once a second supported operator
	// action exists (the catalog has one today).
	if !PokeRequiredActionChanged.CooldownApplies() {
		t.Error("a materially changed required action must respect the repage cooldown")
	}
	for _, escalation := range []PokeClass{PokeFirstPublication, PokeCriticalityCrossed, PokeUrgentAttention, PokeOperatorHandoff} {
		if escalation.CooldownApplies() {
			t.Errorf("%q must bypass the repage cooldown", escalation)
		}
	}
}

// TestInterruptionPriorityInternalWorkProgressNeverPokes pins review round
// 3, R3-F1, on contracts derived through production DeriveActionContract:
// Triage starting and Triage finishing keep investigate_situation
// outstanding and are not a changed required action.
func TestInterruptionPriorityInternalWorkProgressNeverPokes(t *testing.T) {
	for name, phase := range map[string]TriagePhase{"triage_started": TriagePhaseInFlight, "triage_finished": TriagePhaseNone} {
		t.Run(name, func(t *testing.T) {
			c := hsNext(t)
			hsUseReason(&c, reasonCodeDurationOutlier)
			action := model.OperatorActionInvestigateSituation
			state := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate,
				OperatorActionRequired: &action, TriagePhase: TriagePhaseAwaitingDecision}
			c.PriorTransition.ActionContract = DeriveActionContract(state, DeriveCadence(state), c.Now.Add(-20*time.Minute))
			c.PriorTransition.Projection = c.Projection
			c.PriorSummary.ActionContract = c.PriorTransition.ActionContract
			state.TriagePhase = phase
			c.Assessment.ActionContract = DeriveActionContract(state, DeriveCadence(state), c.Now)
			next := hsOnly(t, c)
			if got := ClassifyPoke(c.PriorTransition, next); got != PokeNone {
				t.Fatalf("poke class = %q, want %q: unchanged investigate_situation plus internal progress", got, PokeNone)
			}
		})
	}
}

func TestInterruptionPriorityFloorComparison(t *testing.T) {
	cases := []struct {
		priority, floor model.InterruptionPriority
		want            bool
	}{
		{model.InterruptionCritical, model.InterruptionHigh, true},
		{model.InterruptionCritical, model.InterruptionCritical, true},
		{model.InterruptionHigh, model.InterruptionHigh, true},
		{model.InterruptionMedium, model.InterruptionHigh, false},
		{model.InterruptionLow, model.InterruptionMedium, false},
		{model.InterruptionLow, model.InterruptionLow, true},
		{model.InterruptionLow, model.InterruptionPriority(""), true},
	}
	for _, tc := range cases {
		if got := MeetsSlackFloor(tc.priority, tc.floor); got != tc.want {
			t.Errorf("MeetsSlackFloor(%q, %q) = %v, want %v", tc.priority, tc.floor, got, tc.want)
		}
	}
}

// TestInterruptionPriorityArtifactSiblingIsNotAComparisonBasis pins why
// selectPoke classifies every Transition against the state BEFORE the
// commit rather than against the preceding Transition of the same commit.
// An `operator_artifact_recorded` Transition copies the commit's NEW
// lifecycle/Attention/contract verbatim (it changes none of them), so using
// it as the comparison basis makes the controller-state Transition compare
// new state against itself — no crossing, no escalation, no poke.
func TestInterruptionPriorityArtifactSiblingIsNotAComparisonBasis(t *testing.T) {
	c := hsNext(t)
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))}
	got, err := BuildTransitions(c)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d transitions, want the artifact plus the escalation", len(got))
	}
	artifact, escalation := got[0], got[1]

	if artifact.Attention != escalation.Attention {
		t.Fatalf("fixture no longer models the hazard: artifact attention %q vs escalation %q",
			artifact.Attention, escalation.Attention)
	}
	if class := ClassifyPoke(&artifact, escalation); class != PokeNone {
		t.Errorf("classifying against a same-commit artifact sibling = %q; the characterization this "+
			"test guards has changed, so recheck selectPoke", class)
	}
	if class := ClassifyPoke(c.PriorTransition, escalation); class != PokeUrgentAttention {
		t.Errorf("classifying against the true pre-commit prior = %q, want %q", class, PokeUrgentAttention)
	}
	// The durable Transition and the intent plan must agree that this is a
	// poke: controllerTransition stamps the priority from the same
	// classification the planner uses.
	if escalation.InterruptionPriority == nil {
		t.Error("the escalation transition records no interruption priority")
	}
}

func TestInterruptionPriorityArtifactsNeverPoke(t *testing.T) {
	c := hsNext(t)
	c.OperatorArtifacts = []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))}
	got, err := BuildTransitions(c)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d transitions, want 1", len(got))
	}
	if class := ClassifyPoke(c.PriorTransition, got[0]); class != PokeNone {
		t.Errorf("artifact poke class = %q, want %q", class, PokeNone)
	}
}

// ----------------------------------------------------------------------
// Handoff revalidation (review round 1, R1-F5).
// ----------------------------------------------------------------------

func TestHandoffStillCurrentComparesTheActionBasis(t *testing.T) {
	now := hsNow(t)
	handoffChange := hsChange(t)
	handoffChange.Assessment.ActionContract = hsOperatorContract(now.Add(time.Minute))
	handoff := hsOnly(t, handoffChange)
	if handoff.ActionContract.OperatorActionRequired == nil {
		t.Fatal("fixture: the handoff transition carries no operator action")
	}
	base, err := ProjectEpisode(nil, handoff)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}

	// An annotation folded after the handoff: sequence advanced, nothing
	// steered.
	annotated := base
	annotated.Version++
	annotated.SourceTransitionSequence = handoff.Sequence + 1
	annotated.RecordedOperatorContext = []string{"operator: checked the deploy log"}
	if !HandoffStillCurrent(handoff, annotated) {
		t.Error("an annotation must not cancel a still-required handoff")
	}

	// The same action refreshed with a new deadline is the same action.
	refreshed := base
	refreshed.SourceTransitionSequence = handoff.Sequence + 1
	refreshed.ActionContract.NextUpdateAt = timePtr(now.Add(time.Hour))
	if !HandoffStillCurrent(handoff, refreshed) {
		t.Error("a refreshed deadline does not change the requested action")
	}

	// The action was withdrawn: AlertINT took the Situation back.
	withdrawn := base
	withdrawn.SourceTransitionSequence = handoff.Sequence + 1
	withdrawn.ActionContract = hsMonitoringContract(now.Add(time.Minute))
	if HandoffStillCurrent(handoff, withdrawn) {
		t.Error("a handoff whose action was withdrawn is no longer current")
	}

	// The Situation terminalized.
	terminal := base
	terminal.SourceTransitionSequence = handoff.Sequence + 1
	terminal.TerminalAt = timePtr(now.Add(time.Hour))
	terminal.ActionContract = hsTerminalContract()
	if HandoffStillCurrent(handoff, terminal) {
		t.Error("a terminal Situation has no current interruption")
	}

	// Attention de-escalated below the handoff's while the action text
	// happened to survive.
	calmer := base
	calmer.SourceTransitionSequence = handoff.Sequence + 1
	calmer.CurrentAttention = model.AttentionObserve
	if handoff.Attention == model.AttentionObserve {
		t.Fatal("fixture: the handoff is already at observe Attention")
	}
	if HandoffStillCurrent(handoff, calmer) {
		t.Error("de-escalated Attention demotes the poke it followed")
	}

	// A summary that predates the handoff cannot confirm it.
	stale := base
	stale.SourceTransitionSequence = handoff.Sequence - 1
	if HandoffStillCurrent(handoff, stale) {
		t.Error("a summary older than the handoff cannot confirm it as current")
	}
}

func TestHandoffStillCurrentEscalationPokeNeedsNoOperatorAction(t *testing.T) {
	// hsChange's conclusion is the deterministic critical floor: an urgent
	// escalation poke with no operator action.
	c := hsChange(t)
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	poke := hsOnly(t, c)
	if poke.ActionContract.OperatorActionRequired != nil {
		t.Fatal("fixture: the escalation poke must carry no operator action")
	}
	sum, err := ProjectEpisode(nil, poke)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}
	later := sum
	later.SourceTransitionSequence = poke.Sequence + 1
	if !HandoffStillCurrent(poke, later) {
		t.Error("an escalation poke stays current while its Attention holds")
	}
	later.CurrentAttention = model.AttentionInvestigate
	if HandoffStillCurrent(poke, later) {
		t.Error("an escalation poke is demoted once Attention de-escalates")
	}
}

// TestHandoffStillCurrentIgnoresAlertINTMachinery pins review round 2,
// R2-F2: contracts derived through the production DeriveActionContract for
// "Triage in flight" and "Triage complete" differ in AlertINT's action,
// status, and update triggers while the required human action is
// identical — the queued handoff is still current.
func TestHandoffStillCurrentIgnoresAlertINTMachinery(t *testing.T) {
	c := hsNext(t)
	action := model.OperatorActionInvestigateSituation
	state := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate,
		OperatorActionRequired: &action, TriagePhase: TriagePhaseInFlight}
	handoff := *c.PriorTransition
	handoff.ActionContract = DeriveActionContract(state, DeriveCadence(state), c.Now)
	summary := *c.PriorSummary
	summary.SourceTransitionSequence = handoff.Sequence + 1

	// Triage completed; nothing is in flight; the human action is still owed.
	state.TriagePhase = TriagePhaseNone
	summary.ActionContract = DeriveActionContract(state, DeriveCadence(state), c.Now)
	if err := summary.Validate(); err != nil {
		t.Fatal(err)
	}
	if operatorContractTuple(summary.ActionContract) == operatorContractTuple(handoff.ActionContract) {
		t.Fatal("fixture: the two contracts must differ in AlertINT machinery")
	}
	if !HandoffStillCurrent(handoff, summary) {
		t.Fatal("AlertINT work completed, but the identical outstanding operator action was treated as no longer current")
	}

	// Different reconsideration triggers, same human action: still current.
	summary.ActionContract = handoff.ActionContract
	summary.ActionContract.NextUpdateOn = []model.NextUpdateOn{model.NextUpdateOnSourceResolution}
	if !HandoffStillCurrent(handoff, summary) {
		t.Fatal("a changed update trigger is AlertINT machinery, not a changed human action")
	}

	// The human action withdrawn: demoted.
	summary.ActionContract = DeriveActionContract(ControllerState{Lifecycle: model.LifecycleActive,
		Attention: model.AttentionInvestigate, TriagePhase: TriagePhaseNone}, model.CadenceNormal, c.Now)
	if summary.ActionContract.OperatorActionRequired != nil {
		t.Fatal("fixture: the withdrawn contract must carry no operator action")
	}
	if HandoffStillCurrent(handoff, summary) {
		t.Fatal("a withdrawn human action must demote the handoff")
	}
}
