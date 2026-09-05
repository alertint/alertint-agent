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

	changed := hsChange(t)
	changed.Now = handedOff.CreatedAt.Add(time.Minute)
	changed.Situation.InputVersion = 9
	changed.PriorTransition = &handedOff
	changed.PriorSummary = &sum
	contract := hsOperatorContract(changed.Now.Add(time.Minute))
	contract.NextUpdateOn = []model.NextUpdateOn{model.NextUpdateOnSourceResolution}
	changed.Assessment.ActionContract = contract
	next := hsOnly(t, changed)

	if got := ClassifyPoke(&handedOff, next); got != PokeRequiredActionChanged {
		t.Fatalf("poke class = %q, want %q", got, PokeRequiredActionChanged)
	}
	if !PokeRequiredActionChanged.CooldownApplies() {
		t.Error("a materially changed required action must respect the repage cooldown")
	}
	for _, escalation := range []PokeClass{PokeFirstPublication, PokeCriticalityCrossed, PokeUrgentAttention, PokeOperatorHandoff} {
		if escalation.CooldownApplies() {
			t.Errorf("%q must bypass the repage cooldown", escalation)
		}
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
