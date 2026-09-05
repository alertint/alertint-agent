// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// hsCommitOf runs this task's two history functions over one change: the
// derived Transitions plus the summary folded once per Transition.
func hsCommitOf(t *testing.T, c AuthoritativeChange) ([]model.Transition, model.EpisodeSummary) {
	t.Helper()
	trs, err := BuildTransitions(c)
	if err != nil {
		t.Fatalf("BuildTransitions: %v", err)
	}
	cur := model.EpisodeSummary{}
	prior := c.PriorSummary
	if prior != nil {
		cur = *prior
	}
	for i, tr := range trs {
		next, err := ProjectEpisode(prior, tr)
		if err != nil {
			t.Fatalf("ProjectEpisode(%d): %v", i, err)
		}
		cur = next
		prior = &cur
	}
	return trs, cur
}

// hsPub builds the baseline PublicationInput for a commit: an already
// published root, no floor, the plan's 15-minute repage cooldown.
func hsPub(c AuthoritativeChange, trs []model.Transition, sum model.EpisodeSummary) PublicationInput {
	in := PublicationInput{
		Situation:       c.Situation,
		Transitions:     trs,
		Summary:         sum,
		PriorTransition: c.PriorTransition,
		RootPublished:   true,
		SlackFloor:      model.InterruptionLow,
		RepageCooldown:  15 * time.Minute,
		Drill:           c.Drill,
		Now:             c.Now,
	}
	if len(trs) > 0 {
		in.ContractDeadlineAt = trs[len(trs)-1].ActionContract.NextUpdateAt
	}
	return in
}

func hsPlan(t *testing.T, in PublicationInput) []model.NotificationIntent {
	t.Helper()
	got, err := PlanNotificationIntents(in)
	if err != nil {
		t.Fatalf("PlanNotificationIntents: %v", err)
	}
	for i, intent := range got {
		if err := intent.Validate(); err != nil {
			t.Fatalf("intent %d failed model validation: %v", i, err)
		}
	}
	return got
}

func hsIntentsOfClass(intents []model.NotificationIntent, class model.EffectClass) []model.NotificationIntent {
	out := []model.NotificationIntent{}
	for _, i := range intents {
		if i.EffectClass == class {
			out = append(out, i)
		}
	}
	return out
}

// ----------------------------------------------------------------------
// Roots.
// ----------------------------------------------------------------------

func TestPlanNotificationIntentsInitialRoot(t *testing.T) {
	c := hsChange(t)
	trs, sum := hsCommitOf(t, c)
	in := hsPub(c, trs, sum)
	in.RootPublished = false

	got := hsPlan(t, in)
	roots := hsIntentsOfClass(got, model.EffectRootSync)
	if len(roots) != 1 {
		t.Fatalf("got %d root_sync intents, want 1", len(roots))
	}
	root := roots[0]
	if !root.MainChannelPoke {
		t.Error("the first warranted publication must be a main-channel poke")
	}
	if root.InterruptionPriority == nil {
		t.Fatal("a poke intent must carry the priority it was floor-evaluated against")
	}
	if root.SummaryVersion == nil || *root.SummaryVersion != sum.Version {
		t.Errorf("summary version = %v, want %d", root.SummaryVersion, sum.Version)
	}
	if root.TransitionID == nil || *root.TransitionID != trs[len(trs)-1].ID {
		t.Errorf("root authority transition = %v, want %q", root.TransitionID, trs[len(trs)-1].ID)
	}
	if root.TransitionSequence == nil || *root.TransitionSequence != trs[len(trs)-1].Sequence {
		t.Errorf("root transition sequence = %v, want %d", root.TransitionSequence, trs[len(trs)-1].Sequence)
	}
	if root.RequiresRoot {
		t.Error("root_sync must not depend on a root")
	}
	if root.ContractDeadlineAt == nil || !root.ContractDeadlineAt.Equal(*in.ContractDeadlineAt) {
		t.Errorf("contract deadline = %v, want %v", root.ContractDeadlineAt, in.ContractDeadlineAt)
	}
	if root.Status != model.IntentPending {
		t.Errorf("status = %q, want pending", root.Status)
	}
	if root.ClientMessageID == "" {
		t.Error("client message id is empty")
	}
	if broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff); len(broadcasts) != 0 {
		t.Errorf("the first publication is the poke; got %d extra broadcasts", len(broadcasts))
	}
}

func TestPlanNotificationIntentsLaterRootSyncIsNotAPoke(t *testing.T) {
	c := hsNext(t)
	hsUseReason(&c, reasonCodeDurationOutlier)
	concl := *c.Projection.Assessment
	concl.Impact = model.ImpactConfirmed
	c.Projection.Assessment = &concl
	c.Assessment.Impact = model.ImpactConfirmed

	trs, sum := hsCommitOf(t, c)
	got := hsPlan(t, hsPub(c, trs, sum))

	roots := hsIntentsOfClass(got, model.EffectRootSync)
	if len(roots) != 1 {
		t.Fatalf("got %d root_sync intents, want 1", len(roots))
	}
	if roots[0].MainChannelPoke {
		t.Error("a root edit is never a poke")
	}
	if roots[0].InterruptionPriority != nil {
		t.Error("a non-poke intent must carry no interruption priority")
	}
}

func TestPlanNotificationIntentsTerminalRootCarriesNoPromise(t *testing.T) {
	c := hsNext(t)
	hsRecovered(&c)
	trs, sum := hsCommitOf(t, c)
	in := hsPub(c, trs, sum)

	got := hsPlan(t, in)
	roots := hsIntentsOfClass(got, model.EffectRootSync)
	if len(roots) != 1 {
		t.Fatalf("got %d root_sync intents, want 1", len(roots))
	}
	if roots[0].ContractDeadlineAt != nil {
		t.Errorf("a terminal root promises no update, got %v", roots[0].ContractDeadlineAt)
	}
	if threads := hsIntentsOfClass(got, model.EffectThreadAppend); len(threads) != 1 {
		t.Errorf("got %d thread entries, want 1 for the terminal transition", len(threads))
	}
}

// ----------------------------------------------------------------------
// R4: the deadline refresh.
// ----------------------------------------------------------------------

func TestPlanNotificationIntentsDeadlineRefresh(t *testing.T) {
	c := hsNext(t)
	base := hsPub(c, nil, model.EpisodeSummary{})
	base.Summary = *c.PriorSummary
	base.ContractDeadlineAt = timePtr(c.Now.Add(5 * time.Minute))
	base.LastDeliveredRootDeadlineAt = timePtr(c.Now.Add(-time.Minute))
	base.LatestRootSyncVersion = &c.PriorSummary.Version

	t.Run("published root with an expired promise and a new deadline", func(t *testing.T) {
		got := hsPlan(t, base)
		if len(got) != 1 {
			t.Fatalf("got %d intents, want exactly one refresh: %+v", len(got), got)
		}
		refresh := got[0]
		if refresh.EffectClass != model.EffectRootSync {
			t.Fatalf("effect class = %q, want root_sync", refresh.EffectClass)
		}
		if refresh.MainChannelPoke {
			t.Error("a deadline refresh is never a poke")
		}
		if refresh.ContractDeadlineAt == nil || !refresh.ContractDeadlineAt.Equal(*base.ContractDeadlineAt) {
			t.Errorf("contract deadline = %v, want %v", refresh.ContractDeadlineAt, base.ContractDeadlineAt)
		}
		if refresh.SummaryVersion == nil || *refresh.SummaryVersion != base.Summary.Version {
			t.Errorf("summary version = %v, want the unchanged %d", refresh.SummaryVersion, base.Summary.Version)
		}
		if refresh.TransitionID == nil || *refresh.TransitionID != c.PriorTransition.ID {
			t.Errorf("authority transition = %v, want the prior %q", refresh.TransitionID, c.PriorTransition.ID)
		}
	})

	t.Run("unpublished root refreshes nothing", func(t *testing.T) {
		in := base
		in.RootPublished = false
		if got := hsPlan(t, in); len(got) != 0 {
			t.Fatalf("got %d intents, want 0: %+v", len(got), got)
		}
	})

	t.Run("a promise that has not passed refreshes nothing", func(t *testing.T) {
		in := base
		in.LastDeliveredRootDeadlineAt = timePtr(c.Now.Add(time.Minute))
		if got := hsPlan(t, in); len(got) != 0 {
			t.Fatalf("got %d intents, want 0: %+v", len(got), got)
		}
	})

	t.Run("an unchanged deadline refreshes nothing", func(t *testing.T) {
		in := base
		in.ContractDeadlineAt = in.LastDeliveredRootDeadlineAt
		if got := hsPlan(t, in); len(got) != 0 {
			t.Fatalf("got %d intents, want 0: %+v", len(got), got)
		}
	})

	t.Run("a terminal commit with no deadline refreshes nothing", func(t *testing.T) {
		in := base
		in.ContractDeadlineAt = nil
		if got := hsPlan(t, in); len(got) != 0 {
			t.Fatalf("got %d intents, want 0: %+v", len(got), got)
		}
	})
}

func TestPlanNotificationIntentsQuietSituationCreatesNothing(t *testing.T) {
	c := hsNext(t)
	in := hsPub(c, nil, *c.PriorSummary)
	in.ContractDeadlineAt = timePtr(c.Now.Add(5 * time.Minute))
	in.LastDeliveredRootDeadlineAt = timePtr(c.Now.Add(4 * time.Minute))

	if got := hsPlan(t, in); len(got) != 0 {
		t.Fatalf("a quiet Situation created %d Slack intents, want 0: %+v", len(got), got)
	}
}

// ----------------------------------------------------------------------
// Immutable journal entries and handoff broadcasts.
// ----------------------------------------------------------------------

func TestPlanNotificationIntentsJournalAppendsInSequenceOrder(t *testing.T) {
	c := hsNext(t)
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	c.OperatorArtifacts = []OperatorArtifactInput{
		hsArtifact("input-1", artifactKindAnnotation, hsNow(t)),
		hsArtifact("input-2", artifactKindVerdict, hsNow(t).Add(time.Second)),
	}
	trs, sum := hsCommitOf(t, c)
	got := hsPlan(t, hsPub(c, trs, sum))

	threads := hsIntentsOfClass(got, model.EffectThreadAppend)
	if len(threads) != len(trs) {
		t.Fatalf("got %d thread entries, want one per journaled transition (%d)", len(threads), len(trs))
	}
	for i, intent := range threads {
		if intent.TransitionID == nil || *intent.TransitionID != trs[i].ID {
			t.Errorf("thread entry %d references %v, want %q", i, intent.TransitionID, trs[i].ID)
		}
		if intent.TransitionSequence == nil || *intent.TransitionSequence != trs[i].Sequence {
			t.Errorf("thread entry %d sequence = %v, want %d", i, intent.TransitionSequence, trs[i].Sequence)
		}
		if !intent.RequiresRoot {
			t.Errorf("thread entry %d must wait for durable root coordinates", i)
		}
		if intent.MainChannelPoke {
			t.Errorf("thread entry %d must never be a poke", i)
		}
		if intent.SummaryVersion != nil {
			t.Errorf("thread entry %d must render its own transition, not a summary version", i)
		}
	}
}

func TestPlanNotificationIntentsOperatorHandoffBroadcast(t *testing.T) {
	c := hsNext(t)
	c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
	trs, sum := hsCommitOf(t, c)
	got := hsPlan(t, hsPub(c, trs, sum))

	threads := hsIntentsOfClass(got, model.EffectThreadAppend)
	if len(threads) != 1 {
		t.Fatalf("got %d thread entries, want exactly one journal entry", len(threads))
	}
	broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff)
	if len(broadcasts) != 1 {
		t.Fatalf("got %d broadcast effects, want at most one (and exactly one here)", len(broadcasts))
	}
	if !broadcasts[0].MainChannelPoke {
		t.Error("the handoff broadcast must be the main-channel poke")
	}
	if broadcasts[0].InterruptionPriority == nil {
		t.Fatal("the handoff broadcast carries no interruption priority")
	}
	if !broadcasts[0].RequiresRoot {
		t.Error("a broadcast reply must wait for durable root coordinates")
	}
	roots := hsIntentsOfClass(got, model.EffectRootSync)
	if len(roots) != 1 {
		t.Fatalf("got %d root_sync intents, want the root edit that precedes the broadcast", len(roots))
	}
	if roots[0].MainChannelPoke {
		t.Error("the root edit for a handoff is never itself a poke")
	}
}

// TestPlanNotificationIntentsAtMostOneBroadcastPerCommit pins BOTH bounds:
// several qualifying escalations in one commit still interrupt the channel
// only once, and a commit that qualifies at all always produces that one
// broadcast — including when operator artifacts are journaled ahead of the
// controller-state Transition in the same commit (R1). An artifact
// Transition copies the commit's new state verbatim, so classifying the
// controller-state Transition against it would compare new state with
// itself and silently swallow the poke.
func TestPlanNotificationIntentsAtMostOneBroadcastPerCommit(t *testing.T) {
	build := func(t *testing.T, artifacts ...OperatorArtifactInput) []model.NotificationIntent {
		t.Helper()
		c := hsNext(t)
		c.Situation.Attention = model.AttentionUrgent
		c.Assessment.Attention = model.AttentionUrgent
		c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
		c.OperatorArtifacts = artifacts
		trs, sum := hsCommitOf(t, c)
		return hsPlan(t, hsPub(c, trs, sum))
	}

	cases := []struct {
		name      string
		artifacts []OperatorArtifactInput
	}{
		{name: "no pending artifacts"},
		{name: "one pending artifact", artifacts: []OperatorArtifactInput{
			hsArtifact("input-1", artifactKindAnnotation, hsNow(t)),
		}},
		{name: "two pending artifacts", artifacts: []OperatorArtifactInput{
			hsArtifact("input-1", artifactKindAnnotation, hsNow(t)),
			hsArtifact("input-2", artifactKindVerdict, hsNow(t).Add(time.Second)),
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := build(t, tc.artifacts...)
			broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff)
			if len(broadcasts) != 1 {
				t.Fatalf("got %d broadcast effects, want exactly one escalation poke", len(broadcasts))
			}
			if !broadcasts[0].MainChannelPoke || broadcasts[0].InterruptionPriority == nil {
				t.Error("the escalation broadcast must be a poke carrying its evaluated priority")
			}
			// The broadcast must name the controller-state Transition (last
			// in the commit, per R1) — the same authority the root_sync
			// references — never an artifact Transition.
			roots := hsIntentsOfClass(got, model.EffectRootSync)
			if len(roots) != 1 {
				t.Fatalf("got %d root_sync intents, want 1", len(roots))
			}
			if broadcasts[0].TransitionID == nil || roots[0].TransitionID == nil ||
				*broadcasts[0].TransitionID != *roots[0].TransitionID {
				t.Errorf("broadcast references %v, want the commit's authority transition %v",
					broadcasts[0].TransitionID, roots[0].TransitionID)
			}
		})
	}
}

// TestPlanNotificationIntentsEscalationSurvivesJournaledArtifacts is the
// direct regression for the same defect, stated as a comparison: the same
// escalation must produce the same poke with and without an operator
// artifact journaled ahead of it in the same commit.
func TestPlanNotificationIntentsEscalationSurvivesJournaledArtifacts(t *testing.T) {
	escalate := func(t *testing.T, artifacts []OperatorArtifactInput) int {
		t.Helper()
		c := hsNext(t)
		c.Situation.Attention = model.AttentionUrgent
		c.Assessment.Attention = model.AttentionUrgent
		c.OperatorArtifacts = artifacts
		trs, sum := hsCommitOf(t, c)
		return len(hsIntentsOfClass(hsPlan(t, hsPub(c, trs, sum)), model.EffectBroadcastHandoff))
	}

	without := escalate(t, nil)
	with := escalate(t, []OperatorArtifactInput{hsArtifact("input-1", artifactKindAnnotation, hsNow(t))})
	if without != 1 {
		t.Fatalf("urgent escalation alone produced %d broadcasts, want 1", without)
	}
	if with != without {
		t.Errorf("a journaled operator artifact changed the escalation poke: %d broadcasts with, %d without", with, without)
	}
}

// ----------------------------------------------------------------------
// Floor, cooldown, escalation.
// ----------------------------------------------------------------------

func TestPlanNotificationIntentsFloorWithholdsThePoke(t *testing.T) {
	c := hsChange(t)
	c.Situation.Attention = model.AttentionObserve
	c.Assessment.Attention = model.AttentionObserve
	hsUseReason(&c, reasonCodeDurationOutlier)
	c.Assessment.ActionContract = hsMonitoringContract(c.Now.Add(time.Minute))

	trs, sum := hsCommitOf(t, c)
	in := hsPub(c, trs, sum)
	in.RootPublished = false
	in.SlackFloor = model.InterruptionHigh

	got := hsPlan(t, in)
	roots := hsIntentsOfClass(got, model.EffectRootSync)
	if len(roots) != 1 {
		t.Fatalf("got %d root_sync intents, want 1 (a withheld decision, never an absent row)", len(roots))
	}
	if roots[0].Status != model.IntentWithheld {
		t.Errorf("status = %q, want withheld_by_operator_slack_floor", roots[0].Status)
	}
	if !roots[0].MainChannelPoke || roots[0].InterruptionPriority == nil {
		t.Error("a withheld poke still records that it was a poke and the priority it was judged against")
	}
	if threads := hsIntentsOfClass(got, model.EffectThreadAppend); len(threads) != 1 {
		t.Errorf("the floor must never suppress a non-broadcast journal entry, got %d", len(threads))
	}
	for _, intent := range hsIntentsOfClass(got, model.EffectThreadAppend) {
		if intent.Status != model.IntentPending {
			t.Errorf("journal entry status = %q, want pending", intent.Status)
		}
	}
}

func TestPlanNotificationIntentsWithheldBroadcastKeepsTheJournal(t *testing.T) {
	c := hsNext(t)
	hsUseReason(&c, reasonCodeDurationOutlier)
	c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
	trs, sum := hsCommitOf(t, c)
	in := hsPub(c, trs, sum)
	in.SlackFloor = model.InterruptionCritical

	got := hsPlan(t, in)
	broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff)
	if len(broadcasts) != 1 {
		t.Fatalf("got %d broadcast effects, want one withheld decision", len(broadcasts))
	}
	if broadcasts[0].Status != model.IntentWithheld {
		t.Errorf("status = %q, want withheld_by_operator_slack_floor", broadcasts[0].Status)
	}
	threads := hsIntentsOfClass(got, model.EffectThreadAppend)
	if len(threads) != 1 || threads[0].Status != model.IntentPending {
		t.Errorf("the journal entry must survive the floor, got %+v", threads)
	}
}

func TestPlanNotificationIntentsRepageCooldown(t *testing.T) {
	handedOffChange := hsChange(t)
	handedOffChange.Assessment.ActionContract = hsOperatorContract(handedOffChange.Now.Add(time.Minute))
	handedOff := hsOnly(t, handedOffChange)
	sum, err := ProjectEpisode(nil, handedOff)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}

	changeAt := func(offset time.Duration, mut func(c *AuthoritativeChange)) AuthoritativeChange {
		c := hsChange(t)
		c.Now = handedOff.CreatedAt.Add(offset)
		c.Situation.InputVersion = 9
		c.PriorTransition = &handedOff
		c.PriorSummary = &sum
		contract := hsOperatorContract(c.Now.Add(time.Minute))
		contract.NextUpdateOn = []model.NextUpdateOn{model.NextUpdateOnSourceResolution}
		c.Assessment.ActionContract = contract
		if mut != nil {
			mut(&c)
		}
		return c
	}

	t.Run("a changed required action inside the cooldown does not repage", func(t *testing.T) {
		c := changeAt(2*time.Minute, nil)
		trs, folded := hsCommitOf(t, c)
		in := hsPub(c, trs, folded)
		in.LastMainChannelPokeAt = timePtr(handedOff.CreatedAt)

		got := hsPlan(t, in)
		if broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff); len(broadcasts) != 0 {
			t.Errorf("got %d broadcasts inside the cooldown, want 0", len(broadcasts))
		}
		if threads := hsIntentsOfClass(got, model.EffectThreadAppend); len(threads) != 1 {
			t.Errorf("the journal entry is never cooled down, got %d", len(threads))
		}
	})

	t.Run("a changed required action after the cooldown repages", func(t *testing.T) {
		c := changeAt(20*time.Minute, nil)
		trs, folded := hsCommitOf(t, c)
		in := hsPub(c, trs, folded)
		in.LastMainChannelPokeAt = timePtr(handedOff.CreatedAt)

		got := hsPlan(t, in)
		if broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff); len(broadcasts) != 1 {
			t.Errorf("got %d broadcasts after the cooldown, want 1", len(broadcasts))
		}
	})

	t.Run("escalation bypasses the cooldown", func(t *testing.T) {
		c := changeAt(2*time.Minute, func(c *AuthoritativeChange) {
			c.Situation.Attention = model.AttentionUrgent
			c.Assessment.Attention = model.AttentionUrgent
		})
		trs, folded := hsCommitOf(t, c)
		in := hsPub(c, trs, folded)
		in.LastMainChannelPokeAt = timePtr(handedOff.CreatedAt)

		got := hsPlan(t, in)
		broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff)
		if len(broadcasts) != 1 {
			t.Fatalf("got %d broadcasts, want 1 escalation that bypasses the cooldown", len(broadcasts))
		}
		if broadcasts[0].InterruptionPriority == nil || *broadcasts[0].InterruptionPriority != model.InterruptionCritical {
			t.Errorf("escalation priority = %v, want critical", broadcasts[0].InterruptionPriority)
		}
	})
}

func TestPlanNotificationIntentsCriticalPublicationWithoutL2(t *testing.T) {
	// The L2 provider is unavailable, so the authoritative Assessment is a
	// deterministic fallback — the critical floor still publishes and still
	// pokes, at critical priority, past any configured floor.
	c := hsChange(t)
	c.Derivation = model.DerivationDeterministicFallback
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	concl := *c.Projection.Assessment
	concl.EvidenceQuality = model.EvidenceQualityDegraded
	concl.LimitationCodes = []string{"semantic_assessment_unavailable"}
	c.Projection.Assessment = &concl
	c.Assessment.EvidenceQuality = model.EvidenceQualityDegraded

	trs, sum := hsCommitOf(t, c)
	in := hsPub(c, trs, sum)
	in.RootPublished = false
	in.SlackFloor = model.InterruptionHigh

	got := hsPlan(t, in)
	roots := hsIntentsOfClass(got, model.EffectRootSync)
	if len(roots) != 1 {
		t.Fatalf("got %d root_sync intents, want 1", len(roots))
	}
	if roots[0].Status != model.IntentPending {
		t.Errorf("status = %q, want pending — critical always passes the floor", roots[0].Status)
	}
	if roots[0].InterruptionPriority == nil || *roots[0].InterruptionPriority != model.InterruptionCritical {
		t.Errorf("priority = %v, want critical", roots[0].InterruptionPriority)
	}
	if trs[0].Actor != model.ActorDeterministicController {
		t.Errorf("actor = %q, want deterministic_controller for a fallback Assessment", trs[0].Actor)
	}
}

// ----------------------------------------------------------------------
// Recurrence, recovery, refire, drills, identity.
// ----------------------------------------------------------------------

func TestPlanNotificationIntentsRecurrenceMilestoneStaysInThread(t *testing.T) {
	c := hsNext(t)
	c.RecurrenceCount = 10
	trs, sum := hsCommitOf(t, c)
	got := hsPlan(t, hsPub(c, trs, sum))

	if broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff); len(broadcasts) != 0 {
		t.Errorf("a recurrence milestone must never broadcast, got %d", len(broadcasts))
	}
	threads := hsIntentsOfClass(got, model.EffectThreadAppend)
	if len(threads) != 1 {
		t.Fatalf("got %d thread entries, want 1", len(threads))
	}
	if threads[0].MainChannelPoke {
		t.Error("a recurrence milestone is never a poke")
	}
	if sum.RecurrenceCount != 10 {
		t.Errorf("summary recurrence count = %d, want 10", sum.RecurrenceCount)
	}
}

func TestPlanNotificationIntentsRecoveryAndRefire(t *testing.T) {
	recoveringChange := hsChange(t)
	recoveringChange.Situation.Lifecycle = model.LifecycleRecoveryPending
	recoveringChange.Assessment.Lifecycle = model.LifecycleRecoveryPending
	recoveringChange.Situation.RecoveryObservedAt = timePtr(recoveringChange.Now)
	recoveringChange.Projection.RecoveryObservedAt = timePtr(recoveringChange.Now)
	monitoring := hsOnly(t, recoveringChange)
	sum, err := ProjectEpisode(nil, monitoring)
	if err != nil {
		t.Fatalf("ProjectEpisode: %v", err)
	}

	refire := hsChange(t)
	refire.Now = monitoring.CreatedAt.Add(time.Minute)
	refire.Situation.InputVersion = 8
	refire.PriorTransition = &monitoring
	refire.PriorSummary = &sum
	trs, folded := hsCommitOf(t, refire)
	if trs[0].Reason != model.ReasonRecoveryFailed {
		t.Fatalf("reason = %q, want recovery_failed", trs[0].Reason)
	}

	got := hsPlan(t, hsPub(refire, trs, folded))
	if threads := hsIntentsOfClass(got, model.EffectThreadAppend); len(threads) != 1 {
		t.Fatalf("got %d thread entries, want 1 refire journal entry", len(threads))
	}
	if broadcasts := hsIntentsOfClass(got, model.EffectBroadcastHandoff); len(broadcasts) != 0 {
		t.Errorf("a refire is not on the permitted poke list, got %d broadcasts", len(broadcasts))
	}
	if roots := hsIntentsOfClass(got, model.EffectRootSync); len(roots) != 1 {
		t.Errorf("got %d root_sync intents, want 1", len(roots))
	}
}

func TestPlanNotificationIntentsDrillCommitPlansNormally(t *testing.T) {
	c := hsNext(t)
	c.Drill = true
	c.Situation.Attention = model.AttentionUrgent
	c.Assessment.Attention = model.AttentionUrgent
	trs, sum := hsCommitOf(t, c)
	if !trs[0].Drill {
		t.Fatal("the derived transition lost the Drill marker")
	}
	got := hsPlan(t, hsPub(c, trs, sum))
	if len(got) == 0 {
		t.Fatal("a drill commit planned no intents")
	}
	for _, intent := range got {
		if intent.TransitionID == nil {
			continue
		}
		if *intent.TransitionID != trs[0].ID && *intent.TransitionID != trs[len(trs)-1].ID {
			t.Errorf("intent references %q, outside this drill commit", *intent.TransitionID)
		}
	}
}

func TestPlanNotificationIntentsIdentityIsDeterministic(t *testing.T) {
	plan := func() []model.NotificationIntent {
		c := hsNext(t)
		c.Assessment.ActionContract = hsOperatorContract(c.Now.Add(time.Minute))
		trs, sum := hsCommitOf(t, c)
		return hsPlan(t, hsPub(c, trs, sum))
	}
	a, b := plan(), plan()
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("plans differ in size: %d vs %d", len(a), len(b))
	}
	seen := map[string]bool{}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Errorf("intent %d id is not deterministic: %q vs %q", i, a[i].ID, b[i].ID)
		}
		if a[i].IdempotencyKey != b[i].IdempotencyKey {
			t.Errorf("intent %d idempotency key is not deterministic: %q vs %q", i, a[i].IdempotencyKey, b[i].IdempotencyKey)
		}
		if a[i].ClientMessageID != b[i].ClientMessageID {
			t.Errorf("intent %d client message id is not deterministic: %q vs %q", i, a[i].ClientMessageID, b[i].ClientMessageID)
		}
		if seen[a[i].IdempotencyKey] {
			t.Errorf("duplicate idempotency key %q in one commit", a[i].IdempotencyKey)
		}
		seen[a[i].IdempotencyKey] = true
	}

	// A refreshed deadline is a distinct root projection, not the same one.
	c := hsNext(t)
	in := hsPub(c, nil, *c.PriorSummary)
	in.ContractDeadlineAt = timePtr(c.Now.Add(5 * time.Minute))
	in.LastDeliveredRootDeadlineAt = timePtr(c.Now.Add(-time.Minute))
	first := hsPlan(t, in)
	in.ContractDeadlineAt = timePtr(c.Now.Add(9 * time.Minute))
	second := hsPlan(t, in)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("want one refresh each, got %d and %d", len(first), len(second))
	}
	if first[0].IdempotencyKey == second[0].IdempotencyKey {
		t.Error("two different deadlines produced the same root_sync idempotency key")
	}
}

func TestPlanNotificationIntentsRejectsIncoherentInput(t *testing.T) {
	c := hsNext(t)
	trs, sum := hsCommitOf(t, c)
	_ = trs

	t.Run("summary from another Situation", func(t *testing.T) {
		in := hsPub(c, nil, sum)
		in.Summary.SituationID = "1f0f5a0c-0000-4000-8000-00000000ffff"
		if _, err := PlanNotificationIntents(in); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("unknown Slack floor", func(t *testing.T) {
		in := hsPub(c, nil, *c.PriorSummary)
		in.SlackFloor = model.InterruptionPriority("shout")
		if _, err := PlanNotificationIntents(in); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("transitions without a prior authority and no summary", func(t *testing.T) {
		urgent := hsNext(t)
		urgent.Situation.Attention = model.AttentionUrgent
		urgent.Assessment.Attention = model.AttentionUrgent
		built, _ := hsCommitOf(t, urgent)
		in := hsPub(urgent, built, model.EpisodeSummary{})
		if _, err := PlanNotificationIntents(in); err == nil {
			t.Fatal("want error for transitions with no folded summary, got nil")
		}
	})
}
