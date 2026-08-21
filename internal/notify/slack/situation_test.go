// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestRecoveryPendingAndRecoveredAreDistinct(t *testing.T) {
	pending := RenderSituationRoot(renderInputT(t, model.LifecycleRecoveryPending))
	recovered := RenderSituationRoot(renderInputT(t, model.LifecycleRecovered))
	if !strings.Contains(pending.Fallback, "Recovery observed — confirming stability") {
		t.Fatalf("pending=%q", pending.Fallback)
	}
	if !strings.Contains(recovered.Fallback, "Recovered — no further action") || pending.Color == recovered.Color {
		t.Fatalf("pending=%+v recovered=%+v", pending, recovered)
	}
}

func TestRootStatesCoverAllSevenSurfaces(t *testing.T) {
	cases := []struct {
		name  string
		in    RenderInput
		state RootState
	}{
		{"investigating", investigatingInput(t), RootStateInvestigating},
		{"judgment requested", judgmentRequestedInput(t), RootStateJudgmentRequested},
		{"action required", actionRequiredInput(t), RootStateActionRequired},
		{"expected active", expectedActiveInput(t), RootStateExpectedActive},
		{"recovery pending", renderInputT(t, model.LifecycleRecoveryPending), RootStateRecoveryPending},
		{"recovered", renderInputT(t, model.LifecycleRecovered), RootStateRecovered},
		{"closed unknown", renderInputT(t, model.LifecycleClosedUnknown), RootStateClosedUnknown},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		got := DeriveRootState(tc.in)
		if got != tc.state {
			t.Fatalf("%s: state=%s want=%s", tc.name, got, tc.state)
		}
		root := RenderSituationRoot(tc.in)
		if root.Fallback == "" || root.Color == "" {
			t.Fatalf("%s: incomplete render %+v", tc.name, root)
		}
		key := root.Color + "|" + string(got)
		if seen[key] {
			t.Fatalf("%s: duplicate color/state combination", tc.name)
		}
		seen[key] = true
	}
}

func TestRootIncludesReasonEvidenceNextWorkActorAndHandle(t *testing.T) {
	in := investigatingInput(t)
	root := RenderSituationRoot(in)
	for _, want := range []string{in.ReasonSummary, in.NextWork, in.Actor, in.Handle} {
		if !strings.Contains(root.Fallback, want) {
			t.Fatalf("fallback missing %q: %q", want, root.Fallback)
		}
	}
	for _, evidence := range in.CheckedEvidence {
		if !strings.Contains(root.Fallback, evidence) {
			t.Fatalf("fallback missing checked evidence %q: %q", evidence, root.Fallback)
		}
	}
}

func TestRootIncludesLocalizedAndRelativeNextUpdate(t *testing.T) {
	in := investigatingInput(t)
	root := RenderSituationRoot(in)
	if !strings.Contains(root.Fallback, "in 5 minutes") {
		t.Fatalf("fallback missing relative countdown: %q", root.Fallback)
	}
	if !strings.Contains(root.Fallback, "<!date^") {
		t.Fatalf("fallback missing localized absolute time: %q", root.Fallback)
	}
}

func TestDrillMarkingAppearsOnEverySituationSurface(t *testing.T) {
	in := investigatingInput(t)
	in.Drill = true
	root := RenderSituationRoot(in)
	if !strings.Contains(root.Fallback, "DRILL") {
		t.Fatalf("root fallback missing drill marker: %q", root.Fallback)
	}
	reply := RenderThreadReply(ThreadReplyInput{Text: "routine evidence update", Drill: true})
	if !strings.Contains(reply.Fallback, "DRILL") {
		t.Fatalf("thread reply fallback missing drill marker: %q", reply.Fallback)
	}
	broadcast := RenderBroadcastReply(BroadcastReplyInput{Text: "operator action required", Drill: true})
	if !strings.Contains(broadcast.Fallback, "DRILL") {
		t.Fatalf("broadcast reply fallback missing drill marker: %q", broadcast.Fallback)
	}
}

func TestRetryReusesClientMessageID(t *testing.T) {
	id := ClientMessageID("situation:s1:transition:t1:root")
	if id != ClientMessageID("situation:s1:transition:t1:root") {
		t.Fatal("client_msg_id changed")
	}
	if id == ClientMessageID("situation:s1:transition:t2:root") {
		t.Fatal("client_msg_id must differ for a different idempotency key")
	}
}

func TestEnvelopeReviewRenderNamesEnvelopeDateCountAndHandle(t *testing.T) {
	reviewDue := mustRFC3339(t, "2026-11-20T00:00:00Z")
	rendered := RenderEnvelopeReview(EnvelopeReviewInput{
		EnvelopeName: "db-prod-1 nightly risk calc", ReviewDueAt: reviewDue, MatchCount: 12, MCPHandle: "alertint_expected_behavior_get env-1",
	})
	for _, want := range []string{"db-prod-1 nightly risk calc", "12", "alertint_expected_behavior_get env-1", "<!date^"} {
		if !strings.Contains(rendered.Fallback, want) {
			t.Fatalf("envelope review missing %q: %q", want, rendered.Fallback)
		}
	}
}

func TestDependencyHealthRootAndUpdateRender(t *testing.T) {
	root := RenderDependencyHealth(DependencyHealthInput{Dependency: "llm", Degraded: true})
	if !strings.Contains(root.Fallback, "llm") || !strings.Contains(strings.ToLower(root.Fallback), "degraded") {
		t.Fatalf("health root=%q", root.Fallback)
	}
	recovery := RenderDependencyHealth(DependencyHealthInput{Dependency: "llm", Degraded: false})
	if !strings.Contains(strings.ToLower(recovery.Fallback), "recovered") {
		t.Fatalf("health recovery=%q", recovery.Fallback)
	}
}

func renderInputT(t *testing.T, lifecycle model.Lifecycle) RenderInput {
	t.Helper()
	next := mustRFC3339(t, "2026-08-20T10:05:00Z")
	renderedAt := mustRFC3339(t, "2026-08-20T10:00:00Z")
	in := RenderInput{
		Handle: "db-prod-sustained-cpu", GroupKey: "host=db-prod-1", Lifecycle: lifecycle,
		Attention:       model.AttentionInvestigate,
		ActionContract:  model.ActionContract{NextActor: model.NextActorAlertint, NextUpdateAt: &next, NextUpdateOn: []string{"recovery_observed"}},
		ReasonSummary:   "CPU has remained firing longer than the recent short-episode envelope",
		CheckedEvidence: []string{"cpu duration class", "prior episode distribution"},
		NextWork:        "check bounded workload evidence", Actor: "AlertINT", RenderedAt: renderedAt,
	}
	if lifecycle == model.LifecycleRecoveryPending {
		graceUntil := mustRFC3339(t, "2026-08-20T10:10:00Z")
		in.ActionContract.NextUpdateAt = &graceUntil
	}
	if lifecycle == model.LifecycleRecovered || lifecycle == model.LifecycleClosedUnknown {
		in.ActionContract = model.ActionContract{NextActor: model.NextActorNone}
	}
	return in
}

func investigatingInput(t *testing.T) RenderInput {
	in := renderInputT(t, model.LifecycleActive)
	in.ActionContract.NextActor = model.NextActorAlertint
	in.ActionContract.OperatorJudgmentRequested = nil
	in.ActionContract.OperatorActionRequired = nil
	return in
}

func judgmentRequestedInput(t *testing.T) RenderInput {
	in := renderInputT(t, model.LifecycleActive)
	judgment := "identify owning team"
	in.ActionContract.NextActor = model.NextActorOperator
	in.ActionContract.OperatorJudgmentRequested = &judgment
	in.ActionContract.OperatorActionRequired = nil
	return in
}

func actionRequiredInput(t *testing.T) RenderInput {
	in := renderInputT(t, model.LifecycleActive)
	action := "restart the database"
	in.ActionContract.NextActor = model.NextActorOperator
	in.ActionContract.OperatorActionRequired = &action
	in.ActionContract.OperatorJudgmentRequested = nil
	return in
}

func expectedActiveInput(t *testing.T) RenderInput {
	in := renderInputT(t, model.LifecycleActive)
	in.EnvelopeExpected = true
	in.ActionContract.OperatorJudgmentRequested = nil
	in.ActionContract.OperatorActionRequired = nil
	return in
}
