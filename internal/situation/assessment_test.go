// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed.UTC()
}

// investigateSnapshotWithDurationOutlier returns a snapshot whose only
// eligible reason is the genuine, evidence-backed "duration_outlier"
// candidate (non-floor), with EligibleReasons populated as BuildSnapshot
// would.
func investigateSnapshotWithDurationOutlier(t *testing.T) (Snapshot, model.ReasonCandidate) {
	t.Helper()
	snap, _ := snapshotForReasonEvidence("duration_outlier")
	snap.EligibleReasons = EligibleReasons(snap)
	reason := requireReason(t, snap.EligibleReasons, "duration_outlier")
	return snap, reason
}

func validInvestigateProposal(t *testing.T) model.Assessment {
	t.Helper()
	snap, reason := investigateSnapshotWithDurationOutlier(t)
	future := snap.EffectiveStartedAt.Add(48 * time.Hour)
	return model.Assessment{
		SchemaVersion: AssessmentSchemaVersion,
		Persistence:   model.PersistenceSustained, Impact: model.ImpactSuspected,
		Novelty: model.NoveltyChanged, Causality: model.CausalityCorrelated,
		Attention: model.AttentionInvestigate, Lifecycle: snap.Lifecycle,
		EvidenceQuality: model.EvidenceQualityDegraded,
		SufficientReason: &model.SufficientReason{
			Code: reason.Code, CandidateID: reason.ID, Summary: "duration exceeds recent episodes",
			EvidenceRefs: append([]string(nil), reason.EvidenceRefs...),
		},
		ActionContract: model.ActionContract{
			NextActor: model.NextActorAlertint, ActionStatus: model.ActionStatusPlanned,
			NextUpdateAt: &future,
		},
		Limitations:     []model.Limitation{},
		ProposedCadence: model.CadenceNormal,
	}
}

// TestValidateAssessmentRejectsInventedReasonAndLifecycle verifies the two
// hardest policy boundaries: L2 cannot cite a candidate ID absent from the
// snapshot's own eligible reasons, and cannot change the controller-owned
// lifecycle.
func TestValidateAssessmentRejectsInventedReasonAndLifecycle(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	now := mustTime(t, "2026-08-20T10:00:00Z")

	p := validInvestigateProposal(t)
	p.SufficientReason.CandidateID = "reason:invented:v1:nope"
	if _, _, err := ValidateAssessment(snap, p, now); err == nil {
		t.Fatal("invented reason accepted")
	}

	p = validInvestigateProposal(t)
	p.Lifecycle = model.LifecycleRecovered
	if _, _, err := ValidateAssessment(snap, p, now); err == nil {
		t.Fatal("model changed lifecycle")
	}
}

// TestValidateAssessmentAcceptsValidInvestigateProposal is the green-path
// control: a proposal that cites a genuinely eligible reason and a
// consistent action contract validates without adjustment or error.
func TestValidateAssessmentAcceptsValidInvestigateProposal(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	now := mustTime(t, "2026-08-20T10:00:00Z")
	p := validInvestigateProposal(t)

	out, adjustments, err := ValidateAssessment(snap, p, now)
	if err != nil {
		t.Fatalf("ValidateAssessment: %v", err)
	}
	if len(adjustments) != 0 {
		t.Fatalf("unexpected adjustments: %+v", adjustments)
	}
	if out.Attention != model.AttentionInvestigate {
		t.Fatalf("attention = %s", out.Attention)
	}
}

// TestValidateAssessmentEnforcesUrgentFloorRegardlessOfProposal verifies a
// deterministic urgent floor forces Attention=Urgent and substitutes the
// floor's own SufficientReason even when the proposal named a different
// (non-floor) reason or omitted one — a floor cannot be overridden downward
// by L2 (binding constraint).
func TestValidateAssessmentEnforcesUrgentFloorRegardlessOfProposal(t *testing.T) {
	floorSnap, _ := snapshotForReasonEvidence("critical_anchor")
	floorSnap.EligibleReasons = EligibleReasons(floorSnap)
	now := mustTime(t, "2026-08-20T10:00:00Z")
	future := now.Add(time.Hour)

	p := model.Assessment{
		SchemaVersion: AssessmentSchemaVersion, Persistence: model.PersistenceSustained,
		Impact: model.ImpactUnknown, Novelty: model.NoveltyChanged, Causality: model.CausalityUnknown,
		Attention: model.AttentionObserve, Lifecycle: floorSnap.Lifecycle, EvidenceQuality: model.EvidenceQualityDegraded,
		ActionContract:  model.ActionContract{NextActor: model.NextActorAlertint, ActionStatus: model.ActionStatusPlanned, NextUpdateAt: &future},
		Limitations:     []model.Limitation{},
		ProposedCadence: model.CadenceFast,
	}
	out, adjustments, err := ValidateAssessment(floorSnap, p, now)
	if err != nil {
		t.Fatalf("ValidateAssessment: %v", err)
	}
	if out.Attention != model.AttentionUrgent {
		t.Fatalf("attention = %s, want urgent (floor enforced)", out.Attention)
	}
	if out.SufficientReason == nil || out.SufficientReason.Code != "critical_anchor" {
		t.Fatalf("sufficient reason = %+v, want a substituted critical_anchor floor", out.SufficientReason)
	}
	if len(adjustments) == 0 {
		t.Fatal("expected validation adjustments recording the floor enforcement")
	}
}

// TestValidateAssessmentRejectsMintedUrgentWithoutFloor verifies a model
// cannot claim Attention=Urgent when no deterministic floor is eligible.
func TestValidateAssessmentRejectsMintedUrgentWithoutFloor(t *testing.T) {
	snap, reason := investigateSnapshotWithDurationOutlier(t)
	now := mustTime(t, "2026-08-20T10:00:00Z")
	p := validInvestigateProposal(t)
	p.Attention = model.AttentionUrgent
	p.SufficientReason.Code = reason.Code
	if _, _, err := ValidateAssessment(snap, p, now); err == nil {
		t.Fatal("minted urgent attention accepted without a deterministic floor")
	}
}

// TestValidateAssessmentDowngradesUnsupportedCausality verifies Causality
// "supported" is downgraded to "correlated" deterministically (not rejected)
// when the assessment carries no eligible, evidence-bound reason — temporal
// overlap alone can never become supported cause.
func TestValidateAssessmentDowngradesUnsupportedCausality(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	now := mustTime(t, "2026-08-20T10:00:00Z")
	future := now.Add(time.Hour)
	p := model.Assessment{
		SchemaVersion: AssessmentSchemaVersion, Persistence: model.PersistenceSustained,
		Impact: model.ImpactUnknown, Novelty: model.NoveltyFamiliar, Causality: model.CausalitySupported,
		Attention: model.AttentionObserve, Lifecycle: snap.Lifecycle, EvidenceQuality: model.EvidenceQualityDegraded,
		ActionContract:  model.ActionContract{NextActor: model.NextActorNone, ActionStatus: model.ActionStatusWaiting, NextUpdateAt: &future},
		Limitations:     []model.Limitation{},
		ProposedCadence: model.CadenceSlow,
	}
	out, adjustments, err := ValidateAssessment(snap, p, now)
	if err != nil {
		t.Fatalf("ValidateAssessment: %v", err)
	}
	if out.Causality != model.CausalityCorrelated {
		t.Fatalf("causality = %s, want correlated (downgraded)", out.Causality)
	}
	found := false
	for _, adj := range adjustments {
		if adj.Code == "causality_downgraded_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("adjustments = %+v, want a causality downgrade record", adjustments)
	}
}

// TestValidateAssessmentRejectsRunningWithoutDispatch verifies action_status
// "running" is legal only for AlertINT's own named, dispatched action.
func TestValidateAssessmentRejectsRunningWithoutDispatch(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	now := mustTime(t, "2026-08-20T10:00:00Z")
	p := validInvestigateProposal(t)
	p.ActionContract.ActionStatus = model.ActionStatusRunning
	p.ActionContract.NextActor = model.NextActorOperator
	if _, _, err := ValidateAssessment(snap, p, now); err == nil {
		t.Fatal("running action status accepted without alertint dispatch")
	}
}

// TestValidateAssessmentRequiresFutureNextUpdateAt verifies a nonterminal
// publication without a strictly future next_update_at is rejected.
func TestValidateAssessmentRequiresFutureNextUpdateAt(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	now := mustTime(t, "2026-08-20T10:00:00Z")
	p := validInvestigateProposal(t)
	past := now.Add(-time.Minute)
	p.ActionContract.NextUpdateAt = &past
	if _, _, err := ValidateAssessment(snap, p, now); err == nil {
		t.Fatal("past next_update_at accepted for a nonterminal assessment")
	}
	p2 := validInvestigateProposal(t)
	p2.ActionContract.NextUpdateAt = nil
	if _, _, err := ValidateAssessment(snap, p2, now); err == nil {
		t.Fatal("missing next_update_at accepted for a nonterminal assessment")
	}
}

// TestValidateAssessmentRejectsTerminalWithUpdateSchedule verifies a terminal
// Assessment must carry neither next_update_at nor next_update_on.
func TestValidateAssessmentRejectsTerminalWithUpdateSchedule(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	snap.Lifecycle = model.LifecycleRecovered
	now := mustTime(t, "2026-08-20T10:00:00Z")
	future := now.Add(time.Hour)
	p := model.Assessment{
		SchemaVersion: AssessmentSchemaVersion, Persistence: model.PersistenceTransient,
		Impact: model.ImpactNoneObserved, Novelty: model.NoveltyFamiliar, Causality: model.CausalityUnknown,
		Attention: model.AttentionObserve, Lifecycle: model.LifecycleRecovered, EvidenceQuality: model.EvidenceQualityComplete,
		ActionContract:  model.ActionContract{NextActor: model.NextActorNone, ActionStatus: model.ActionStatusComplete, NextUpdateAt: &future},
		Limitations:     []model.Limitation{},
		ProposedCadence: model.CadenceSlow,
	}
	if _, _, err := ValidateAssessment(snap, p, now); err == nil {
		t.Fatal("terminal assessment with a next_update_at accepted")
	}
}

// TestValidateAssessmentRejectsActorInconsistency verifies the action
// contract cannot name work for an actor other than the declared next actor.
func TestValidateAssessmentRejectsActorInconsistency(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	now := mustTime(t, "2026-08-20T10:00:00Z")
	p := validInvestigateProposal(t)
	operatorAction := "restart the service"
	p.ActionContract.OperatorActionRequired = &operatorAction // next_actor is alertint
	if _, _, err := ValidateAssessment(snap, p, now); err == nil {
		t.Fatal("operator work accepted while next actor is alertint")
	}
}

// TestValidateAssessmentAllowsObserveWithoutReason verifies a quiet
// "observe" publication needs no sufficient reason at all.
func TestValidateAssessmentAllowsObserveWithoutReason(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	snap.EligibleReasons = nil // no eligible reason at all — still fine for observe
	now := mustTime(t, "2026-08-20T10:00:00Z")
	future := now.Add(time.Hour)
	p := model.Assessment{
		SchemaVersion: AssessmentSchemaVersion, Persistence: model.PersistenceTransient,
		Impact: model.ImpactNoneObserved, Novelty: model.NoveltyFamiliar, Causality: model.CausalityUnknown,
		Attention: model.AttentionObserve, Lifecycle: snap.Lifecycle, EvidenceQuality: model.EvidenceQualityComplete,
		ActionContract:  model.ActionContract{NextActor: model.NextActorNone, ActionStatus: model.ActionStatusWaiting, NextUpdateAt: &future},
		Limitations:     []model.Limitation{},
		ProposedCadence: model.CadenceSlow,
	}
	out, _, err := ValidateAssessment(snap, p, now)
	if err != nil {
		t.Fatalf("ValidateAssessment: %v", err)
	}
	if out.SufficientReason != nil {
		t.Fatalf("sufficient reason = %+v, want nil", out.SufficientReason)
	}
}

// TestBuildAssessmentPromptCarriesOnlyClosedInputs verifies the L2 prompt
// body includes exactly the closed input set the spec names (typed facts,
// eligible reasons, lifecycle, prior trusted Assessment, allowed
// capabilities) and nothing about presentation or raw evidence.
func TestBuildAssessmentPromptCarriesOnlyClosedInputs(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	prior := &model.Assessment{SchemaVersion: AssessmentSchemaVersion, Attention: model.AttentionObserve}
	prompt := BuildAssessmentPrompt(snap, prior, []string{"prometheus_query", "zabbix_problem_history"})

	var payload AssessmentPromptPayload
	if err := json.Unmarshal([]byte(prompt.Prefix), &payload); err != nil {
		t.Fatalf("prompt body is not valid json: %v", err)
	}
	if len(payload.Facts) != len(snap.Facts) {
		t.Fatalf("facts = %d, want %d", len(payload.Facts), len(snap.Facts))
	}
	if len(payload.EligibleReasons) != len(snap.EligibleReasons) {
		t.Fatalf("eligible reasons = %d, want %d", len(payload.EligibleReasons), len(snap.EligibleReasons))
	}
	if payload.Lifecycle != snap.Lifecycle {
		t.Fatalf("lifecycle = %s, want %s", payload.Lifecycle, snap.Lifecycle)
	}
	if payload.PriorTrustedAssessment == nil || payload.PriorTrustedAssessment.Attention != model.AttentionObserve {
		t.Fatalf("prior trusted assessment = %+v", payload.PriorTrustedAssessment)
	}
	if len(payload.AllowedCapabilities) != 2 {
		t.Fatalf("allowed capabilities = %v", payload.AllowedCapabilities)
	}
}

// TestBuildAssessmentPromptOmitsPriorWhenAbsent verifies a first-ever
// attempt (no trusted prior) renders a null prior rather than a fabricated
// placeholder.
func TestBuildAssessmentPromptOmitsPriorWhenAbsent(t *testing.T) {
	snap, _ := investigateSnapshotWithDurationOutlier(t)
	prompt := BuildAssessmentPrompt(snap, nil, nil)
	var payload AssessmentPromptPayload
	if err := json.Unmarshal([]byte(prompt.Prefix), &payload); err != nil {
		t.Fatalf("prompt body is not valid json: %v", err)
	}
	if payload.PriorTrustedAssessment != nil {
		t.Fatalf("prior trusted assessment = %+v, want nil", payload.PriorTrustedAssessment)
	}
}
