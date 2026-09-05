// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Fixtures.
// ----------------------------------------------------------------------

// awaitingDecisionIncident is baseIncident with its Triage schedule freshly
// at awaiting_decision, attempt zero — the B+ gate's universal starting
// state for every ready Incident.
func awaitingDecisionIncident(t *testing.T, id string) IncidentState {
	t.Helper()
	inc := baseIncident(t, id)
	inc.Triage = TriageState{Phase: "awaiting_decision", Attempts: 0}
	return inc
}

// pendingDecidedIncident is an Incident already judged "request" (phase
// pending), carrying the decision's recorded digests — the fixture for
// membership/Incident-input "refresh" tests.
func pendingDecidedIncident(t *testing.T, id, membershipDigest, inputDigest string) IncidentState {
	t.Helper()
	inc := baseIncident(t, id)
	decision := TriageDecisionRequest
	inc.Triage = TriageState{
		Phase: "pending", Attempts: 0,
		Decision: &decision, MembershipDigest: &membershipDigest, IncidentInputDigest: &inputDigest,
	}
	return inc
}

// triageDecideInput is baseSnapshotInput with its one Incident placed in
// awaiting_decision, ready for a fresh DecideTriage judgment.
func triageDecideInput(t *testing.T) SnapshotInput {
	t.Helper()
	in := baseSnapshotInput(t)
	in.Incidents = []IncidentState{awaitingDecisionIncident(t, "incident-1")}
	return in
}

// trustworthyPriorCovering builds a trustworthy (model_validated)
// AuthoritativeAssessment whose own MaterialFactHash and coverage tuple
// exactly match snap/in's current material fact hash and per-Incident
// digests — the only shape DecideTriage may legally skip against.
func trustworthyPriorCovering(t *testing.T, snap Snapshot, in SnapshotInput) AuthoritativeAssessment {
	t.Helper()
	futureUpdate := in.Now.Add(5 * time.Minute)
	return AuthoritativeAssessment{
		ID:               "assessment-1",
		SituationID:      snap.SituationID,
		MaterialFactHash: snap.MaterialFactHash,
		InputVersion:     snap.InputVersion,
		Assessment: model.Assessment{
			SchemaVersion:   model.AssessmentSchemaVersion,
			Persistence:     model.PersistenceUnknown,
			Impact:          model.ImpactNoneObserved,
			Novelty:         model.NoveltyInsufficientHistory,
			Causality:       model.CausalityUnknown,
			Attention:       model.AttentionObserve,
			Lifecycle:       snap.Lifecycle,
			EvidenceQuality: model.EvidenceQualityComplete,
			ActionContract:  model.ActionContract{NextActor: model.NextActorNone, NextUpdateAt: &futureUpdate},
			Cadence:         model.CadenceSlow,
		},
		Coverage:   DeriveIncidentCoverage(in),
		Derivation: model.DerivationModelValidated,
	}
}

// ----------------------------------------------------------------------
// DecideTriage: fresh awaiting_decision judgments.
// ----------------------------------------------------------------------

func TestDecideTriageRequestsWhenNoPriorAssessment(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)

	got := DecideTriage(snap, in, now)
	if len(got) != 1 {
		t.Fatalf("decisions = %d, want 1", len(got))
	}
	d := got[0]
	if d.Decision != TriageDecisionRequest {
		t.Fatalf("Decision = %q, want request", d.Decision)
	}
	if d.DecisionReason != DecisionReasonNoTrustworthyAssessment {
		t.Fatalf("DecisionReason = %q, want %q", d.DecisionReason, DecisionReasonNoTrustworthyAssessment)
	}
	if d.IncidentID != "incident-1" || d.SituationID != snap.SituationID || d.SituationInputVersion != snap.InputVersion {
		t.Fatalf("decision identity = %+v", d)
	}
	if d.MaterialFactHash != snap.MaterialFactHash {
		t.Fatalf("MaterialFactHash = %q, want snapshot's %q", d.MaterialFactHash, snap.MaterialFactHash)
	}
	if d.MembershipDigest != MembershipDigest("incident-1", in.Deliveries) {
		t.Fatalf("MembershipDigest = %q, want current", d.MembershipDigest)
	}
	if d.IncidentInputDigest != IncidentInputDigest("incident-1", "group-1", in.Deliveries) {
		t.Fatalf("IncidentInputDigest = %q, want current", d.IncidentInputDigest)
	}
	if d.CoveredAssessmentID != nil {
		t.Fatalf("CoveredAssessmentID = %v, want nil for a request", d.CoveredAssessmentID)
	}
	if !d.DecidedAt.Equal(now) {
		t.Fatalf("DecidedAt = %v, want %v", d.DecidedAt, now)
	}
}

// TestDecideTriageNewIncidentIdentityNeverProvesSkip pins spec.md's explicit
// list of things that never justify a skip: a brand-new Incident identity
// (no prior Assessment has ever seen it) always requests, regardless of how
// unremarkable its Alert name or severity looks.
func TestDecideTriageNewIncidentIdentityNeverProvesSkip(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	in.Deliveries[0].Severity = "info" // deliberately unremarkable, below any floor
	snap := BuildSnapshot(in)

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want exactly one request", got)
	}
}

func TestDecideTriageSkipsOnlyWhenTrustworthyAssessmentExactlyCovers(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	in.CurrentAssessment = &prior

	got := DecideTriage(snap, in, now)
	if len(got) != 1 {
		t.Fatalf("decisions = %d, want 1", len(got))
	}
	d := got[0]
	if d.Decision != TriageDecisionSkip {
		t.Fatalf("Decision = %q, want skip", d.Decision)
	}
	if d.DecisionReason != DecisionReasonCleanSkip {
		t.Fatalf("DecisionReason = %q, want %q", d.DecisionReason, DecisionReasonCleanSkip)
	}
	if d.CoveredAssessmentID == nil || *d.CoveredAssessmentID != prior.ID {
		t.Fatalf("CoveredAssessmentID = %v, want %q", d.CoveredAssessmentID, prior.ID)
	}
}

// TestDecideTriageDeterministicCleanSkipIsFullyReproducible proves the skip
// judgment is a pure function of its inputs: calling DecideTriage twice
// against byte-identical snap/in/now produces byte-identical decisions — a
// "deterministic clean skip".
func TestDecideTriageDeterministicCleanSkipIsFullyReproducible(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	in.CurrentAssessment = &prior

	first := DecideTriage(snap, in, now)
	second := DecideTriage(snap, in, now)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("decisions = %d/%d, want 1/1", len(first), len(second))
	}
	a, b := first[0], second[0]
	// Compare CoveredAssessmentID by value: DecideTriage legitimately
	// allocates a fresh *string each call even for the identical logical
	// value, so pointer-identity is never part of "deterministic."
	if a.CoveredAssessmentID == nil || b.CoveredAssessmentID == nil || *a.CoveredAssessmentID != *b.CoveredAssessmentID {
		t.Fatalf("CoveredAssessmentID not deterministic: %v != %v", a.CoveredAssessmentID, b.CoveredAssessmentID)
	}
	a.CoveredAssessmentID, b.CoveredAssessmentID = nil, nil
	if a != b {
		t.Fatalf("DecideTriage is not deterministic: %+v != %+v", a, b)
	}
}

func TestDecideTriageRequestsWhenPriorNotTrustworthy(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	prior.Derivation = model.DerivationDeterministicFallback // never a semantic reuse/skip source
	in.CurrentAssessment = &prior

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want request", got)
	}
	if got[0].DecisionReason != DecisionReasonAssessmentNotTrustworthy {
		t.Fatalf("DecisionReason = %q, want %q", got[0].DecisionReason, DecisionReasonAssessmentNotTrustworthy)
	}
}

func TestDecideTriageRequestsWhenMaterialFactHashChanged(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	prior.MaterialFactHash = "sha256:stale-material-fact-hash"
	in.CurrentAssessment = &prior

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want request", got)
	}
	if got[0].DecisionReason != DecisionReasonMaterialFactHashChanged {
		t.Fatalf("DecisionReason = %q, want %q", got[0].DecisionReason, DecisionReasonMaterialFactHashChanged)
	}
}

func TestDecideTriageRequestsWhenIncidentNotCovered(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	prior.Coverage = nil // this prior never covered this Incident at all
	in.CurrentAssessment = &prior

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want request", got)
	}
	if got[0].DecisionReason != DecisionReasonIncidentNotCovered {
		t.Fatalf("DecisionReason = %q, want %q", got[0].DecisionReason, DecisionReasonIncidentNotCovered)
	}
}

func TestDecideTriageRequestsWhenCoveredMembershipDigestStale(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	prior.Coverage[0].MembershipDigest = "sha256:stale-membership"
	in.CurrentAssessment = &prior

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want request", got)
	}
	if got[0].DecisionReason != DecisionReasonMembershipDigestChanged {
		t.Fatalf("DecisionReason = %q, want %q", got[0].DecisionReason, DecisionReasonMembershipDigestChanged)
	}
}

func TestDecideTriageRequestsWhenCoveredIncidentInputDigestStale(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	snap := BuildSnapshot(in)
	prior := trustworthyPriorCovering(t, snap, in)
	prior.Coverage[0].IncidentInputDigest = "sha256:stale-incident-input"
	in.CurrentAssessment = &prior

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want request", got)
	}
	if got[0].DecisionReason != DecisionReasonIncidentInputChanged {
		t.Fatalf("DecisionReason = %q, want %q", got[0].DecisionReason, DecisionReasonIncidentInputChanged)
	}
}

// TestDecideTriageUrgentFloorStillRequestsAndNeverBlocksOnAssessment pins
// "urgent floors never wait for Acute Triage": a proven deterministic urgent
// floor (critical_anchor eligible) neither shortcuts DecideTriage into a
// skip, nor makes it withhold a decision — the request still comes back
// exactly as it would without the floor, because DecideTriage never reads
// Attention/EligibleReasons at all.
func TestDecideTriageUrgentFloorStillRequestsAndNeverBlocksOnAssessment(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := triageDecideInput(t)
	in.Deliveries[0].Severity = "critical"
	in.Deliveries[0].Status = model.DeliveryStatusFiring
	snap := BuildSnapshot(in)
	if !hasDeterministicFloor(snap.EligibleReasons) {
		t.Fatal("fixture invariant violated: critical_anchor floor not eligible")
	}

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want exactly one request despite the urgent floor", got)
	}
}

// ----------------------------------------------------------------------
// Membership/Incident-input digest refresh of an already-decided row.
// ----------------------------------------------------------------------

// TestDecideTriageRefreshesRequestWhenMembershipChangesBeforeDispatch pins
// spec.md's "Before dispatch, a changed membership digest refreshes the
// request against the new digest": a pending row's recorded digest has gone
// stale relative to the current snapshot, so it gets a fresh decision — but
// that decision is always "request" (a refresh never newly discovers a
// skip), and it carries the CURRENT (not stale) digests.
func TestDecideTriageRefreshesRequestWhenMembershipChangesBeforeDispatch(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := baseSnapshotInput(t)
	currentMembership := MembershipDigest("incident-1", in.Deliveries)
	currentInput := IncidentInputDigest("incident-1", "group-1", in.Deliveries)
	in.Incidents = []IncidentState{pendingDecidedIncident(t, "incident-1", "sha256:stale-membership", currentInput)}
	snap := BuildSnapshot(in)
	// Even a trustworthy, exactly-covering prior must not turn this into a
	// skip: a refresh is always "request".
	prior := trustworthyPriorCovering(t, snap, in)
	in.CurrentAssessment = &prior

	got := DecideTriage(snap, in, now)
	if len(got) != 1 {
		t.Fatalf("decisions = %d, want 1", len(got))
	}
	d := got[0]
	if d.Decision != TriageDecisionRequest {
		t.Fatalf("Decision = %q, want request (a refresh never newly discovers a skip)", d.Decision)
	}
	if d.DecisionReason != DecisionReasonMembershipOrInputRefresh {
		t.Fatalf("DecisionReason = %q, want %q", d.DecisionReason, DecisionReasonMembershipOrInputRefresh)
	}
	if d.MembershipDigest != currentMembership {
		t.Fatalf("MembershipDigest = %q, want the CURRENT digest %q, not the stale recorded one", d.MembershipDigest, currentMembership)
	}
}

func TestDecideTriageRefreshesRequestWhenIncidentInputChangesBeforeDispatch(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := baseSnapshotInput(t)
	currentMembership := MembershipDigest("incident-1", in.Deliveries)
	in.Incidents = []IncidentState{pendingDecidedIncident(t, "incident-1", currentMembership, "sha256:stale-incident-input")}
	snap := BuildSnapshot(in)

	got := DecideTriage(snap, in, now)
	if len(got) != 1 || got[0].Decision != TriageDecisionRequest {
		t.Fatalf("decisions = %+v, want request", got)
	}
	if got[0].DecisionReason != DecisionReasonMembershipOrInputRefresh {
		t.Fatalf("DecisionReason = %q, want %q", got[0].DecisionReason, DecisionReasonMembershipOrInputRefresh)
	}
}

// TestDecideTriageUnchangedPendingRowNeedsNoDecision proves an already-
// decided pending row whose recorded digests still match current is left
// alone entirely — no attempt-consuming, no due-time-accelerating "refresh"
// for a row that has not actually changed.
func TestDecideTriageUnchangedPendingRowNeedsNoDecision(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := baseSnapshotInput(t)
	currentMembership := MembershipDigest("incident-1", in.Deliveries)
	currentInput := IncidentInputDigest("incident-1", "group-1", in.Deliveries)
	in.Incidents = []IncidentState{pendingDecidedIncident(t, "incident-1", currentMembership, currentInput)}
	snap := BuildSnapshot(in)

	got := DecideTriage(snap, in, now)
	if len(got) != 0 {
		t.Fatalf("decisions = %+v, want none for an unchanged already-decided row", got)
	}
}

// ----------------------------------------------------------------------
// Unjudged-but-not-decidable phases: in_flight/skipped/exhausted never need
// a new decision from DecideTriage.
// ----------------------------------------------------------------------

func TestDecideTriageSkipsPhasesThatNeverNeedANewDecision(t *testing.T) {
	for _, phase := range []string{"in_flight", "skipped", "exhausted"} {
		t.Run(phase, func(t *testing.T) {
			now := mustTime(t, "2026-09-01T12:05:00Z")
			in := baseSnapshotInput(t)
			inc := baseIncident(t, "incident-1")
			inc.Triage = TriageState{Phase: phase, Attempts: 1}
			in.Incidents = []IncidentState{inc}
			snap := BuildSnapshot(in)

			got := DecideTriage(snap, in, now)
			if len(got) != 0 {
				t.Fatalf("phase %s: decisions = %+v, want none", phase, got)
			}
		})
	}
}

// TestDecideTriageMultipleIncidentsEachJudgedIndependently proves a
// multi-Incident Situation gets one decision per Incident that needs one,
// in Snapshot's own stable (sorted-by-ID) order.
func TestDecideTriageMultipleIncidentsEachJudgedIndependently(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:05:00Z")
	in := baseSnapshotInput(t)
	in.Deliveries = []Delivery{
		deliveryFor("delivery-1", "incident-1", "digest-1", in.Situation.EffectiveStartedAt),
		deliveryFor("delivery-2", "incident-2", "digest-2", in.Situation.EffectiveStartedAt),
	}
	in.Incidents = []IncidentState{
		awaitingDecisionIncident(t, "incident-2"),
		awaitingDecisionIncident(t, "incident-1"),
	}
	snap := BuildSnapshot(in)

	got := DecideTriage(snap, in, now)
	if len(got) != 2 {
		t.Fatalf("decisions = %d, want 2", len(got))
	}
	if got[0].IncidentID != "incident-1" || got[1].IncidentID != "incident-2" {
		t.Fatalf("decisions out of Snapshot's stable order: %+v", got)
	}
	for _, d := range got {
		if d.Decision != TriageDecisionRequest {
			t.Fatalf("decision for %s = %q, want request (no prior Assessment)", d.IncidentID, d.Decision)
		}
	}
}
