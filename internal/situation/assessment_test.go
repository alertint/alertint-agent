// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Fixtures.
// ----------------------------------------------------------------------

// criticalInput is baseSnapshotInput with a firing critical-severity
// delivery — makes critical_anchor (the sole deterministic urgent floor)
// eligible.
func criticalInput(t *testing.T) SnapshotInput {
	t.Helper()
	in := baseSnapshotInput(t)
	in.Deliveries = append([]Delivery{}, in.Deliveries...)
	in.Deliveries[0].Severity = "critical"
	in.Deliveries[0].Status = model.DeliveryStatusFiring
	return in
}

// durationOutlierInput is baseSnapshotInput with five short comparable prior
// Situations and a current elapsed duration far past their p95/2x-median —
// makes duration_outlier (Plan 2's only reachable non-floor reason) eligible.
func durationOutlierInput(t *testing.T) SnapshotInput {
	t.Helper()
	in := baseSnapshotInput(t)
	start := in.Situation.EffectiveStartedAt
	in.Now = start.Add(10 * time.Hour)
	in.PriorSituations = fiveShortPriorSituations(in.Situation.GroupKey, start)
	return in
}

func callFor(snap Snapshot) AssessmentCall {
	return AssessmentCall{
		SituationID:      snap.SituationID,
		InputVersion:     snap.InputVersion,
		MaterialFactHash: snap.MaterialFactHash,
	}
}

func marshalRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// validCriticalProposal is a baseline valid AssessmentProposal against snap
// (built from criticalInput): grounded in the eligible critical_anchor
// candidate, urgent (the proven floor), causality=supported (legitimate only
// because the cited candidate is a deterministic floor).
func validCriticalProposal(snap Snapshot) model.AssessmentProposal {
	floor := snap.EligibleReasons[0]
	return model.AssessmentProposal{
		SchemaVersion: model.AssessmentSchemaVersion,
		Persistence:   model.PersistenceSustained,
		Impact:        model.ImpactConfirmed,
		Novelty:       model.NoveltyNew,
		Causality:     model.CausalitySupported,
		Attention:     model.AttentionUrgent,
		SufficientReason: &model.SufficientReason{
			Code:         floor.Code,
			CandidateID:  floor.ID,
			Summary:      "Confirmed active critical source severity.",
			EvidenceRefs: append([]string(nil), floor.EvidenceRefs...),
		},
	}
}

// validPlainProposal is a baseline valid AssessmentProposal against a
// Snapshot with no eligible reasons: no material claims, no Sufficient
// reason, observe attention.
func validPlainProposal() model.AssessmentProposal {
	return model.AssessmentProposal{
		SchemaVersion: model.AssessmentSchemaVersion,
		Persistence:   model.PersistenceUnknown,
		Impact:        model.ImpactNoneObserved,
		Novelty:       model.NoveltyInsufficientHistory,
		Causality:     model.CausalityUnknown,
		Attention:     model.AttentionObserve,
	}
}

func snapshotFor(t *testing.T, in SnapshotInput) Snapshot {
	t.Helper()
	return BuildSnapshot(in)
}

// ----------------------------------------------------------------------
// ValidateAssessmentProposal: baseline accept, then one authority dimension
// mutated per case (brief bullet 1).
// ----------------------------------------------------------------------

func TestValidateAssessmentProposalAcceptsValidProposal(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	raw := marshalRaw(t, validCriticalProposal(snap))

	got := ValidateAssessmentProposal(raw, snap, call, snap.Facts[0].ObservedAt)
	if got.Outcome != ProposalOutcomeAccepted {
		t.Fatalf("Outcome = %q, want accepted; errors=%v", got.Outcome, got.Errors)
	}
	if got.Proposal.Attention != model.AttentionUrgent {
		t.Fatalf("Attention = %q, want urgent", got.Proposal.Attention)
	}
}

func TestValidateAssessmentProposalRejectsUnknownSchemaVersion(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	p := validCriticalProposal(snap)
	p.SchemaVersion = 2
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
}

func TestValidateAssessmentProposalRejectsUnknownEnum(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	// Bypass the Go enum type to inject a genuinely unknown raw value.
	raw := []byte(`{"schema_version":1,"persistence":"bogus","impact":"none_observed","novelty":"insufficient_history","causality":"unknown","attention":"observe","limitations":[]}`)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
}

func TestValidateAssessmentProposalRejectsUnknownReasonID(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	p := validPlainProposal()
	p.SufficientReason = &model.SufficientReason{Code: "critical_anchor", CandidateID: "not-a-real-candidate-id"}
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeCapabilityRejected {
		t.Fatalf("Outcome = %q, want capability_rejected", got.Outcome)
	}
}

// TestValidateAssessmentProposalRejectsUnknownLimitationCode proves a
// fabricated Limitation.Code (spec.md: capability absence "is never
// represented as confirmed empty, healthy, or fetched" — a model inventing
// e.g. "prometheus_confirmed_healthy" must not be accepted verbatim) is
// rejected rather than stored as-is on an authoritative Assessment.
func TestValidateAssessmentProposalRejectsUnknownLimitationCode(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	p := validPlainProposal()
	p.Limitations = []model.Limitation{{Code: "prometheus_confirmed_healthy", Detail: "fabricated capability claim"}}
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeCapabilityRejected {
		t.Fatalf("Outcome = %q, want capability_rejected", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "limitation_code_unknown" {
		t.Fatalf("Errors = %v, want limitation_code_unknown", got.Errors)
	}
}

// TestValidateAssessmentProposalAcceptsKnownLimitationCode is the positive
// control: a proposal citing an actual plan2UnsupportedCapabilities code
// (facts.go) is accepted, not swept up by the new rejection.
func TestValidateAssessmentProposalAcceptsKnownLimitationCode(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	p := validPlainProposal()
	p.Limitations = []model.Limitation{{Code: "prometheus_unavailable", Detail: "Prometheus is not a Plan 2 fact producer."}}
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeAccepted {
		t.Fatalf("Outcome = %q, want accepted; errors=%v", got.Outcome, got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsAbsentEvidenceRef(t *testing.T) {
	in := durationOutlierInput(t)
	snap := snapshotFor(t, in)
	call := callFor(snap)
	candidate := snap.EligibleReasons[0]
	p := validPlainProposal()
	p.SufficientReason = &model.SufficientReason{
		Code:         candidate.Code,
		CandidateID:  candidate.ID,
		Summary:      "outlier",
		EvidenceRefs: []string{"fact:does-not-exist-in-this-snapshot"},
	}
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomePolicyRejected {
		t.Fatalf("Outcome = %q, want policy_rejected", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "evidence_ref_missing" {
		t.Fatalf("Errors = %v, want evidence_ref_missing", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsUnsupportedCausalStrength(t *testing.T) {
	// causality=supported with impact left at none_observed and no
	// Sufficient reason at all: a bare, unsupported causal/material claim —
	// stronger than anything the (empty) evidence set allows.
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	p := validPlainProposal()
	p.Causality = model.CausalitySupported
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomePolicyRejected {
		t.Fatalf("Outcome = %q, want policy_rejected", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "ungrounded_material_claim" {
		t.Fatalf("Errors = %v, want ungrounded_material_claim", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsTemporalOverlapAsSupportedCause(t *testing.T) {
	in := durationOutlierInput(t)
	snap := snapshotFor(t, in)
	call := callFor(snap)
	candidate := snap.EligibleReasons[0]
	if candidate.Code != reasonCodeDurationOutlier {
		t.Fatalf("fixture invariant violated: expected duration_outlier eligible, got %q", candidate.Code)
	}
	p := validPlainProposal()
	p.Causality = model.CausalitySupported
	p.SufficientReason = &model.SufficientReason{
		Code: candidate.Code, CandidateID: candidate.ID, Summary: "outlier",
		EvidenceRefs: append([]string(nil), candidate.EvidenceRefs...),
	}
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomePolicyRejected {
		t.Fatalf("Outcome = %q, want policy_rejected", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "temporal_overlap_as_cause" {
		t.Fatalf("Errors = %v, want temporal_overlap_as_cause", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsUrgentWithoutFloor(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t)) // no eligible reasons, no floor
	call := callFor(snap)
	p := validPlainProposal()
	p.Attention = model.AttentionUrgent
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomePolicyRejected {
		t.Fatalf("Outcome = %q, want policy_rejected", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "urgent_without_floor" {
		t.Fatalf("Errors = %v, want urgent_without_floor", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsStaleInputVersion(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	call.InputVersion = snap.InputVersion + 1 // the call answers a superseded input
	raw := marshalRaw(t, validCriticalProposal(snap))

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeStaleBasis {
		t.Fatalf("Outcome = %q, want stale_basis", got.Outcome)
	}
}

func TestValidateAssessmentProposalRejectsStaleMaterialFactHash(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	call.MaterialFactHash = "sha256:not-this-snapshots-hash"
	raw := marshalRaw(t, validCriticalProposal(snap))

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeStaleBasis {
		t.Fatalf("Outcome = %q, want stale_basis", got.Outcome)
	}
}

func TestValidateAssessmentProposalRejectsModelProposedLifecycle(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	base := marshalRaw(t, validPlainProposal())
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		t.Fatal(err)
	}
	obj["lifecycle"] = json.RawMessage(`"active"`)
	raw := marshalRaw(t, obj)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "forbidden_field" {
		t.Fatalf("Errors = %v, want forbidden_field", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsModelProposedActionContract(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	base := marshalRaw(t, validPlainProposal())
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		t.Fatal(err)
	}
	obj["action_contract"] = json.RawMessage(`{"next_actor":"alertint"}`)
	raw := marshalRaw(t, obj)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "forbidden_field" {
		t.Fatalf("Errors = %v, want forbidden_field", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsModelProposedCadence(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	base := marshalRaw(t, validPlainProposal())
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		t.Fatal(err)
	}
	obj["cadence"] = json.RawMessage(`"fast"`)
	raw := marshalRaw(t, obj)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "forbidden_field" {
		t.Fatalf("Errors = %v, want forbidden_field", got.Errors)
	}
}

// TestValidateAssessmentProposalRejectsStrayTopLevelOperatorContractField
// proves the allowlist (Finding #3) catches what the old 3-key blacklist
// ("lifecycle"/"action_contract"/"cadence") could not: a model response
// that FLATTENS an Operator-contract field to the top level instead of
// nesting it under action_contract. json.Unmarshal into AssessmentProposal
// silently drops it (the Go struct has no such field), so only an
// allowlist over the raw decoded object catches it.
func TestValidateAssessmentProposalRejectsStrayTopLevelOperatorContractField(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	base := marshalRaw(t, validPlainProposal())
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		t.Fatal(err)
	}
	obj["next_update_at"] = json.RawMessage(`"2026-09-01T13:00:00Z"`)
	raw := marshalRaw(t, obj)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "forbidden_field" {
		t.Fatalf("Errors = %v, want forbidden_field", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsUnboundedText(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	p := validCriticalProposal(snap)
	huge := make([]byte, maxBoundedTextLength+1)
	for i := range huge {
		huge[i] = 'x'
	}
	p.SufficientReason.Summary = string(huge)
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
	if len(got.Errors) == 0 || got.Errors[0].Code != "unbounded_text" {
		t.Fatalf("Errors = %v, want unbounded_text", got.Errors)
	}
}

func TestValidateAssessmentProposalRejectsOperatorConfirmedCausality(t *testing.T) {
	// Plan 2 has no manual reassessment producer — no input exists to ground
	// operator_confirmed causality in.
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	p := validPlainProposal()
	p.Causality = model.CausalityOperatorConfirmed
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomePolicyRejected {
		t.Fatalf("Outcome = %q, want policy_rejected", got.Outcome)
	}
}

func TestValidateAssessmentProposalRejectsInvalidJSON(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)

	got := ValidateAssessmentProposal(json.RawMessage(`not json`), snap, call, time.Now())
	if got.Outcome != ProposalOutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
}

func TestValidateAssessmentProposalContradictedStandsAsAuthoritative(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	p := validCriticalProposal(snap)
	p.Causality = model.CausalityContradicted
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeContradicted {
		t.Fatalf("Outcome = %q, want contradicted", got.Outcome)
	}
	if !got.Outcome.accepted() {
		t.Fatal("contradicted outcome must count as accepted/authoritative-eligible")
	}
}

// ----------------------------------------------------------------------
// Attention-floor adjustment: raise never lower (brief bullet 2).
// ----------------------------------------------------------------------

func TestValidateAssessmentProposalRaisesAttentionToFloorButNeverLowers(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	p := validCriticalProposal(snap)
	p.Attention = model.AttentionObserve // the model under-calls it
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeAccepted {
		t.Fatalf("Outcome = %q, want accepted; errors=%v", got.Outcome, got.Errors)
	}
	if got.Proposal.Attention != model.AttentionUrgent {
		t.Fatalf("Attention = %q, want raised to urgent", got.Proposal.Attention)
	}
	if len(got.Adjustments) == 0 || got.Adjustments[0].Code != "attention_raised_to_floor" {
		t.Fatalf("Adjustments = %v, want attention_raised_to_floor recorded", got.Adjustments)
	}
}

func TestValidateAssessmentProposalNeverLowersAnAlreadyUrgentAttention(t *testing.T) {
	// No floor present (plain snapshot): the model cannot legitimately
	// propose urgent at all (rejected — proven by
	// TestValidateAssessmentProposalRejectsUrgentWithoutFloor). This test
	// proves the converse: a floor being present never causes the
	// controller to LOWER an already-urgent proposal — Attention stays
	// urgent, not silently dropped to some intermediate value.
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	p := validCriticalProposal(snap) // already Attention: urgent
	raw := marshalRaw(t, p)

	got := ValidateAssessmentProposal(raw, snap, call, time.Now())
	if got.Outcome != ProposalOutcomeAccepted {
		t.Fatalf("Outcome = %q, want accepted", got.Outcome)
	}
	if got.Proposal.Attention != model.AttentionUrgent {
		t.Fatalf("Attention = %q, want urgent (unchanged)", got.Proposal.Attention)
	}
	for _, a := range got.Adjustments {
		if a.Code == "attention_raised_to_floor" {
			t.Fatal("redundant adjustment recorded for an already-urgent proposal")
		}
	}
}

// ----------------------------------------------------------------------
// DeriveActionContract / DeriveCadence: durable state only, closed
// combinations, no model-authored prose (brief bullet 2).
// ----------------------------------------------------------------------

func mustValidActionContract(t *testing.T, c model.ActionContract, terminal bool, now time.Time) {
	t.Helper()
	a := model.Assessment{
		SchemaVersion: model.AssessmentSchemaVersion, Persistence: model.PersistenceUnknown,
		Impact: model.ImpactNoneObserved, Novelty: model.NoveltyInsufficientHistory,
		Causality: model.CausalityUnknown, Attention: model.AttentionObserve,
		Lifecycle: model.LifecycleActive, EvidenceQuality: model.EvidenceQualityInsufficient,
		ActionContract: c, Cadence: model.CadenceSlow,
	}
	if terminal {
		a.Lifecycle = model.LifecycleRecovered
		a.Cadence = model.Cadence("")
	}
	if err := a.Validate(now); err != nil {
		t.Fatalf("derived ActionContract fails model.Assessment.Validate: %v (contract=%+v)", err, c)
	}
}

func TestDeriveActionContractAwaitingDecision(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	state := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, TriagePhase: TriagePhaseAwaitingDecision}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if c.NextActor != model.NextActorAlertINT || c.AlertINTAction == nil || *c.AlertINTAction != model.AlertINTActionRunAcuteTriage {
		t.Fatalf("contract = %+v, want run_acute_triage/alertint", c)
	}
	if c.AlertINTStatus == nil || *c.AlertINTStatus != model.AlertINTStatusPlanned {
		t.Fatalf("status = %v, want planned", c.AlertINTStatus)
	}
	if c.WaitReason != nil {
		t.Fatalf("wait_reason = %v, want nil for a planned (non-waiting) status", c.WaitReason)
	}
	mustValidActionContract(t, c, false, now)
}

func TestDeriveActionContractInFlight(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	state := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate, TriagePhase: TriagePhaseInFlight}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if c.AlertINTStatus == nil || *c.AlertINTStatus != model.AlertINTStatusRunning {
		t.Fatalf("status = %v, want running", c.AlertINTStatus)
	}
	if DeriveCadence(state) != model.CadenceFast {
		t.Fatalf("cadence = %q, want fast for durably running AlertINT work", DeriveCadence(state))
	}
	mustValidActionContract(t, c, false, now)
}

func TestDeriveActionContractBackoff(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	state := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, TriagePhase: TriagePhaseBackoff}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if c.AlertINTStatus == nil || *c.AlertINTStatus != model.AlertINTStatusWaiting {
		t.Fatalf("status = %v, want waiting", c.AlertINTStatus)
	}
	if c.WaitReason == nil || *c.WaitReason != model.WaitReasonAcuteTriageBackoff {
		t.Fatalf("wait_reason = %v, want acute_triage_backoff", c.WaitReason)
	}
	mustValidActionContract(t, c, false, now)
}

func TestDeriveActionContractSemanticRetryDueAndBlocked(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")

	due := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, SemanticRetry: SemanticRetryPhaseDue}
	cDue := DeriveActionContract(due, DeriveCadence(due), now)
	if cDue.AlertINTAction == nil || *cDue.AlertINTAction != model.AlertINTActionRetrySituationAssessment {
		t.Fatalf("action = %v, want retry_situation_assessment", cDue.AlertINTAction)
	}
	if cDue.AlertINTStatus == nil || *cDue.AlertINTStatus != model.AlertINTStatusWaiting {
		t.Fatalf("status = %v, want waiting", cDue.AlertINTStatus)
	}
	if cDue.WaitReason == nil || *cDue.WaitReason != model.WaitReasonAssessmentRetry {
		t.Fatalf("wait_reason = %v, want assessment_retry", cDue.WaitReason)
	}
	mustValidActionContract(t, cDue, false, now)

	blocked := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, SemanticRetry: SemanticRetryPhaseBlocked}
	cBlocked := DeriveActionContract(blocked, DeriveCadence(blocked), now)
	if cBlocked.AlertINTStatus == nil || *cBlocked.AlertINTStatus != model.AlertINTStatusBlocked {
		t.Fatalf("status = %v, want blocked", cBlocked.AlertINTStatus)
	}
	if cBlocked.WaitReason == nil || *cBlocked.WaitReason != model.WaitReasonAssessmentParked {
		t.Fatalf("wait_reason = %v, want assessment_parked", cBlocked.WaitReason)
	}
	mustValidActionContract(t, cBlocked, false, now)
}

func TestDeriveActionContractRecoveryPending(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	state := ControllerState{Lifecycle: model.LifecycleRecoveryPending, Attention: model.AttentionObserve}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if c.AlertINTAction == nil || *c.AlertINTAction != model.AlertINTActionVerifyRecovery {
		t.Fatalf("action = %v, want verify_recovery", c.AlertINTAction)
	}
	if c.WaitReason == nil || *c.WaitReason != model.WaitReasonRecoveryGrace {
		t.Fatalf("wait_reason = %v, want recovery_grace", c.WaitReason)
	}
	if DeriveCadence(state) != model.CadenceFast {
		t.Fatalf("cadence = %q, want fast for recovery-pending", DeriveCadence(state))
	}
	mustValidActionContract(t, c, false, now)
}

func TestDeriveActionContractActiveObserveWithoutFallibleWork(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	state := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if c.AlertINTAction == nil || *c.AlertINTAction != model.AlertINTActionMonitorSituation {
		t.Fatalf("action = %v, want monitor_situation", c.AlertINTAction)
	}
	if c.AlertINTStatus == nil || *c.AlertINTStatus != model.AlertINTStatusWaiting {
		t.Fatalf("status = %v, want waiting", c.AlertINTStatus)
	}
	if DeriveCadence(state) != model.CadenceSlow {
		t.Fatalf("cadence = %q, want slow", DeriveCadence(state))
	}
	mustValidActionContract(t, c, false, now)
}

func TestDeriveActionContractOperatorActionOverridesNextActorWhileAlertINTWorkContinues(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	action := model.OperatorActionInvestigateSituation
	state := ControllerState{
		Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate,
		TriagePhase: TriagePhaseInFlight, OperatorActionRequired: &action,
	}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if c.NextActor != model.NextActorOperator {
		t.Fatalf("next_actor = %q, want operator even though AlertINT work continues", c.NextActor)
	}
	if c.AlertINTAction == nil || *c.AlertINTAction != model.AlertINTActionRunAcuteTriage {
		t.Fatal("AlertINT action must still be present alongside operator_action_required")
	}
	if c.OperatorActionRequired == nil || *c.OperatorActionRequired != model.OperatorActionInvestigateSituation {
		t.Fatalf("operator_action_required = %v, want investigate_situation", c.OperatorActionRequired)
	}
	mustValidActionContract(t, c, false, now)
}

func TestDeriveActionContractTerminalHasNoActionOrUpdateFields(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	state := ControllerState{Lifecycle: model.LifecycleRecovered, Attention: model.AttentionObserve, TriagePhase: TriagePhaseInFlight}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if c.NextActor != model.NextActorNone {
		t.Fatalf("next_actor = %q, want none for terminal state", c.NextActor)
	}
	if c.AlertINTAction != nil || c.AlertINTStatus != nil {
		t.Fatalf("terminal contract must carry no AlertINT work, got action=%v status=%v", c.AlertINTAction, c.AlertINTStatus)
	}
	if c.NextUpdateAt != nil || len(c.NextUpdateOn) != 0 {
		t.Fatalf("terminal contract must carry no update fields, got %+v", c)
	}
	if DeriveCadence(state) != model.Cadence("") {
		t.Fatalf("cadence = %q, want none for terminal lifecycle", DeriveCadence(state))
	}
	mustValidActionContract(t, c, true, now)
}

func TestDeriveActionContractNextUpdateAtIsEarliestCandidateAndClampsPastOverdue(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	earliest := now.Add(30 * time.Second)
	later := now.Add(time.Hour)
	state := ControllerState{
		Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve,
		TriageDueAt: &later, SemanticRetryAt: &earliest,
	}
	cadence := DeriveCadence(state)
	c := DeriveActionContract(state, cadence, now)
	if c.NextUpdateAt == nil || !c.NextUpdateAt.Equal(earliest) {
		t.Fatalf("next_update_at = %v, want the earliest candidate %v", c.NextUpdateAt, earliest)
	}

	overdue := now.Add(-time.Hour)
	stateOverdue := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, SemanticRetryAt: &overdue}
	cOverdue := DeriveActionContract(stateOverdue, DeriveCadence(stateOverdue), now)
	if cOverdue.NextUpdateAt == nil || !cOverdue.NextUpdateAt.After(now) {
		t.Fatalf("next_update_at = %v, want clamped strictly after now (%v)", cOverdue.NextUpdateAt, now)
	}
	mustValidActionContract(t, c, false, now)
	mustValidActionContract(t, cOverdue, false, now)
}

func TestDeriveActionContractNextUpdateOnNamesPresentCandidatesOnly(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	due := now.Add(time.Hour)
	state := ControllerState{Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve, TriageDueAt: &due}
	c := DeriveActionContract(state, DeriveCadence(state), now)
	if len(c.NextUpdateOn) != 1 || c.NextUpdateOn[0] != model.NextUpdateOnTriageOutcome {
		t.Fatalf("next_update_on = %v, want exactly [triage_outcome]", c.NextUpdateOn)
	}
}

// ----------------------------------------------------------------------
// RevalidateReuse (brief bullet 3): unchanged basis reuses without a model
// call; changed basis and untrustworthy priors forbid it.
// ----------------------------------------------------------------------

func authoritativeFrom(t *testing.T, res AssessmentResult, id string, now time.Time) AuthoritativeAssessment {
	t.Helper()
	if err := res.Assessment.Validate(now); err != nil {
		t.Fatalf("fixture AssessmentResult fails Assessment.Validate: %v", err)
	}
	return AuthoritativeAssessment{
		ID: id, SituationID: "situation-1", AssessmentBasisHash: res.AssessmentBasisHash,
		MaterialFactHash: res.MaterialFactHash,
		InputVersion:     res.InputVersion, Assessment: res.Assessment, Coverage: res.Coverage,
		Derivation: res.Derivation,
	}
}

func TestRevalidateReuseSucceedsAcrossNewerInputWithUnchangedBasis(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := criticalInput(t)
	snap := BuildSnapshot(in)
	call := callFor(snap)
	vr := ValidateAssessmentProposal(marshalRaw(t, validCriticalProposal(snap)), snap, call, now)
	if vr.Outcome != ProposalOutcomeAccepted {
		t.Fatalf("fixture proposal not accepted: %v", vr.Errors)
	}
	priorState := ControllerState{TriagePhase: TriagePhaseInFlight}
	priorResult := DeriveAssessment(vr.Proposal, snap, in, priorState, model.DerivationModelValidated, nil, now)
	prior := authoritativeFrom(t, priorResult, "assessment-1", now)

	// A newer input version, everything else unchanged — same material
	// content, same eligible reasons, so AssessmentBasisHash matches.
	bumped := in
	bumped.Situation.InputVersion++
	newSnap := BuildSnapshot(bumped)
	if newSnap.AssessmentBasisHash != prior.AssessmentBasisHash {
		t.Fatalf("fixture invariant violated: basis hash changed across input version alone (h1=%s h2=%s)", prior.AssessmentBasisHash, newSnap.AssessmentBasisHash)
	}

	later := now.Add(time.Minute)
	newState := ControllerState{TriagePhase: TriagePhaseNone} // Triage completed by the newer input
	got := RevalidateReuse(prior, newSnap, bumped, newState, later)

	if !got.Ok {
		t.Fatalf("RevalidateReuse rejected an unchanged-basis newer input: %s", got.Reason)
	}
	if got.Result.Derivation != model.DerivationRevalidatedReuse {
		t.Fatalf("Derivation = %q, want revalidated_reuse", got.Result.Derivation)
	}
	if got.Result.ReusedFromAssessmentID == nil || *got.Result.ReusedFromAssessmentID != prior.ID {
		t.Fatalf("ReusedFromAssessmentID = %v, want %q", got.Result.ReusedFromAssessmentID, prior.ID)
	}
	if got.Result.InputVersion != newSnap.InputVersion {
		t.Fatalf("InputVersion = %d, want the NEW snapshot's %d, not the prior's", got.Result.InputVersion, newSnap.InputVersion)
	}
	// Recomputed, not copied: the Operator contract must reflect the newer
	// controller state (Triage now none, not in_flight), so its
	// AlertINTStatus differs from the prior row's.
	if got.Result.Assessment.ActionContract.AlertINTStatus != nil &&
		prior.Assessment.ActionContract.AlertINTStatus != nil &&
		*got.Result.Assessment.ActionContract.AlertINTStatus == *prior.Assessment.ActionContract.AlertINTStatus {
		t.Fatal("reused ActionContract.AlertINTStatus was copied from prior rather than recomputed from the newer ControllerState")
	}
	if got.Result.Assessment.ActionContract.NextUpdateAt == nil ||
		prior.Assessment.ActionContract.NextUpdateAt == nil ||
		got.Result.Assessment.ActionContract.NextUpdateAt.Equal(*prior.Assessment.ActionContract.NextUpdateAt) {
		t.Fatal("reused next_update_at must never be copied from the prior row")
	}
	// Sufficient reason rebound to the NEW snapshot's own candidate ID, not
	// carried over verbatim from the stale prior.
	if got.Result.Assessment.SufficientReason == nil {
		t.Fatal("expected a rebound SufficientReason on the reused Assessment")
	}
	if got.Result.Assessment.SufficientReason.CandidateID == prior.Assessment.SufficientReason.CandidateID {
		t.Fatal("SufficientReason.CandidateID was not rebound to the new Snapshot's own (differently-versioned) candidate ID")
	}
	if err := got.Result.Assessment.Validate(later); err != nil {
		t.Fatalf("reused Assessment fails Assessment.Validate: %v", err)
	}
}

// TestRevalidateReuseSucceedsWellPastPriorNextUpdateAt is the reviewer's
// repro for the trustworthy()-re-breaks-reuse bug: the prior's OWN
// next_update_at promise (computed against the clock at the time prior was
// written) has already elapsed by the time reuse is actually evaluated —
// exactly the case reuse exists to serve (a LATER reconciliation revisiting
// an unchanged basis). Fixture cadence is slow (15 minutes); this wakes
// well past that window, unlike every other reuse test in this file, which
// wakes within ~1 minute of a 2-minute fast-cadence window and so never
// exercised this path. spec.md: the controller "never copies a stale
// next_update_at" — it always recomputes the Operator contract fresh — so
// staleness of the PRIOR's own next_update_at must never by itself make an
// otherwise-valid prior ineligible for reuse.
func TestRevalidateReuseSucceedsWellPastPriorNextUpdateAt(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := baseSnapshotInput(t) // no eligible reasons, no Triage/retry state -> default (slow) cadence
	snap := BuildSnapshot(in)
	call := callFor(snap)
	vr := ValidateAssessmentProposal(marshalRaw(t, validPlainProposal()), snap, call, now)
	if vr.Outcome != ProposalOutcomeAccepted {
		t.Fatalf("fixture proposal not accepted: %v", vr.Errors)
	}
	priorResult := DeriveAssessment(vr.Proposal, snap, in, ControllerState{}, model.DerivationModelValidated, nil, now)
	prior := authoritativeFrom(t, priorResult, "assessment-1", now)
	if prior.Assessment.Cadence != model.CadenceSlow {
		t.Fatalf("fixture invariant violated: want slow cadence, got %q", prior.Assessment.Cadence)
	}
	if prior.Assessment.ActionContract.NextUpdateAt == nil {
		t.Fatal("fixture invariant violated: prior carries no next_update_at")
	}
	// Well past the prior's own promise — not just past cadence, past it by
	// a further hour, so this can never pass by accident of clock rounding.
	wakeAt := prior.Assessment.ActionContract.NextUpdateAt.Add(time.Hour)

	bumped := in
	bumped.Situation.InputVersion++
	newSnap := BuildSnapshot(bumped)
	if newSnap.AssessmentBasisHash != prior.AssessmentBasisHash {
		t.Fatalf("fixture invariant violated: basis hash changed across input version alone")
	}

	got := RevalidateReuse(prior, newSnap, bumped, ControllerState{}, wakeAt)
	if !got.Ok {
		t.Fatalf("RevalidateReuse rejected reuse solely because the prior's own stale next_update_at had elapsed: %s", got.Reason)
	}
	if got.Result.Derivation != model.DerivationRevalidatedReuse {
		t.Fatalf("Derivation = %q, want revalidated_reuse", got.Result.Derivation)
	}
	if err := got.Result.Assessment.Validate(wakeAt); err != nil {
		t.Fatalf("reused Assessment fails Assessment.Validate: %v", err)
	}
}

// TestRevalidateReuseStillRejectsShapeInvalidPrior proves the fix above does
// not overcorrect: trustworthy() must still reject a prior that is
// genuinely shape/consistency-invalid for reasons that have nothing to do
// with next_update_at freshness (here, an unknown Persistence enum value —
// the same class of defect Assessment.Validate would have caught before
// this fix, and Assessment.ValidateShape must still catch after it).
func TestRevalidateReuseStillRejectsShapeInvalidPrior(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := baseSnapshotInput(t)
	snap := BuildSnapshot(in)
	vr := ValidateAssessmentProposal(marshalRaw(t, validPlainProposal()), snap, callFor(snap), now)
	priorResult := DeriveAssessment(vr.Proposal, snap, in, ControllerState{}, model.DerivationModelValidated, nil, now)
	prior := authoritativeFrom(t, priorResult, "assessment-1", now)
	prior.Assessment.Persistence = model.Persistence("bogus") // shape-invalid, unrelated to timing

	bumped := in
	bumped.Situation.InputVersion++
	newSnap := BuildSnapshot(bumped)

	got := RevalidateReuse(prior, newSnap, bumped, ControllerState{}, now.Add(time.Minute))
	if got.Ok {
		t.Fatal("RevalidateReuse must still reject a shape-invalid prior, unrelated to next_update_at freshness")
	}
	if got.Reason != "fails_current_validators" {
		t.Fatalf("Reason = %q, want fails_current_validators", got.Reason)
	}
}

func TestRevalidateReuseForbiddenWhenBasisChanged(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := baseSnapshotInput(t) // no eligible reasons
	snap := BuildSnapshot(in)
	vr := ValidateAssessmentProposal(marshalRaw(t, validPlainProposal()), snap, callFor(snap), now)
	priorResult := DeriveAssessment(vr.Proposal, snap, in, ControllerState{}, model.DerivationModelValidated, nil, now)
	prior := authoritativeFrom(t, priorResult, "assessment-1", now)

	changed := criticalInput(t) // a materially different Situation: critical severity now firing
	changed.Situation.InputVersion = in.Situation.InputVersion + 1
	newSnap := BuildSnapshot(changed)

	got := RevalidateReuse(prior, newSnap, changed, ControllerState{}, now.Add(time.Minute))
	if got.Ok {
		t.Fatal("RevalidateReuse must forbid reuse when the Assessment basis changed")
	}
	if got.Reason != "assessment_basis_changed" {
		t.Fatalf("Reason = %q, want assessment_basis_changed", got.Reason)
	}
}

func TestRevalidateReuseForbiddenAgainstDeterministicFallbackPrior(t *testing.T) {
	// spec.md: a deterministic fallback is never a semantic reuse source
	// while it carries semantic_assessment_unavailable — this is Task 5's
	// direct proof that a due semantic retry cannot satisfy its reuse guard
	// against a fallback prior.
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := baseSnapshotInput(t)
	snap := BuildSnapshot(in)
	fallback := DeterministicFallback(snap, in, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now)
	prior := authoritativeFrom(t, fallback, "assessment-fallback-1", now)

	bumped := in
	bumped.Situation.InputVersion++
	newSnap := BuildSnapshot(bumped)
	if newSnap.AssessmentBasisHash != prior.AssessmentBasisHash {
		t.Fatalf("fixture invariant violated: basis hash changed across input version alone")
	}

	got := RevalidateReuse(prior, newSnap, bumped, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now.Add(time.Minute))
	if got.Ok {
		t.Fatal("a deterministic fallback must never satisfy the reuse guard")
	}
	if got.Reason != "fallback_not_a_semantic_reuse_source" {
		t.Fatalf("Reason = %q, want fallback_not_a_semantic_reuse_source", got.Reason)
	}
}

func TestRevalidateReuseNeverCallsAModel(t *testing.T) {
	// Structural proof: RevalidateReuse's signature and this package's
	// import graph carry no llm client dependency it could dispatch through
	// — internal/situation never imports internal/llm/anthropic or
	// internal/llm/openaicompat (see this test's presence in a file with no
	// such import). This test exists as an explicit, named assertion of that
	// property for the brief's "zero model calls" requirement, backed by
	// TestRevalidateReuseSucceedsAcrossNewerInputWithUnchangedBasis actually
	// exercising a real reuse end to end above.
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := criticalInput(t)
	snap := BuildSnapshot(in)
	vr := ValidateAssessmentProposal(marshalRaw(t, validCriticalProposal(snap)), snap, callFor(snap), now)
	priorResult := DeriveAssessment(vr.Proposal, snap, in, ControllerState{}, model.DerivationModelValidated, nil, now)
	prior := authoritativeFrom(t, priorResult, "assessment-1", now)

	bumped := in
	bumped.Situation.InputVersion++
	newSnap := BuildSnapshot(bumped)
	got := RevalidateReuse(prior, newSnap, bumped, ControllerState{}, now.Add(time.Minute))
	if !got.Ok {
		t.Fatalf("expected reuse to succeed: %s", got.Reason)
	}
}

// ----------------------------------------------------------------------
// Per-Incident coverage metadata (brief bullet 4): every derivation path
// records the canonical bounded tuple; reuse rebinds it fresh.
// ----------------------------------------------------------------------

func TestDeriveIncidentCoverageMatchesMembershipAndInputDigests(t *testing.T) {
	in := criticalInput(t)
	snap := BuildSnapshot(in)
	got := DeriveIncidentCoverage(in)
	if len(got) != 1 {
		t.Fatalf("Coverage len = %d, want 1", len(got))
	}
	want := model.IncidentCoverage{
		IncidentID:          "incident-1",
		MembershipDigest:    MembershipDigest("incident-1", in.Deliveries),
		IncidentInputDigest: IncidentInputDigest("incident-1", "group-1", in.Deliveries),
	}
	if got[0] != want {
		t.Fatalf("Coverage[0] = %+v, want %+v", got[0], want)
	}
	_ = snap
}

func TestCoverageRecordedByEveryDerivationPath(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := criticalInput(t)
	snap := BuildSnapshot(in)
	want := DeriveIncidentCoverage(in)

	modelValidated := DeriveAssessment(validCriticalProposal(snap), snap, in, ControllerState{}, model.DerivationModelValidated, nil, now)
	deterministic := DeterministicAssessment(snap, in, ControllerState{}, model.DerivationDeterministic, nil, now)
	fallback := DeterministicFallback(snap, in, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now)

	for name, res := range map[string]AssessmentResult{
		"model_validated": modelValidated, "deterministic": deterministic, "fallback": fallback,
	} {
		if len(res.Coverage) != len(want) || res.Coverage[0] != want[0] {
			t.Fatalf("%s: Coverage = %+v, want %+v", name, res.Coverage, want)
		}
	}
}

func TestReuseRebindsCoverageToNewInputNeverCopyingStalePrior(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := criticalInput(t)
	snap := BuildSnapshot(in)
	priorResult := DeriveAssessment(validCriticalProposal(snap), snap, in, ControllerState{}, model.DerivationModelValidated, nil, now)
	prior := authoritativeFrom(t, priorResult, "assessment-1", now)
	// Corrupt prior's own coverage to a value that could never legitimately
	// match the new input — proves RevalidateReuse never copies it forward.
	prior.Coverage = []model.IncidentCoverage{{IncidentID: "incident-1", MembershipDigest: "stale", IncidentInputDigest: "stale"}}

	bumped := in
	bumped.Situation.InputVersion++
	newSnap := BuildSnapshot(bumped)
	got := RevalidateReuse(prior, newSnap, bumped, ControllerState{}, now.Add(time.Minute))
	if !got.Ok {
		t.Fatalf("expected reuse to succeed: %s", got.Reason)
	}
	want := DeriveIncidentCoverage(bumped)
	if len(got.Result.Coverage) != 1 || got.Result.Coverage[0] != want[0] {
		t.Fatalf("Coverage = %+v, want freshly computed %+v (not the corrupted prior)", got.Result.Coverage, want)
	}
}

// ----------------------------------------------------------------------
// DeterministicFallback with no prior Assessment (brief bullet 5).
// ----------------------------------------------------------------------

func TestDeterministicFallbackNoPriorAssessment(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := baseSnapshotInput(t) // no eligible reasons, no floor
	snap := BuildSnapshot(in)

	got := DeterministicFallback(snap, in, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now)

	if got.Derivation != model.DerivationDeterministicFallback {
		t.Fatalf("Derivation = %q, want deterministic_fallback", got.Derivation)
	}
	if got.Assessment.Lifecycle != snap.Lifecycle {
		t.Fatalf("Lifecycle = %q, want the current snapshot Lifecycle %q", got.Assessment.Lifecycle, snap.Lifecycle)
	}
	if got.Assessment.Attention != model.AttentionObserve {
		t.Fatalf("Attention = %q, want observe (no floor present)", got.Assessment.Attention)
	}
	if got.Assessment.Persistence != model.PersistenceUnknown || got.Assessment.Impact != model.ImpactNoneObserved ||
		got.Assessment.Novelty != model.NoveltyInsufficientHistory || got.Assessment.Causality != model.CausalityUnknown {
		t.Fatalf("conservative semantic fields not applied: %+v", got.Assessment)
	}
	foundLimitation := false
	for _, l := range got.Assessment.Limitations {
		if l.Code == limitationSemanticAssessmentUnavailable {
			foundLimitation = true
		}
	}
	if !foundLimitation {
		t.Fatalf("Limitations = %v, want semantic_assessment_unavailable", got.Assessment.Limitations)
	}
	if got.Assessment.ActionContract.AlertINTAction == nil || *got.Assessment.ActionContract.AlertINTAction != model.AlertINTActionRetrySituationAssessment {
		t.Fatalf("action = %v, want retry_situation_assessment (bounded model retry checkpoint)", got.Assessment.ActionContract.AlertINTAction)
	}
	if err := got.Assessment.Validate(now); err != nil {
		t.Fatalf("fallback Assessment fails Assessment.Validate: %v", err)
	}
}

func TestDeterministicFallbackAppliesUrgentFloorWhenOneExists(t *testing.T) {
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := criticalInput(t)
	snap := BuildSnapshot(in)

	got := DeterministicFallback(snap, in, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now)
	if got.Assessment.Attention != model.AttentionUrgent {
		t.Fatalf("Attention = %q, want urgent: a deterministic floor is proven", got.Assessment.Attention)
	}
	if got.Assessment.SufficientReason == nil || got.Assessment.SufficientReason.Code != reasonCodeCriticalAnchor {
		t.Fatalf("SufficientReason = %v, want the deterministic critical_anchor floor recorded", got.Assessment.SufficientReason)
	}
}

func TestDeterministicFallbackCannotSatisfyDueSemanticRetryReuseGuard(t *testing.T) {
	// Duplicated, named assertion of
	// TestRevalidateReuseForbiddenAgainstDeterministicFallbackPrior's
	// property, phrased against the brief's own "due semantic retry" wording.
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := baseSnapshotInput(t)
	snap := BuildSnapshot(in)
	fallback := DeterministicFallback(snap, in, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now)
	prior := authoritativeFrom(t, fallback, "assessment-fallback-1", now)

	bumped := in
	bumped.Situation.InputVersion++
	newSnap := BuildSnapshot(bumped)
	got := RevalidateReuse(prior, newSnap, bumped, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now.Add(time.Minute))
	if got.Ok {
		t.Fatal("a due semantic retry must dispatch bounded L2 work, never satisfy reuse against a fallback")
	}
}

func TestDeterministicFallbackDueThenParkedContractsDiffer(t *testing.T) {
	// "bounded work dispatches until parked, after which automatic calls
	// stop": proven here as the two distinct Operator-contract shapes the
	// caller's SemanticRetryPhase selects — Task 8 owns WHEN the transition
	// from Due to Blocked happens (attempt-budget bookkeeping); Task 5 only
	// guarantees each phase renders correctly.
	now := mustTime(t, "2026-09-01T12:00:00Z")
	in := baseSnapshotInput(t)
	snap := BuildSnapshot(in)

	due := DeterministicFallback(snap, in, ControllerState{SemanticRetry: SemanticRetryPhaseDue}, now)
	if due.Assessment.ActionContract.AlertINTStatus == nil || *due.Assessment.ActionContract.AlertINTStatus != model.AlertINTStatusWaiting {
		t.Fatalf("due status = %v, want waiting", due.Assessment.ActionContract.AlertINTStatus)
	}

	blocked := DeterministicFallback(snap, in, ControllerState{SemanticRetry: SemanticRetryPhaseBlocked}, now)
	if blocked.Assessment.ActionContract.AlertINTStatus == nil || *blocked.Assessment.ActionContract.AlertINTStatus != model.AlertINTStatusBlocked {
		t.Fatalf("blocked status = %v, want blocked", blocked.Assessment.ActionContract.AlertINTStatus)
	}
	if blocked.Assessment.ActionContract.WaitReason == nil || *blocked.Assessment.ActionContract.WaitReason != model.WaitReasonAssessmentParked {
		t.Fatalf("blocked wait_reason = %v, want assessment_parked", blocked.Assessment.ActionContract.WaitReason)
	}
}

func TestDeriveEvidenceQualityFromFactAvailabilityAlone(t *testing.T) {
	complete := Snapshot{Facts: []model.Fact{
		{Material: true, ResultStatus: model.FactConfirmedValue},
		{Material: true, ResultStatus: model.FactConfirmedEmpty},
		{Material: false, ResultStatus: model.FactUnavailable}, // non-material: ignored
	}}
	if got := DeriveEvidenceQuality(complete); got != model.EvidenceQualityComplete {
		t.Fatalf("DeriveEvidenceQuality = %q, want complete", got)
	}

	degraded := Snapshot{Facts: []model.Fact{
		{Material: true, ResultStatus: model.FactConfirmedValue},
		{Material: true, ResultStatus: model.FactUnavailable},
	}}
	if got := DeriveEvidenceQuality(degraded); got != model.EvidenceQualityDegraded {
		t.Fatalf("DeriveEvidenceQuality = %q, want degraded", got)
	}

	insufficient := Snapshot{Facts: []model.Fact{
		{Material: true, ResultStatus: model.FactUnavailable},
		{Material: true, ResultStatus: model.FactFailed},
	}}
	if got := DeriveEvidenceQuality(insufficient); got != model.EvidenceQualityInsufficient {
		t.Fatalf("DeriveEvidenceQuality = %q, want insufficient", got)
	}
}

// ----------------------------------------------------------------------
// ClassifyL2Outcome: outcome matrix (brief bullet 6).
// ----------------------------------------------------------------------

func TestClassifyL2OutcomeMalformedFirstPermitsOneCorrection(t *testing.T) {
	got := ClassifyL2Outcome(nil, llm.ErrSchemaViolation, false)
	if got.Outcome != L2OutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
	if !got.ImmediateCorrection {
		t.Fatal("expected exactly one immediate correction to be permitted on the first malformed response")
	}
	if !got.DurableRetry {
		t.Fatal("expected durable retry to remain available")
	}
}

func TestClassifyL2OutcomeMalformedSecondRejectsCorrectionButRetries(t *testing.T) {
	got := ClassifyL2Outcome(nil, llm.ErrSchemaViolation, true)
	if got.Outcome != L2OutcomeMalformed {
		t.Fatalf("Outcome = %q, want malformed", got.Outcome)
	}
	if got.ImmediateCorrection {
		t.Fatal("Plan 2 permits at most one immediate correction; a second malformed response must not grant another")
	}
	if !got.DurableRetry {
		t.Fatal("expected durable retry (while attempt budget remains) to remain available")
	}
}

func TestClassifyL2OutcomeTransportFailuresRetryWithoutCorrection(t *testing.T) {
	for name, err := range map[string]error{
		"timeout":     context.DeadlineExceeded,
		"network":     &url.Error{Op: "Get", URL: "https://example.invalid", Err: &net.AddrError{Err: "no such host"}},
		"unavailable": &llm.RetryableError{StatusCode: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			got := ClassifyL2Outcome(nil, err, false)
			if got.Outcome != L2OutcomeTransportFailure {
				t.Fatalf("Outcome = %q, want transport_failure", got.Outcome)
			}
			if got.ImmediateCorrection {
				t.Fatal("a transport failure must never grant an immediate correction")
			}
			if !got.DurableRetry {
				t.Fatal("expected durable retry with typed backoff")
			}
		})
	}
}

func TestClassifyL2OutcomeRateLimitedRetriesRespectingProviderTiming(t *testing.T) {
	got := ClassifyL2Outcome(nil, &llm.RetryableError{StatusCode: http.StatusTooManyRequests}, false)
	if got.Outcome != L2OutcomeRateLimited {
		t.Fatalf("Outcome = %q, want rate_limited", got.Outcome)
	}
	if got.ImmediateCorrection {
		t.Fatal("a rate limit must never grant an immediate correction")
	}
	if !got.DurableRetry {
		t.Fatal("expected durable retry")
	}
}

func TestClassifyL2OutcomePolicyAndCapabilityRejectionsPark(t *testing.T) {
	snap := snapshotFor(t, baseSnapshotInput(t))
	call := callFor(snap)
	p := validPlainProposal()
	p.Attention = model.AttentionUrgent // urgent without a floor: policy rejection
	vrPolicy := ValidateAssessmentProposal(marshalRaw(t, p), snap, call, time.Now())
	gotPolicy := ClassifyL2Outcome(&vrPolicy, nil, false)
	if gotPolicy.Outcome != L2OutcomePolicyRejected {
		t.Fatalf("Outcome = %q, want policy_rejected", gotPolicy.Outcome)
	}
	if gotPolicy.ImmediateCorrection || gotPolicy.DurableRetry {
		t.Fatalf("policy rejection must never retry until relevant input changes, got %+v", gotPolicy)
	}

	p2 := validPlainProposal()
	p2.SufficientReason = &model.SufficientReason{Code: "critical_anchor", CandidateID: "not-real"}
	vrCapability := ValidateAssessmentProposal(marshalRaw(t, p2), snap, call, time.Now())
	gotCapability := ClassifyL2Outcome(&vrCapability, nil, false)
	if gotCapability.Outcome != L2OutcomeCapabilityRejected {
		t.Fatalf("Outcome = %q, want capability_rejected", gotCapability.Outcome)
	}
	if gotCapability.ImmediateCorrection || gotCapability.DurableRetry {
		t.Fatalf("capability rejection must never retry until relevant input changes, got %+v", gotCapability)
	}
}

func TestClassifyL2OutcomeContradictedIsAuthoritativeWithoutCall2(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	p := validCriticalProposal(snap)
	p.Causality = model.CausalityContradicted
	vr := ValidateAssessmentProposal(marshalRaw(t, p), snap, call, time.Now())

	got := ClassifyL2Outcome(&vr, nil, false)
	if got.Outcome != L2OutcomeContradicted {
		t.Fatalf("Outcome = %q, want contradicted", got.Outcome)
	}
	if got.ImmediateCorrection || got.DurableRetry {
		t.Fatalf("a valid contradicted Assessment must stand alone: no correction, no retry, got %+v", got)
	}
}

func TestClassifyL2OutcomeAcceptedNeedsNoRetryOrCorrection(t *testing.T) {
	snap := snapshotFor(t, criticalInput(t))
	call := callFor(snap)
	vr := ValidateAssessmentProposal(marshalRaw(t, validCriticalProposal(snap)), snap, call, time.Now())

	got := ClassifyL2Outcome(&vr, nil, false)
	if got.Outcome != L2OutcomeAccepted {
		t.Fatalf("Outcome = %q, want accepted", got.Outcome)
	}
	if got.ImmediateCorrection || got.DurableRetry {
		t.Fatalf("a valid Assessment must not retry or correct, got %+v", got)
	}
}
