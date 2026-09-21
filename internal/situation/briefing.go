// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// BuildOperatorBriefing selects presentation facts without changing evidence,
// lifecycle, assessment prompts or reuse identity. Selection is deterministic.
//
// Alert counts and per-alert states come from briefingAlertStates — the
// same per-Incident, per-Alert latest-delivery fold the lifecycle reads
// (deriveSymptoms / incidentSymptomStatus), never a second reducer — so
// Firing > 0 here holds exactly when AnyFiring(deriveSymptoms(in.Deliveries))
// holds for the controller (B0 integration contract §2). Unknown is
// reserved for a source state this tree cannot observe and is always 0.
func BuildOperatorBriefing(in SnapshotInput, lifecycle model.Lifecycle) *model.OperatorBriefing {
	b := &model.OperatorBriefing{Historical: lifecycle != model.LifecycleActive, BlockedReason: in.ControllerParked.Reason, AssessmentRetryAt: in.Situation.RetryAt}
	b.Flow = buildOperatorFlow(in)
	scopes, symptoms := map[string]bool{}, map[string]bool{}
	displayScopes := map[string]bool{}
	states := briefingAlertStates(in.Deliveries)
	alerts := make([]briefingAlertCandidate, 0, len(states))
	for id, s := range states {
		b.Total++
		alertState := "resolved"
		if s.firing {
			b.Firing++
			alertState = "firing"
		} else {
			b.Resolved++
		}
		latest := s.latest
		candidate := newBriefingAlert(id, alertState, latest.Labels)
		candidate.alert.SourceSummary = briefingLabel(latest.SourceSummary, 500)
		alerts = append(alerts, candidate)
		if display := briefingDisplayScope(latest.Labels); display != "" {
			displayScopes[display] = true
		}
		if s.firing && strings.EqualFold(latest.Severity, "critical") {
			b.Critical++
		}
		var scope []string
		for _, key := range []string{"service", "namespace", "environment", "cluster"} {
			if v := strings.TrimSpace(latest.Labels[key]); v != "" {
				scope = append(scope, boundedText(v, 80))
			}
		}
		if len(scope) > 0 {
			scopes[strings.Join(scope, " · ")] = true
		}
		if v := strings.TrimSpace(latest.Labels["alertname"]); v != "" {
			symptoms[boundedText(v, 120)] = true
		}
	}
	b.Scope = strings.Join(briefingValues(scopes, 3), "; ")
	if b.Scope == "" {
		b.Scope = boundedText(in.Situation.GroupKey, 180)
	}
	if b.Scope == "" {
		b.Scope = "Affected scope unavailable"
	}
	b.Symptoms = briefingValues(symptoms, 3)
	b.Alerts, b.AlertsOmitted = selectBriefingAlerts(alerts)
	b.DisplayScope = briefingLabel(strings.Join(briefingValues(displayScopes, 3), "; "), 180)
	if b.DisplayScope == "" {
		b.DisplayScope = briefingLabel(b.Scope, 180)
	}
	b.Failed, b.Pending, b.Unavailable = briefingWorkCounts(in.Incidents)
	b.Analyses = append([]model.IncidentAnalysis(nil), in.Analyses...)
	sort.Slice(b.Analyses, func(i, j int) bool {
		a, c := b.Analyses[i], b.Analyses[j]
		if a.Stale != c.Stale {
			return !a.Stale
		}
		if a.AnalyzedAt != nil && c.AnalyzedAt != nil && !a.AnalyzedAt.Equal(*c.AnalyzedAt) {
			return a.AnalyzedAt.After(*c.AnalyzedAt)
		}
		if (a.AnalyzedAt == nil) != (c.AnalyzedAt == nil) {
			return a.AnalyzedAt != nil
		}
		return a.IncidentID < c.IncidentID
	})
	b.AnalysisCount = len(b.Analyses)
	if in.AnalysisCount > b.AnalysisCount {
		b.AnalysisCount = in.AnalysisCount
	}
	if len(b.Analyses) > 3 {
		b.Analyses = b.Analyses[:3]
	}
	for i := range b.Analyses {
		b.Analyses[i] = model.BoundIncidentAnalysis(b.Analyses[i])
	}
	return b
}

type briefingAlertCandidate struct {
	alert   model.BriefingAlert
	context string
}

// briefingAlertState is one distinct Alert's display state: firing when ANY
// member Incident's latest delivery for that Alert is firing (exactly the
// lifecycle's per-Incident rule), plus the overall latest delivery whose
// immutable labels name it.
type briefingAlertState struct {
	firing bool
	latest Delivery
}

// briefingAlertStates folds deliveries per Incident with
// latestDeliveryPerAlert — the lifecycle's own fold — and merges the
// per-Incident results per Alert with firing winning, so an Alert that
// appears under two Incidents reads the way resolveLifecycle reads it.
func briefingAlertStates(deliveries []Delivery) map[string]briefingAlertState {
	byIncident := make(map[string][]Delivery, len(deliveries))
	for _, d := range deliveries {
		byIncident[d.IncidentID] = append(byIncident[d.IncidentID], d)
	}
	states := make(map[string]briefingAlertState)
	for _, ds := range byIncident {
		for key, latest := range latestDeliveryPerAlert(ds) {
			s, ok := states[key]
			if !ok || deliveryLess(s.latest, latest) {
				s.latest = latest
			}
			s.firing = s.firing || latest.Status == model.DeliveryStatusFiring
			states[key] = s
		}
	}
	return states
}

func briefingLabel(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > limit {
		return boundedText(s, limit-3) + "…"
	}
	return s
}

func newBriefingAlert(id, state string, labels map[string]string) briefingAlertCandidate {
	// Never truncate identity: distinct long IDs must not become the same alert.
	if len(id) > 200 {
		id = canonicalDigest(id)
	}
	name := briefingLabel(labels["alertname"], 160)
	if name == "" {
		name = "Unnamed alert"
	}
	host := labels["host"]
	if host == "" {
		host = labels["instance"]
	}
	var context []string
	for _, value := range []string{host, labels["service"], labels["namespace"]} {
		if value = briefingLabel(value, 80); value != "" {
			context = append(context, value)
		}
	}
	joinedContext := strings.Join(context, " · ")
	return briefingAlertCandidate{alert: model.BriefingAlert{ID: id, Name: name, Service: briefingLabel(labels["service"], 80), Context: briefingLabel(joinedContext, 240), State: state}, context: joinedContext}
}

func selectBriefingAlerts(candidates []briefingAlertCandidate) ([]model.BriefingAlert, int) {
	names := make(map[string]int, len(candidates))
	for _, c := range candidates {
		names[c.alert.Name]++
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].alert.ID < candidates[j].alert.ID })
	alerts := make([]model.BriefingAlert, 0, len(candidates))
	for _, c := range candidates {
		if names[c.alert.Name] > 1 && c.context != "" {
			c.alert.Name += " (" + c.context + ")"
		}
		c.alert.Name = briefingLabel(c.alert.Name, 240)
		alerts = append(alerts, c.alert)
	}
	return alerts, 0
}

func buildOperatorFlow(in SnapshotInput) *model.OperatorFlow {
	flow := &model.OperatorFlow{
		FirstReceivedAt:             in.Situation.FirstReceivedAt.UTC(),
		CorrelationOpenedAt:         in.Situation.FirstReceivedAt.UTC(),
		GroupKey:                    briefingLabel(in.Situation.GroupKey, 500),
		GroupingRule:                groupingRuleDescription(in.Situation.GroupKey),
		InvestigationStartedAt:      briefingTimePtr(in.PresentationFacts.InvestigationStartedAt),
		InvestigationCompletedAt:    briefingTimePtr(in.PresentationFacts.InvestigationCompletedAt),
		InvestigationRuntimeSeconds: int64Ptr(in.PresentationFacts.InvestigationRuntimeSeconds),
		AnalysisUsage:               in.PresentationFacts.AnalysisUsage,
		SourceChecks:                append([]model.SourceCheck(nil), in.PresentationFacts.SourceChecks...),
	}
	for _, inc := range in.Incidents {
		if inc.ReadyAt.IsZero() {
			continue
		}
		at := inc.ReadyAt.UTC()
		if flow.CorrelationClosesAt == nil || at.Before(*flow.CorrelationClosesAt) {
			flow.CorrelationClosesAt = &at
		}
	}
	return flow
}

func int64Ptr(in *int64) *int64 {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func briefingTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	at := in.UTC()
	return &at
}

func groupingRuleDescription(groupKey string) string {
	var keys []string
	for _, part := range strings.Split(groupKey, ",") {
		if key, _, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.TrimSpace(key) != "" {
			keys = append(keys, strings.TrimSpace(key))
		}
	}
	if len(keys) == 0 {
		return "Configured receiver grouping"
	}
	sort.Strings(keys)
	return "Same configured " + strings.Join(keys, " and ")
}

func mergePresentationSourceChecks(configured, recorded []model.SourceCheck) []model.SourceCheck {
	recordedIdentity := make(map[string]bool, len(recorded))
	for _, check := range recorded {
		recordedIdentity[check.Source+"\x00"+check.Check] = true
	}
	var out []model.SourceCheck
	for _, check := range configured {
		if !recordedIdentity[check.Source+"\x00"+check.Check] {
			out = append(out, check)
		}
	}
	out = append(out, recorded...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Check < out[j].Check
	})
	return out
}

func briefingDisplayScope(labels map[string]string) string {
	primary := labels["service"]
	if primary == "" {
		primary = labels["namespace"]
	}
	if primary == "" {
		primary = labels["cluster"]
	}
	var parts []string
	for _, s := range []string{primary, labels["environment"]} {
		if s = briefingLabel(s, 80); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " · ")
}

// CommittedOperatorBriefing is the committed publication projection of one
// reconciliation: BuildOperatorBriefing over the decision-overlaid input plus
// the coherent WorkProjection (contract §3) with its investigation-input and
// ended-work provenance. Exported so internal/store's own provenance tests
// can drive the real frozen-claim load → projection → commit → reload path
// (lead decision B/D, round 2, 2026-09-09); Reconcile is its one production
// caller. Only the current committed work contract can select a retry
// timestamp. NextUpdateAt is a status checkpoint, not proof that work is due
// then.
func CommittedOperatorBriefing(in SnapshotInput, commit ControllerCommit) *model.OperatorBriefing {
	in = committedBriefingInput(in, commit.TriageDecisions)
	b := BuildOperatorBriefing(in, commit.Lifecycle)
	if commit.JudgmentApplicable && in.Judgment != nil {
		b.ExpectedJudgment = &model.ExpectedJudgmentProjection{
			Revision: in.Judgment.Revision, AssertedOperator: in.Judgment.AssertedOperator,
			ValidUntil: in.Judgment.ValidUntil.UTC(),
		}
	}
	if evaluation := commit.ExpectedBehaviorEvaluation; evaluation != nil && len(evaluation.Candidates) > 0 { //nolint:nestif // aggregate precedence and chosen-candidate projection stay together.
		candidate := evaluation.Candidates[0]
		if evaluation.ChosenEnvelopeID != "" {
			for _, current := range evaluation.Candidates {
				if current.EnvelopeID == evaluation.ChosenEnvelopeID {
					candidate = current
					break
				}
			}
		}
		projection := &model.ExpectedBehaviorProjection{
			EnvelopeID: candidate.EnvelopeID, Version: candidate.Version,
			Disposition: evaluation.Disposition, Reason: evaluation.Reason,
		}
		if evaluation.Occurrence != nil {
			boundary := evaluation.Occurrence.Boundary.UTC()
			projection.Boundary = &boundary
		}
		for _, head := range in.ExpectedBehaviorHeads {
			if head.EnvelopeID == candidate.EnvelopeID {
				projection.AssertedOperator = head.AssertedOperator
				projection.Source = head.Scope.Source
				if head.Policy != nil {
					projection.Workload = head.Policy.Conditions.Workload
				}
				break
			}
		}
		b.ExpectedBehavior = projection
	}
	if commit.Parked.Touch {
		b.BlockedReason = commit.Parked.Reason
	}
	b.AssessmentRetryAt = commit.RetryAt
	b.Work = BuildWorkProjection(in.Incidents, commit.GraceUntil, commit.Assessment.ActionContract.NextUpdateAt)
	// R3 repair (lead review 2026-09-09): BuildWorkProjection's own
	// 3-parameter shape is a pinned external test boundary (see its doc
	// comment) and only ever sees per-incident Triage backoff. The committed
	// Assessment-level retry (situations.retry_at, ControllerCommit.RetryAt
	// — contract §3's "next_at / retry_at") is carried here instead,
	// truthfully distinct from a status checkpoint. Earliest of the two
	// wins: a Triage backoff and an Assessment retry are independently
	// scheduled and either can be outstanding at once; RetryEligibleAt
	// promises the actual next one, not only the triage-schedule one.
	b.Work.RetryEligibleAt = earliestNonNil(b.Work.RetryEligibleAt, commit.RetryAt)
	// R1 repair (lead review 2026-09-09): the actual investigation input —
	// the frozen claim-time member deliveries each Incident's current
	// execution ran against, resolved to Alert identity/name — never
	// Situation.Total (plan.md item 3).
	b.Work.InvestigatedAlertIDs, b.Work.InvestigatedNames, b.Work.InvestigatedCount, b.Work.InvestigatedCountKnown = investigatedAlertInputs(in.Incidents, in.Deliveries)
	c := commit.Assessment.ActionContract
	if commit.Lifecycle.Terminal() || c.AlertINTAction == nil || c.AlertINTStatus == nil || *c.AlertINTStatus != model.AlertINTStatusWaiting || c.WaitReason == nil {
		return b
	}
	var due *time.Time
	switch {
	case *c.AlertINTAction == model.AlertINTActionRunAcuteTriage && *c.WaitReason == model.WaitReasonAcuteTriageBackoff:
		for _, inc := range in.Incidents {
			if inc.Triage.Phase == "backoff" && inc.Triage.NextAt != nil && (due == nil || inc.Triage.NextAt.Before(*due)) {
				due = inc.Triage.NextAt
			}
		}
	case *c.AlertINTAction == model.AlertINTActionRetrySituationAssessment && *c.WaitReason == model.WaitReasonAssessmentRetry:
		due = commit.RetryAt
	}
	if due != nil {
		b.RetryAt = timePtr(due.UTC())
	}
	return b
}

// earliestNonNil returns whichever of a, b is earlier, either one when the
// other is nil, or nil when both are — the shared "truthful distinct
// timing" rule WorkProjection's independent instants use (R3).
func earliestNonNil(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.Before(*a):
		return b
	default:
		return a
	}
}

// investigatedAlertIdentities unions each Incident's CURRENT execution's
// frozen claim-time member delivery IDs (ActiveAttempt when one is running,
// else the most recent LastExecution) into the actual Alert identities/
// names that execution analyzed — resolved through in's own Deliveries,
// never the Situation's current membership, which may have grown or changed
// since that attempt was claimed (B0 integration contract §3;
// plan.md item 3: "Situation.Total is not investigation input count"). A
// member delivery id this Situation no longer carries (a legacy/reassigned
// row) is silently skipped rather than fabricated. Bounded and
// deterministically ordered by Alert ID, same naming as BriefingAlert.Name
// (newBriefingAlert) — an unrecognized name still reports "Unnamed alert"
// rather than an empty string.
func investigatedAlertIdentities(incidents []IncidentState, deliveries []Delivery) (ids, names []string) {
	ids, names, _, _ = investigatedAlertInputs(incidents, deliveries)
	return ids, names
}

// investigatedIdentityLimit bounds the persisted identity list and
// investigatedNameLimit the display names one reply lists. They are
// deliberately different: the identities are provenance a later reader can
// resolve, the names are what fits a Slack reply. Neither bound is ever the
// investigation's input count — investigatedAlertInputs returns that
// separately, counted before either is applied (R3 repair, lead review
// 2026-09-09).
const (
	investigatedIdentityLimit = 64
	investigatedNameLimit     = 8
)

// investigatedAlertInputs is investigatedAlertIdentities plus the exact
// number of distinct frozen claim-time inputs that execution ran against,
// so a reply can state the real count without a caller re-deriving the
// union or mistaking a bounded list length for it. known is true ONLY when
// the complete frozen union was resolved and counted before truncation
// (lead decision B, round 2, 2026-09-09): a frozen member delivery id this
// Situation's deliveries cannot resolve (a legacy/moved row) is skipped from
// the list as before, but it makes the count unknown rather than silently
// under-reported; an execution with no recorded member deliveries at all
// (a pre-ledger claim that fell back to incident_alerts) is likewise
// unknown, never a known zero.
//
// Completeness is judged per EXECUTION, not per resolved identity (R1
// repair, lead review round 3, 2026-09-09): every member that actually ran
// must have recorded the inputs it ran against, so one execution missing
// that provenance makes the union incomplete even while another resolves
// completely. The identities that DID resolve are still returned as partial
// facts; only the exact numeric claim is withheld.
func investigatedAlertInputs(incidents []IncidentState, deliveries []Delivery) (ids, names []string, count int, known bool) {
	byDeliveryID := make(map[string]Delivery, len(deliveries))
	for _, d := range deliveries {
		byDeliveryID[d.ID] = d
	}

	order := make([]string, 0, len(incidents))
	nameByID := make(map[string]string, len(incidents))
	executed, incomplete := false, false
	for _, inc := range incidents {
		exec := inc.Triage.ActiveAttempt
		if exec == nil {
			exec = inc.Triage.LastExecution
		}
		if exec == nil {
			// A member that counted attempts but carries no attempt-ledger
			// row (a pre-ledger claim) ran against inputs this projection
			// cannot name. A member that never ran contributes no inputs and
			// is not a gap.
			if inc.Triage.Attempts > 0 {
				executed, incomplete = true, true
			}
			continue
		}
		executed = true
		// An attempt row whose frozen member list is empty analyzed inputs
		// it did not record: unknown, exactly as a lone such execution is.
		if len(exec.MemberDeliveryIDs) == 0 {
			incomplete = true
		}
		for _, deliveryID := range exec.MemberDeliveryIDs {
			d, ok := byDeliveryID[deliveryID]
			if !ok {
				incomplete = true
				continue
			}
			id := d.AlertID
			if id == "" {
				id = "delivery:" + d.ID
			}
			if len(id) > 200 { // never truncate identity into a collision — same bound newBriefingAlert uses
				id = canonicalDigest(id)
			}
			if _, dup := nameByID[id]; dup {
				continue
			}
			name := briefingLabel(d.Labels["alertname"], 160)
			if name == "" {
				name = "Unnamed alert"
			}
			nameByID[id] = name
			order = append(order, id)
		}
	}
	sort.Strings(order)
	count = len(order)
	known = executed && !incomplete && count > 0
	ids = make([]string, 0, min(count, investigatedIdentityLimit))
	names = make([]string, 0, min(count, investigatedNameLimit))
	for i, id := range order {
		if i < investigatedIdentityLimit {
			ids = append(ids, id)
		}
		if i < investigatedNameLimit {
			names = append(names, nameByID[id])
		}
	}
	return ids, names, count, known
}

// investigatedInputCount is the truthful number of investigation inputs a
// reply may state: the exact recorded count when this projection positively
// knows it, otherwise 0 — meaning UNKNOWN, never "no inputs". A bounded
// identity list is never presented as an exact count (lead decision B, round
// 2, 2026-09-09): accepted B2 persisted at most eight IDs and this candidate
// at most sixty-four, and neither length proves the union was complete, so
// legacy JSON without InvestigatedCountKnown reads as unknown. Never
// Situation.Total, which counts current membership, not what executed.
func investigatedInputCount(w model.WorkProjection) int {
	if w.InvestigatedCountKnown && w.InvestigatedCount > 0 {
		return w.InvestigatedCount
	}
	return 0
}

func briefingWorkCounts(incidents []IncidentState) (failed, pending, unavailable int) {
	for _, inc := range incidents {
		if inc.Triage.Phase == "exhausted" {
			failed++
			continue
		}
		if inc.Triage.Phase == "skipped" && inc.Status != "analyzed" && inc.Status != "resolved" {
			unavailable++
			continue
		}
		switch inc.Status {
		case "failed":
			failed++
		case "collecting", "ready", "processing":
			pending++
		}
	}
	return failed, pending, unavailable
}

// Overlay only the work phases (and, for a freshly skipped row, the exact
// reason this cycle decided) this commit will persist, on a presentation
// copy. The coherent input and snapshot remain the original assessment
// basis. Shares effectiveTriagePhase with aggregateTriagePhase/
// earliestTriageDue (controller.go) so the presentation overlay and the
// controller's own aggregate can never disagree (B0 integration contract
// §3; S2-02's "committed projection agrees with durable work").
func committedBriefingInput(in SnapshotInput, decisions []TriageDecision) SnapshotInput {
	byIncident := decisionsByIncident(decisions)
	in.Incidents = append([]IncidentState(nil), in.Incidents...)
	for i := range in.Incidents {
		inc := &in.Incidents[i]
		phase := effectiveTriagePhase(*inc, byIncident)
		if phase == inc.Triage.Phase {
			continue
		}
		inc.Triage.Phase = phase
		// A phase move only ever happens from awaiting_decision, where the
		// prior decision_reason is always nil — this cycle's fresh reason
		// is the only one that can apply, never a stale reason left over
		// from a different decision (plan.md: "do not keep an old request
		// reason under a newly skipped result").
		if d, ok := byIncident[inc.ID]; ok {
			reason := d.DecisionReason
			inc.Triage.DecisionReason = &reason
			// The same commit that moves this schedule to pending also
			// stamps its durable next_at with this cycle's instant
			// (applyRequestFromAwaitingDecisionTx: next_at = now, anchored
			// on canonicalCommitTime, which is the Reconcile now this
			// DecidedAt was taken from). earliestTriageDue already treats a
			// just-requested schedule as due at that same instant; the
			// presentation copy carries it too, so the queued line states
			// the eligibility the commit records instead of reporting none
			// (G1 repair, lead final review 2026-09-10).
			if phase == "pending" {
				eligibleAt := d.DecidedAt.UTC()
				inc.Triage.NextAt = &eligibleAt
			}
		}
		inc.Triage.SkipReason = TriageSkipReason(inc.Triage)
	}
	return in
}

func briefingValues(values map[string]bool, limit int) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = append(out[:limit], "…")
	}
	return out
}

func operatorBriefingChanged(a, b *model.OperatorBriefing) bool {
	return canonicalDigest(briefingMaterialityView(a)) != canonicalDigest(briefingMaterialityView(b))
}

// briefingMaterialityView strips Work.StatusCheckpointAt before comparison:
// ActionContract.NextUpdateAt (its source, see BuildWorkProjection) ticks
// every cadence cycle by design and must never by itself make an R4
// deadline-refresh cycle look materially changed — the exact reason
// operatorContractTuple already excludes NextUpdateAt from the Operator
// contract's own materiality tuple. This changes only whether a Transition
// gets created (history.go's selectControllerReason), never reply
// eligibility or rendering.
func briefingMaterialityView(b *model.OperatorBriefing) *model.OperatorBriefing {
	if b == nil {
		return nil
	}
	cp := *b
	cp.Work.StatusCheckpointAt = nil
	return &cp
}

// A repeated judgment's clock or paraphrased cause does not establish new
// evidence. A first analysis or changed structured facts (Observations,
// i.e. Findings, or a new decision-relevant verification limitation) does.
//
// B0 integration contract §4: materiality is structured-fact inequality,
// never prose equality — a changed Verification enum ALONE (supported vs
// revised vs degraded) is a text-comparison outcome internal to one
// analysis's own draft/final judgment, not proof the operator-visible
// Observations/Unknowns changed, so it is deliberately excluded here
// (S3-04). A Stale flip is also excluded (S3-03: "Stale flips are not
// evidence") — a newer alert delivery arriving alone does not invalidate or
// re-validate a hypothesis.
func usefulAnalysisChanged(prior, current *model.OperatorBriefing) bool {
	if current == nil {
		return false
	}
	for _, a := range current.Analyses {
		if a.Summary == "" && a.Title == "" {
			continue
		}
		if findingStructurallyChanged(priorKnownFinding(prior, a.IncidentID), findingFactsOf(a)) {
			return true
		}
	}
	return false
}

// findAnalysis returns the prior committed analysis for incidentID, or nil
// when b is nil or carries none — never a name/index match, only identity.
func findAnalysis(b *model.OperatorBriefing, incidentID string) *model.IncidentAnalysis {
	if b == nil {
		return nil
	}
	for i := range b.Analyses {
		if b.Analyses[i].IncidentID == incidentID {
			return &b.Analyses[i]
		}
	}
	return nil
}

// analysisHypothesis is the same "likely cause" text notify/slack's
// briefingInterpretation selects — Summary when recorded, else Title —
// duplicated here (not exported from notify/slack, which depends on this
// package) so FindingFacts.Hypothesis matches what the operator actually
// sees.
func analysisHypothesis(a model.IncidentAnalysis) string {
	if a.Summary != "" {
		return a.Summary
	}
	return a.Title
}

// findingFactsOf converts one persisted IncidentAnalysis into the
// structured FindingFacts a MaterialCandidate carries (B0 integration
// contract §4) — Observations is exactly the recorded Findings; Unknowns is
// the recorded decision-relevant verification limitation/gap count, never
// an invented "cause unproven" boilerplate line.
func findingFactsOf(a model.IncidentAnalysis) *model.FindingFacts {
	f := &model.FindingFacts{
		IncidentID:          a.IncidentID,
		Hypothesis:          analysisHypothesis(a),
		Observations:        append([]string(nil), a.Findings...),
		AnalyzedAt:          a.AnalyzedAt,
		EvidenceFingerprint: a.EvidenceFingerprint,
	}
	f.Unknowns = verificationUnknowns(a.VerificationLimit, a.VerificationGaps)
	return f
}

// verificationUnknowns is the one shared rendering of a recorded
// verification limitation and gap count into FindingFacts.Unknowns, so an
// analysis-overview finding and an EndedWork completion state the same
// decision-relevant unknowns in the same words — never an invented "cause
// unproven" boilerplate line.
func verificationUnknowns(limit string, gaps int) []string {
	var out []string
	if limit != "" {
		out = append(out, limit)
	}
	if gaps > 0 {
		out = append(out, fmt.Sprintf("%d verification checks unavailable or invalid", gaps))
	}
	return out
}

// workNextStep is the actual recorded next step a candidate's reply may
// state: a real retry time when one is due, otherwise the status
// checkpoint, otherwise nothing — never a fabricated retry or ETA.
func workNextStep(b *model.OperatorBriefing) model.NextStepFacts {
	if b == nil {
		return model.NextStepFacts{}
	}
	if b.Work.RetryEligibleAt != nil {
		return model.NextStepFacts{Kind: model.NextStepRetryEligible, At: b.Work.RetryEligibleAt}
	}
	if b.Work.StatusCheckpointAt != nil {
		return model.NextStepFacts{Kind: model.NextStepStatusCheck, At: b.Work.StatusCheckpointAt}
	}
	return model.NextStepFacts{}
}

// stillFiringNames lists the recorded still-firing member names — the same
// identity/name pairs BriefingAlert.Name carries, never a Situation total.
func stillFiringNames(b *model.OperatorBriefing) []string {
	var out []string
	for _, alert := range b.Alerts {
		if alert.State == "firing" {
			out = append(out, alert.Name)
		}
	}
	return out
}

// membersChangedCandidate reports a material source change while the
// Situation stays Active (S4-06): a moved member set, a changed recorded
// scope, or a raised attention. Scope and urgency are carried explicitly
// because either can change while every alert keeps firing — slide 4's
// "scope-expanded" reply and an observe -> urgent escalation are real
// operator-visible changes that had no candidate at all, so they vanished
// once candidates became the eligibility source (R2 repair, lead review
// 2026-09-09). Only a POSITIVE change qualifies: a de-escalation and an
// unchanged scope stay quiet, and grouping still infers no common cause.
func membersChangedCandidate(a, b *model.OperatorBriefing, priorAttention, attention model.Attention) (model.MaterialCandidate, bool) {
	changed, cleared, firing := briefingAlertDelta(a, b)
	scopeChanged := a != nil && a.Scope != b.Scope
	urgencyIncreased := attentionRank(attention) > attentionRank(priorAttention)
	if !changed && !scopeChanged && !urgencyIncreased {
		return model.MaterialCandidate{}, false
	}
	facts := &model.MemberFacts{
		Cleared:     cleared,
		NowFiring:   firing,
		StillFiring: stillFiringNames(b),
		FiringCount: b.Firing,
		Total:       b.Total,
	}
	if scopeChanged {
		facts.PreviousScope, facts.Scope = a.Scope, b.Scope
	}
	if urgencyIncreased {
		facts.PreviousUrgency, facts.Urgency = string(priorAttention), string(attention)
	}
	return model.MaterialCandidate{Kind: model.CandidateMembersChanged, Members: facts, Next: workNextStep(b)}, true
}

// findingCandidates emits one useful_finding candidate per member Incident
// whose analysis structurally changed (S4-04) — findingStructurallyChanged
// against whatever this Incident's evidence was last known to be, wherever
// the PRIOR transition carried it, which is the same comparison the legacy
// reply gate and the completion path use, so no path can disagree about what
// counts as a new finding and none of them can mistake movement between the
// paths for new evidence (R2 repair, lead review round 4, 2026-09-09). An
// unchanged accepted result re-entering the three-item overview is a repeat
// of a reported result; a member delta that reorders the overview does not
// make old evidence new. An analysis that
// recorded no root cause is not a useful finding: its title is a name, not a
// causal hypothesis (lead decision D, round 2, 2026-09-09), and an accepted
// completion without a hypothesis is endedWorkCandidates' inconclusive
// completion instead, never both.
func findingCandidates(a, b *model.OperatorBriefing) []model.MaterialCandidate {
	if b == nil {
		return nil
	}
	var out []model.MaterialCandidate
	for _, an := range b.Analyses {
		if an.Summary == "" {
			continue
		}
		f := findingFactsOf(an)
		if findingStructurallyChanged(priorKnownFinding(a, an.IncidentID), f) {
			out = append(out, model.MaterialCandidate{Kind: model.CandidateUsefulFinding, Finding: candidateFinding(f), Next: workNextStep(b)})
		}
	}
	return out
}

// endedWorkCandidates derives the completion candidates per-incident
// provenance supports (S4-05, lead decision D, round 2, 2026-09-09): one
// inconclusive_completion for each member schedule that NEWLY ended — by
// stable incident/attempt/outcome identity against the prior committed
// EndedWork, never by aggregate phase alone — with an accepted completion
// that recorded no causal hypothesis, or with a typed exhaustion; plus one
// useful_finding for a newly accepted result that DID record a hypothesis
// but sits outside the top-three analysis overview findingCandidates
// already covers. Quiet by construction for: clean skips (pre- or
// post-claim), a schedule that ended with no attempt to attribute, an
// accepted result whose evidence could not be matched to its own attempt
// (unmatched evidence establishes neither a hypothesis nor its absence),
// stale-input and owner-terminal outcomes (never promoted as an accepted
// finding), a re-run whose retained observations and unknowns repeat what
// this Incident's evidence was already known to be (R2 repair, lead review
// rounds 3 and 4, 2026-09-09), a repeated reconciliation/reload of the same
// ended work, and any prior transition whose ended work is unknown (legacy
// replay), where only the aggregate exhaustion edge is reported and nothing
// is attributed to an incident — never retrospective phantom completions.
func endedWorkCandidates(a, b *model.OperatorBriefing) []model.MaterialCandidate {
	if b == nil {
		return nil
	}
	if a == nil || !a.Work.EndedWorkKnown || !b.Work.EndedWorkKnown {
		return legacyExhaustionCandidate(a, b)
	}
	prior := make(map[string]bool, len(a.Work.EndedWork))
	for _, o := range a.Work.EndedWork {
		prior[endedWorkKey(o)] = true
	}
	var out []model.MaterialCandidate
	for _, o := range b.Work.EndedWork {
		if prior[endedWorkKey(o)] || o.SkipReason != "" || o.AttemptID == "" || o.ResultCode == "" {
			continue
		}
		outcome := o
		outcome.Finding = nil
		if cand, ok := endedWorkCandidate(a, b, o, &outcome); ok {
			out = append(out, cand)
		}
	}
	return out
}

// endedWorkCandidate classifies one newly ended, attempt-bearing outcome —
// see endedWorkCandidates for the full rule set.
func endedWorkCandidate(a, b *model.OperatorBriefing, o model.IncidentWorkOutcome, outcome *model.IncidentWorkOutcome) (model.MaterialCandidate, bool) {
	if o.Phase == model.WorkPhaseSettled {
		return settledWorkCandidate(a, b, o, outcome)
	}
	if o.Phase != model.WorkPhaseExhausted {
		return model.MaterialCandidate{}, false
	}
	switch o.ResultCode {
	case "stale_membership", "stale_incident_input", "owner_terminal":
		return model.MaterialCandidate{}, false
	}
	// A typed failure retained its result code and completion time, not a
	// list of the checks it ran: the candidate states exactly that
	// (EvidenceKnown false, no observations) rather than borrowing another
	// incident's output.
	return model.MaterialCandidate{
		Kind:    model.CandidateInconclusiveCompletion,
		Finding: &model.FindingFacts{IncidentID: o.IncidentID, AnalyzedAt: o.CompletedAt},
		Outcome: outcome,
		Next:    workNextStep(b),
	}, true
}

// settledWorkCandidate classifies one settled, attempt-bearing outcome: a
// matched accepted result is either a useful finding or an inconclusive
// completion, and anything without matched success evidence is neither.
// Split out of endedWorkCandidate so each ended phase reads as one flat rule
// set rather than a nested one.
func settledWorkCandidate(a, b *model.OperatorBriefing, o model.IncidentWorkOutcome, outcome *model.IncidentWorkOutcome) (model.MaterialCandidate, bool) {
	if o.ResultCode != "success" || !o.EvidenceKnown || o.Finding == nil {
		return model.MaterialCandidate{}, false
	}
	if o.Finding.Hypothesis == "" {
		return model.MaterialCandidate{Kind: model.CandidateInconclusiveCompletion, Finding: candidateFinding(o.Finding), Outcome: outcome, Next: workNextStep(b)}, true
	}
	// A useful accepted result: never an inconclusive completion.
	// findingCandidates already reports it when it is in the analysis
	// overview; outside that bound it is reported here from its own matched
	// evidence so it is not silently dropped.
	if findAnalysis(b, o.IncidentID) != nil {
		return model.MaterialCandidate{}, false
	}
	// The overview bound decides which PATH reports a useful result, never
	// whether it is material: outside it the same structural rule applies
	// against whatever this Incident's evidence was last known to be (R2
	// repair, lead review rounds 3 and 4, 2026-09-09). A fresh attempt id, a
	// later completion time and a rephrased hypothesis over identical
	// retained checks are a repeat of a reported result, not a new finding.
	if !findingStructurallyChanged(priorKnownFinding(a, o.IncidentID), o.Finding) {
		return model.MaterialCandidate{}, false
	}
	return model.MaterialCandidate{Kind: model.CandidateUsefulFinding, Finding: candidateFinding(o.Finding), Outcome: outcome, Next: workNextStep(b)}, true
}

// priorKnownFinding is the structured evidence the PRIOR transition already
// committed for one Incident, wherever that transition carried it: its own
// matched completion evidence when the prior ended work held it, otherwise
// its entry in the prior analysis overview — so a result does not become
// "new" merely by moving between the two paths, in either direction. nil
// means nothing was known about this Incident before, and any recorded result
// is genuinely new.
func priorKnownFinding(a *model.OperatorBriefing, incidentID string) *model.FindingFacts {
	if a == nil {
		return nil
	}
	for _, o := range a.Work.EndedWork {
		if o.IncidentID == incidentID && o.EvidenceKnown && o.Finding != nil {
			return o.Finding
		}
	}
	if an := findAnalysis(a, incidentID); an != nil {
		return findingFactsOf(*an)
	}
	return nil
}

// findingStructurallyChanged is the ONE materiality comparison both reporting
// paths use (R2 repair, lead review round 4, 2026-09-09): the retained
// observations and the decision-relevant unknowns only. Hypothesis prose,
// attempt identity, judgment/completion time and the outcome enum are
// deliberately excluded — canonical slide 4 row 577, "Neither paraphrasing nor
// an evidence enum change earns a reply" (S3-04).
//
// Comparison provenance is separated from display truncation. When both sides
// recorded an EvidenceFingerprint, that fingerprint decides: it was taken from
// the full recorded evidence BEFORE the three-item overview bound and the
// six-item completion bound, so a genuine change past either bound is still a
// change and a mere change of display path is not. When either side carries
// none — a legacy projection, or a shape built outside the loader — provenance
// is UNKNOWN, never an empty result, and only what the two displays can prove
// counts as a difference.
func findingStructurallyChanged(old, f *model.FindingFacts) bool {
	if old == nil || f == nil {
		return true
	}
	if old.EvidenceFingerprint != "" && f.EvidenceFingerprint != "" {
		return old.EvidenceFingerprint != f.EvidenceFingerprint
	}
	return !sameDisplayedEvidence(old.Observations, f.Observations) || !sameDisplayedEvidence(old.Unknowns, f.Unknowns)
}

// sameDisplayedEvidence reports whether two recorded lists are the same
// evidence as far as DISPLAY bounds alone can prove, for the legacy case
// where at least one side carries no comparison fingerprint. A list can only
// hide entries where a bound actually cut it — the overview keeps three, a
// completion six — so a shorter list is complete as recorded and a difference
// in it is a real difference, while a list sitting exactly at one of those
// bounds proves nothing about what follows it. An absent list and an empty one
// are the same fact, so a persistence round trip is never a change.
func sameDisplayedEvidence(old, cur []string) bool {
	short, long := old, cur
	if len(long) < len(short) {
		short, long = long, short
	}
	if len(short) != len(long) && !displayBoundedLen(len(short)) {
		return false
	}
	for i := range short {
		if !sameDisplayedText(short[i], long[i]) {
			return false
		}
	}
	return true
}

// displayBoundedLen reports whether a list of n entries could have been cut
// by one of the two display bounds it may have passed through.
func displayBoundedLen(n int) bool {
	return n == model.AnalysisFindingsBound || n == model.CompletionObservationsBound
}

// sameDisplayedText compares two recorded texts under the same rule: equal
// once whitespace is normalized, or one is the other marked as cut.
// model.BoundIncidentAnalysis bounds an overview limitation to a hundred
// bytes and marks the cut with an ellipsis, while the completion path carries
// the same limitation whole; that difference is display, not evidence.
func sameDisplayedText(x, y string) bool {
	x, y = strings.Join(strings.Fields(x), " "), strings.Join(strings.Fields(y), " ")
	if x == y {
		return true
	}
	return markedAsCut(x, y) || markedAsCut(y, x)
}

func markedAsCut(short, long string) bool {
	cut, ok := strings.CutSuffix(short, "…")
	return ok && cut != "" && strings.HasPrefix(long, cut)
}

// candidateFinding is the FindingFacts a MaterialCandidate carries: the
// operator-visible facts, never the comparison fingerprint. Materiality is
// decided here in B3 from the committed projections; B4 renders and B5 owns
// delivery history, and neither may key anything on comparison provenance.
func candidateFinding(f *model.FindingFacts) *model.FindingFacts {
	cp := copyFindingFacts(f)
	if cp != nil {
		cp.EvidenceFingerprint = ""
	}
	return cp
}

// endedWorkKey is the stable identity two committed EndedWork records are
// compared by: the incident, the attempt that ended it, and the outcome —
// never phase alone, so a second completion for the same incident is a new
// event and a reload of the same one is not.
func endedWorkKey(o model.IncidentWorkOutcome) string {
	return o.IncidentID + "\x00" + o.AttemptID + "\x00" + string(o.Phase) + "\x00" + o.ResultCode + "\x00" + o.SkipReason
}

func copyFindingFacts(f *model.FindingFacts) *model.FindingFacts {
	if f == nil {
		return nil
	}
	cp := *f
	cp.Observations = append([]string(nil), f.Observations...)
	cp.Unknowns = append([]string(nil), f.Unknowns...)
	return &cp
}

// legacyExhaustionCandidate is the pre-provenance rule kept for a prior
// transition whose ended work is unknown: fires once when the aggregate
// disposition newly reaches WorkPhaseExhausted, carrying no Finding and no
// Outcome because the aggregate names no member schedule and another
// incident's analysis is not evidence of what the failed attempt checked
// (R1 repair, lead review 2026-09-09).
func legacyExhaustionCandidate(a, b *model.OperatorBriefing) []model.MaterialCandidate {
	if b.Work.Phase != model.WorkPhaseExhausted {
		return nil
	}
	if a != nil && a.Work.Phase == model.WorkPhaseExhausted {
		return nil
	}
	return []model.MaterialCandidate{{Kind: model.CandidateInconclusiveCompletion, Next: model.NextStepFacts{Kind: model.NextStepWorkEnded}}}
}

// waitReasonCode is the recorded obstacle code a contract carries, or ""
// when it names none — never a substitute code from elsewhere.
func waitReasonCode(r *model.WaitReason) string {
	if r == nil {
		return ""
	}
	return string(*r)
}

// abilityChangedCandidates reports every recorded investigation-ability
// change this cycle, as two INDEPENDENT facts that may both occur at once
// (lead decision C, round 2, 2026-09-09 — a single precedence switch dropped
// one through the other):
//
//   - the contract obstacle: newly blocked, blocked under a DIFFERENT
//     recorded reason, or newly cleared — never a repeated, unchanged blocked
//     cycle. The code always identifies the limitation actually reported:
//     the newly recorded obstacle when blocking, and the obstacle reported
//     BEFORE when clearing it, so B5 §5 can match it against
//     CommunicatedLimitationCodes (R4 repair, lead review 2026-09-09);
//   - the coverage gap: the recorded unavailable-investigation aggregate
//     rising is a new limitation under the stable code
//     LimitationInvestigationUnavailable, and that aggregate actually
//     ending (positive -> zero) is its clearance. A partial fall claims no
//     clearance while some unavailable work remains, and member removal is
//     not proof a removed incident resumed — the code names the recorded
//     aggregate, never a particular backend.
//
// Next carries the actual recorded next step, so a resumed investigation
// states its real checkpoint instead of nothing; an obstacle clearing does
// not itself prove execution resumed.
func abilityChangedCandidates(a, b *model.OperatorBriefing, prior, current model.ActionContract) []model.MaterialCandidate {
	limitation := func(code string, cleared bool) model.MaterialCandidate {
		return model.MaterialCandidate{
			Kind:       model.CandidateAbilityChanged,
			Limitation: &model.LimitationFacts{Code: code, Cleared: cleared},
			Next:       workNextStep(b),
		}
	}
	var out []model.MaterialCandidate
	priorBlocked, blocked := operatorBlocked(prior), operatorBlocked(current)
	priorCode, code := waitReasonCode(prior.WaitReason), waitReasonCode(current.WaitReason)
	switch {
	case blocked && !priorBlocked:
		out = append(out, limitation(code, false))
	case blocked && priorBlocked && code != priorCode:
		out = append(out, limitation(code, false))
	case priorBlocked && !blocked:
		out = append(out, limitation(priorCode, true))
	}
	if a != nil && b != nil {
		switch {
		case b.Unavailable > a.Unavailable:
			out = append(out, limitation(model.LimitationInvestigationUnavailable, false))
		case a.Unavailable > 0 && b.Unavailable == 0:
			out = append(out, limitation(model.LimitationInvestigationUnavailable, true))
		}
	}
	return out
}

// actionChangedCandidate distinguishes a recorded operator Action newly
// introduced, revised or withdrawn (S4-09) — never a guessed impact or
// synthetic ownership; withdrawal correction against delivered history is
// B5's job (§5), this only reports the structural fact.
func actionChangedCandidate(prior, current *model.OperatorAction) (model.MaterialCandidate, bool) {
	switch {
	case prior == nil && current != nil:
		return model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Introduced: true, Action: *current}}, true
	case prior != nil && current == nil:
		return model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Withdrawn: true, Action: *prior}}, true
	case prior != nil && current != nil && *prior != *current:
		return model.MaterialCandidate{Kind: model.CandidateActionChanged, Action: &model.ActionFacts{Revised: true, Action: *current}}, true
	default:
		return model.MaterialCandidate{}, false
	}
}

// MaterialCandidates derives the structured material-evidence facts a
// committed Transition carries (B0 integration contract §4), replacing
// buildOperatorDelta's own booleans as the eligibility source for B5's
// ReplyEligible. Pure: never queries delivery history, never schedules
// work, never calls an LLM. Returns nil for the very first transition
// (prior == nil) — there is no delta without a baseline, and the first root
// conveys itself without an echoed reply.
func MaterialCandidates(prior *model.Transition, tr model.Transition) []model.MaterialCandidate {
	b := tr.Projection.Briefing
	if prior == nil || b == nil {
		return nil
	}
	a := prior.Projection.Briefing
	priorLifecycle := prior.Lifecycle
	priorExecutionStarted := a != nil && a.Work.ExecutionStarted

	var out []model.MaterialCandidate

	if tr.Lifecycle.Terminal() && priorLifecycle != tr.Lifecycle {
		next := model.NextStepFacts{Kind: model.NextStepWorkEnded}
		if tr.Lifecycle == model.LifecycleClosedUnknown {
			next.Kind = model.NextStepTrackingEnded
		}
		out = append(out, model.MaterialCandidate{Kind: model.CandidateTerminalEnd, Next: next})
	}

	switch {
	case tr.Lifecycle == model.LifecycleRecoveryPending && priorLifecycle != model.LifecycleRecoveryPending:
		_, cleared, _ := briefingAlertDelta(a, b)
		out = append(out, model.MaterialCandidate{
			Kind:    model.CandidateAllClear,
			Members: &model.MemberFacts{Cleared: cleared, FiringCount: b.Firing, Total: b.Total},
			Next:    model.NextStepFacts{Kind: model.NextStepGraceDeadline, At: b.Work.SourceGraceUntil},
		})
	case priorLifecycle == model.LifecycleRecoveryPending && tr.Lifecycle == model.LifecycleActive:
		_, _, firing := briefingAlertDelta(a, b)
		out = append(out, model.MaterialCandidate{
			Kind:    model.CandidateRefire,
			Members: &model.MemberFacts{NowFiring: firing, StillFiring: stillFiringNames(b), FiringCount: b.Firing, Total: b.Total},
			Next:    workNextStep(b),
		})
	case tr.Lifecycle == model.LifecycleActive && priorLifecycle == model.LifecycleActive:
		if cand, ok := membersChangedCandidate(a, b, prior.Attention, tr.Attention); ok {
			out = append(out, cand)
		}
	}

	out = append(out, findingCandidates(a, b)...)
	out = append(out, endedWorkCandidates(a, b)...)
	out = append(out, abilityChangedCandidates(a, b, prior.ActionContract, tr.ActionContract)...)

	if cand, ok := actionChangedCandidate(prior.ActionContract.OperatorActionRequired, tr.ActionContract.OperatorActionRequired); ok {
		out = append(out, cand)
	}

	if b.Work.ExecutionStarted && !priorExecutionStarted {
		// FiringCount is the actual number of frozen investigation inputs,
		// never the bounded display-name list length and never
		// Situation.Total — slide 4's "investigating [recorded count] alerts"
		// states a real count or none at all (R3 repair, lead review
		// 2026-09-09). CountKnown qualifies it: a projection that cannot
		// prove its union was complete reports an unknown count (0), which
		// B4/B5 must not render as a number (lead decision B, round 2).
		count := investigatedInputCount(b.Work)
		out = append(out, model.MaterialCandidate{
			Kind:    model.CandidateFirstExecutionAssurance,
			Members: &model.MemberFacts{NowFiring: b.Work.InvestigatedNames, FiringCount: count, CountKnown: count > 0, Total: b.Total},
			Next:    workNextStep(b),
		})
	}

	return out
}

func operatorBlocked(c model.ActionContract) bool {
	return c.AlertINTStatus != nil && (*c.AlertINTStatus == model.AlertINTStatusBlocked || *c.AlertINTStatus == model.AlertINTStatusExhausted)
}

func buildOperatorDelta(prior *model.Transition, tr model.Transition) *model.OperatorDelta {
	b := tr.Projection.Briefing
	if b == nil {
		return nil
	}
	d := &model.OperatorDelta{}
	if prior == nil {
		return d
	}
	a := prior.Projection.Briefing
	for _, analysis := range b.Analyses {
		if usefulAnalysisChanged(a, &model.OperatorBriefing{Analyses: []model.IncidentAnalysis{analysis}}) {
			d.Analyses = append(d.Analyses, analysis)
		}
	}
	if a != nil {
		d.PreviousFiring, d.PreviousTotal = a.Firing, a.Total
		d.StateChanged = a.Firing != b.Firing || a.Total != b.Total || a.Resolved != b.Resolved || a.Unknown != b.Unknown
		d.ScopeChanged = a.Scope != b.Scope
		if d.ScopeChanged {
			d.PreviousScope = a.Scope
		}
		d.SymptomsChanged = !reflect.DeepEqual(a.Symptoms, b.Symptoms)
		if d.SymptomsChanged {
			d.PreviousSymptoms = append([]string(nil), a.Symptoms...)
		}
		d.AnalysisFailed = b.Failed > a.Failed
		changed, cleared, firing := briefingAlertDelta(a, b)
		d.StateChanged = d.StateChanged || changed
		d.ClearedAlerts, d.NewFiringAlerts = cleared, firing
	}
	d.AttentionIncreased = attentionRank(tr.Attention) > attentionRank(prior.Attention)
	d.HumanRequestChanged = derefOperatorAction(tr.ActionContract.OperatorActionRequired) != derefOperatorAction(prior.ActionContract.OperatorActionRequired)
	d.AbilityLost = operatorBlocked(tr.ActionContract) && !operatorBlocked(prior.ActionContract)
	if a != nil && b.Unavailable > a.Unavailable {
		d.AbilityLost = true
	}
	d.Candidates = MaterialCandidates(prior, tr)
	return d
}

// Match selected stable identities, never names or disappearing metadata.
// A dropped member or an old wire projection cannot establish a clearance.
func briefingAlertDelta(prior, current *model.OperatorBriefing) (changed bool, cleared, firing []string) {
	if prior == nil || current == nil || len(prior.Alerts) == 0 {
		return false, nil, nil
	}
	old := make(map[string]model.BriefingAlert, len(prior.Alerts))
	for _, a := range prior.Alerts {
		old[a.ID] = a
	}
	for _, a := range current.Alerts {
		before, found := old[a.ID]
		if a.ID == "" || (!found && prior.AlertsOmitted > 0) {
			continue
		}
		if found && before.State != a.State {
			changed = true
		}
		if found && before.State == "firing" && a.State == "resolved" {
			cleared = append(cleared, a.Name)
		}
		if a.State == "firing" && (!found || before.State != "firing") {
			changed = true
			firing = append(firing, a.Name)
		}
	}
	sort.Strings(cleared)
	sort.Strings(firing)
	return changed, cleared, firing
}

// Publication is a separate decision from durable audit materiality. Job
// starts/completions, renewals and scheduling remain in the ledger only.
func operatorReplyWarranted(prior *model.Transition, tr model.Transition) bool {
	if tr.Reason == model.ReasonOperatorArtifactRecorded {
		return strings.TrimSpace(tr.Journal.Headline+tr.Journal.Detail) != ""
	}
	if prior == nil {
		return false
	}
	if tr.Lifecycle != prior.Lifecycle {
		return true
	}
	if attentionRank(tr.Attention) > attentionRank(prior.Attention) {
		return true
	}
	if derefOperatorAction(tr.ActionContract.OperatorActionRequired) != derefOperatorAction(prior.ActionContract.OperatorActionRequired) {
		return true
	}
	if operatorBlocked(tr.ActionContract) && !operatorBlocked(prior.ActionContract) {
		return true
	}
	a, b := prior.Projection.Briefing, tr.Projection.Briefing
	if changed, _, _ := briefingAlertDelta(a, b); changed {
		return true
	}
	if usefulAnalysisChanged(a, b) {
		return true
	}
	if a != nil && b != nil {
		return a.Scope != b.Scope || !reflect.DeepEqual(a.Symptoms, b.Symptoms) || a.Firing != b.Firing || a.Resolved != b.Resolved || a.Unknown != b.Unknown || a.Total != b.Total || b.Failed > a.Failed || b.Unavailable > a.Unavailable
	}
	return false
}
