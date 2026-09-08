// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
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
	b := &model.OperatorBriefing{Historical: lifecycle != model.LifecycleActive}
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
		alerts = append(alerts, newBriefingAlert(id, alertState, latest.Labels))
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
	return briefingAlertCandidate{alert: model.BriefingAlert{ID: id, Name: name, State: state}, context: strings.Join(context, " · ")}
}

func selectBriefingAlerts(candidates []briefingAlertCandidate) ([]model.BriefingAlert, int) {
	names := make(map[string]int, len(candidates))
	for _, c := range candidates {
		names[c.alert.Name]++
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].alert.ID < candidates[j].alert.ID })
	var alerts []model.BriefingAlert
	for i, c := range candidates {
		if i == 8 {
			return alerts, len(candidates) - 8
		}
		if names[c.alert.Name] > 1 && c.context != "" {
			c.alert.Name += " (" + c.context + ")"
		}
		c.alert.Name = briefingLabel(c.alert.Name, 240)
		alerts = append(alerts, c.alert)
	}
	return alerts, 0
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

// Only the current committed work contract can select a retry timestamp.
// NextUpdateAt is a status checkpoint, not proof that work is due then.
func committedOperatorBriefing(in SnapshotInput, commit ControllerCommit) *model.OperatorBriefing {
	in = committedBriefingInput(in, commit.TriageDecisions)
	b := BuildOperatorBriefing(in, commit.Lifecycle)
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

// Overlay only the work phases this commit will persist, on a presentation
// copy. The coherent input and snapshot remain the original assessment basis.
func committedBriefingInput(in SnapshotInput, decisions []TriageDecision) SnapshotInput {
	in.Incidents = append([]IncidentState(nil), in.Incidents...)
	for i := range in.Incidents {
		// A refresh request on pending/backoff work does not change its
		// persisted phase or due time. Only awaiting_decision advances here.
		if in.Incidents[i].Triage.Phase != "awaiting_decision" {
			continue
		}
		for _, d := range decisions {
			if d.IncidentID != in.Incidents[i].ID {
				continue
			}
			switch d.Decision {
			case TriageDecisionSkip:
				in.Incidents[i].Triage.Phase = "skipped"
			case TriageDecisionRequest:
				in.Incidents[i].Triage.Phase = "pending"
			}
		}
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
	return canonicalDigest(a) != canonicalDigest(b)
}

// A repeated judgment's clock or paraphrased cause does not establish new
// evidence. A first analysis, changed findings or verification does.
func usefulAnalysisChanged(prior, current *model.OperatorBriefing) bool {
	if current == nil {
		return false
	}
	for _, a := range current.Analyses {
		if a.Summary == "" && a.Title == "" {
			continue
		}
		var old *model.IncidentAnalysis
		if prior != nil {
			for i := range prior.Analyses {
				if prior.Analyses[i].IncidentID == a.IncidentID {
					old = &prior.Analyses[i]
					break
				}
			}
		}
		if old == nil || !reflect.DeepEqual(old.Findings, a.Findings) || old.Verification != a.Verification || old.VerificationLimit != a.VerificationLimit || old.VerificationGaps != a.VerificationGaps || (old.Stale && !a.Stale) {
			return true
		}
	}
	return false
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
