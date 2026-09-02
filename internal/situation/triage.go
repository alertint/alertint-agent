// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 6: DecideTriage — the pure B+ Acute Triage gate decision (spec.md
// "B+ Acute Triage gate"). It is pure: no I/O, no clock read beyond the
// explicit now parameter. Task 8's CommitController is the only production
// caller; there is no independent controller-decision transaction. See
// controller.go's TriageDecision doc comment for the persisted shape.
// ----------------------------------------------------------------------

// The closed Decision values a TriageDecision may carry.
const (
	TriageDecisionRequest = "request"
	TriageDecisionSkip    = "skip"
)

// Closed DecisionReason codes. Every branch DecideTriage can take is
// represented so the persisted decision_reason is always a stable,
// grep-able code, never free text.
// Request reasons: every one of these proves Triage was NOT proven safe to
// skip, per spec's own list of things that "never prove that Triage has no
// value" — a new Incident, an unchanged Alert name, below-floor severity, or
// raw confidence.
const (
	DecisionReasonNoTrustworthyAssessment  = "no_trustworthy_assessment"
	DecisionReasonAssessmentNotTrustworthy = "assessment_not_trustworthy"
	DecisionReasonMaterialFactHashChanged  = "material_fact_hash_changed"
	DecisionReasonIncidentNotCovered       = "incident_not_covered_by_assessment"
	DecisionReasonMembershipDigestChanged  = "membership_digest_changed"
	DecisionReasonIncidentInputChanged     = "incident_input_digest_changed"
	// DecisionReasonMembershipOrInputRefresh is the "before dispatch, a
	// changed membership digest refreshes the request against the new
	// digest" case: an already-decided pending/backoff row whose recorded
	// digests no longer match current membership/Incident input gets a new
	// decision — always "request" (a refresh can never newly discover a
	// skip; that judgment already passed on this Incident once).
	DecisionReasonMembershipOrInputRefresh = "membership_or_input_refresh"

	// DecisionReasonCleanSkip is the only Decision=skip reason: one
	// trustworthy Assessment exactly covers the unchanged material fact
	// hash and current membership/Incident-input digests.
	DecisionReasonCleanSkip = "clean_skip_unchanged_coverage"
)

// needsTriageDecision reports whether inc requires a fresh DecideTriage
// judgment against currentMembership/currentInputDigest, and whether that
// judgment is a refresh of an already-"request"-decided row (pending/
// backoff) rather than a first judgment from awaiting_decision.
// in_flight/skipped/exhausted Incidents never need a new decision here —
// in_flight finishes against the digests it already claimed (spec:
// "Membership changes"); skipped/exhausted are terminal.
func needsTriageDecision(inc IncidentState, currentMembership, currentInputDigest string) (needs, refresh bool) {
	switch inc.Triage.Phase {
	case "awaiting_decision":
		return true, false
	case "pending", "backoff":
		if inc.Triage.MembershipDigest == nil || *inc.Triage.MembershipDigest != currentMembership ||
			inc.Triage.IncidentInputDigest == nil || *inc.Triage.IncidentInputDigest != currentInputDigest {
			return true, true
		}
		return false, false
	default:
		return false, false
	}
}

// findIncidentCoverage returns the coverage tuple for incidentID within cov,
// if present.
func findIncidentCoverage(cov []model.IncidentCoverage, incidentID string) (model.IncidentCoverage, bool) {
	for _, c := range cov {
		if c.IncidentID == incidentID {
			return c, true
		}
	}
	return model.IncidentCoverage{}, false
}

// decideOne judges one Incident against snap/in's current digests. refresh
// forces Decision=request unconditionally (a refresh never newly discovers a
// skip — see needsTriageDecision's doc comment); otherwise skip requires a
// trustworthy current Assessment whose own material fact hash and per-
// Incident coverage tuple exactly match the current snapshot. Deliberately
// never reads Attention, EligibleReasons, or any urgency signal: spec.md is
// explicit that "new Incident identity, unchanged Alert name, source
// severity below a deterministic urgent floor, or raw model confidence
// never proves that Triage has no value" — this function has no way to let
// urgency (or its absence) shortcut the coverage check even if it wanted to,
// because urgency never reaches its signature. Acute Triage's decision is
// therefore never blocked or bypassed by whatever the deterministic urgent
// floor happens to be doing elsewhere in the controller cycle.
func decideOne(inc IncidentState, currentMembership, currentInputDigest string, snap Snapshot, in SnapshotInput, refresh bool) (decision, reason string, coveredAssessmentID *string) {
	if refresh {
		return TriageDecisionRequest, DecisionReasonMembershipOrInputRefresh, nil
	}

	prior := in.CurrentAssessment
	if prior == nil {
		return TriageDecisionRequest, DecisionReasonNoTrustworthyAssessment, nil
	}
	if _, ok := trustworthy(*prior); !ok {
		return TriageDecisionRequest, DecisionReasonAssessmentNotTrustworthy, nil
	}
	if prior.MaterialFactHash != snap.MaterialFactHash {
		return TriageDecisionRequest, DecisionReasonMaterialFactHashChanged, nil
	}
	cov, found := findIncidentCoverage(prior.Coverage, inc.ID)
	if !found {
		return TriageDecisionRequest, DecisionReasonIncidentNotCovered, nil
	}
	if cov.MembershipDigest != currentMembership {
		return TriageDecisionRequest, DecisionReasonMembershipDigestChanged, nil
	}
	if cov.IncidentInputDigest != currentInputDigest {
		return TriageDecisionRequest, DecisionReasonIncidentInputChanged, nil
	}

	id := prior.ID
	return TriageDecisionSkip, DecisionReasonCleanSkip, &id
}

// DecideTriage is the pure B+ Acute Triage gate: it makes one versioned
// request/skip decision per current membership and Incident-input digest
// pair for every member Incident of snap/in that currently needs one — a
// fresh awaiting_decision judgment, or a refresh of an already-"request"-
// decided pending/backoff row whose recorded digests have gone stale. It
// touches no database; Task 8's CommitController persists the result via
// the unexported applyTriageDecisionsTx (internal/store/triage_controller.go)
// inside the same fenced transaction that commits the Assessment sharing
// this decision round.
//
// Every returned TriageDecision carries its own basis: SituationID/
// SituationInputVersion pin the Situation input version the judgment was
// made against, MaterialFactHash is snap's own current material fact hash,
// MembershipDigest/IncidentInputDigest are the CURRENT (not stale) per-
// Incident digests, and CoveredAssessmentID is set only for Decision=skip
// (the trustworthy Assessment's own id).
func DecideTriage(snap Snapshot, in SnapshotInput, now time.Time) []TriageDecision {
	var out []TriageDecision
	for _, inc := range snap.Incidents {
		membership := MembershipDigest(inc.ID, in.Deliveries)
		inputDigest := IncidentInputDigest(inc.ID, inc.GroupKey, in.Deliveries)

		needs, refresh := needsTriageDecision(inc, membership, inputDigest)
		if !needs {
			continue
		}

		decision, reason, coveredID := decideOne(inc, membership, inputDigest, snap, in, refresh)
		out = append(out, TriageDecision{
			IncidentID:            inc.ID,
			Decision:              decision,
			DecisionReason:        reason,
			SituationID:           snap.SituationID,
			SituationInputVersion: snap.InputVersion,
			CoveredAssessmentID:   coveredID,
			MaterialFactHash:      snap.MaterialFactHash,
			MembershipDigest:      membership,
			IncidentInputDigest:   inputDigest,
			DecidedAt:             now,
		})
	}
	return out
}
