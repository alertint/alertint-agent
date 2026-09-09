// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-3 repair regressions (lead review round 2, 2026-09-09, R2).
//
// Delivered and owed replies were folded separately and their positive
// sets unioned. A union cannot express a correction that is queued behind
// the fact it corrects: a delivered obstacle plus an owed clearance still
// reads as "on screen", so a genuine recurrence is suppressed as a
// duplicate and the operator's last word on the subject is the clearance.
//
// The standing state is one ordered fold over both sets: what the operator
// will be looking at once everything owed has landed.
// ----------------------------------------------------------------------

// rd3Limitation is one recorded coverage-limitation candidate.
func rd3Limitation(cleared bool) model.MaterialCandidate {
	return model.MaterialCandidate{Kind: model.CandidateAbilityChanged,
		Limitation: &model.LimitationFacts{Code: model.LimitationInvestigationUnavailable, Cleared: cleared}}
}

func rd3Action(withdrawn bool) model.MaterialCandidate {
	action := model.OperatorActionInvestigateSituation
	return model.MaterialCandidate{Kind: model.CandidateActionChanged,
		Action: &model.ActionFacts{Action: action, Withdrawn: withdrawn, Introduced: !withdrawn}}
}

// R2/1: the obstacle was delivered and its clearance is still queued. The
// operator will end up looking at a cleared limitation, so the obstacle
// appearing AGAIN is news, not a repeat.
func TestReplyEligibleRecurrenceBehindAnOwedClearanceIsReported(t *testing.T) {
	h := DeliveredHistory{
		CommunicatedLimitationCodes: []string{model.LimitationInvestigationUnavailable},
		ProjectedLimitationCodes:    nil,
	}
	got := ReplyEligible([]model.MaterialCandidate{rd3Limitation(false)}, h, true)
	if len(got) != 1 {
		t.Fatalf("a recurrence behind an owed clearance was dropped as a duplicate: %+v", got)
	}
}

// R2/2, negative control: while the obstacle is still STANDING — delivered
// with nothing queued to clear it — repeating it is a duplicate.
func TestReplyEligibleStandingObstacleStaysQuiet(t *testing.T) {
	h := DeliveredHistory{
		CommunicatedLimitationCodes: []string{model.LimitationInvestigationUnavailable},
		ProjectedLimitationCodes:    []string{model.LimitationInvestigationUnavailable},
	}
	if got := ReplyEligible([]model.MaterialCandidate{rd3Limitation(false)}, h, true); len(got) != 0 {
		t.Fatalf("an unchanged standing limitation was announced again: %+v", got)
	}
}

// R2/3: a clearance follows the STANDING obstacle, including one the
// operator has not seen yet because its reply is still queued.
func TestReplyEligibleClearanceFollowsTheStandingObstacle(t *testing.T) {
	owed := DeliveredHistory{ProjectedLimitationCodes: []string{model.LimitationInvestigationUnavailable}}
	if got := ReplyEligible([]model.MaterialCandidate{rd3Limitation(true)}, owed, true); len(got) != 1 {
		t.Fatalf("the correction for an owed obstacle was dropped: %+v", got)
	}
	none := DeliveredHistory{}
	if got := ReplyEligible([]model.MaterialCandidate{rd3Limitation(true)}, none, true); len(got) != 0 {
		t.Fatalf("a clearance for an obstacle nobody was ever owed still posted: %+v", got)
	}
}

// R2/4, the action boundary the same representation change decides: a
// delivered request whose withdrawal is already queued leaves nothing
// standing, so a second withdrawal corrects nothing — while a request that
// is still standing keeps its withdrawal.
func TestReplyEligibleWithdrawalFollowsTheStandingRequest(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	withdrawn := DeliveredHistory{CommunicatedAction: &action, ProjectedAction: nil}
	if got := ReplyEligible([]model.MaterialCandidate{rd3Action(true)}, withdrawn, true); len(got) != 0 {
		t.Fatalf("a withdrawal was planned for a request already being withdrawn: %+v", got)
	}
	standing := DeliveredHistory{CommunicatedAction: &action, ProjectedAction: &action}
	if got := ReplyEligible([]model.MaterialCandidate{rd3Action(true)}, standing, true); len(got) != 1 {
		t.Fatalf("the withdrawal of a standing request was dropped: %+v", got)
	}
	// A request owed but never delivered is still standing for this
	// purpose: its withdrawal must survive to correct it.
	owedOnly := DeliveredHistory{ProjectedAction: &action}
	if got := ReplyEligible([]model.MaterialCandidate{rd3Action(true)}, owedOnly, true); len(got) != 1 {
		t.Fatalf("the withdrawal of an owed request was dropped: %+v", got)
	}
}

// R2/5: a NEW request is never a duplicate — reintroduction after a
// withdrawal keeps working whatever the history says.
func TestReplyEligibleReintroducedRequestIsAlwaysReported(t *testing.T) {
	action := model.OperatorActionInvestigateSituation
	h := DeliveredHistory{CommunicatedAction: &action, ProjectedAction: nil}
	if got := ReplyEligible([]model.MaterialCandidate{rd3Action(false)}, h, true); len(got) != 1 {
		t.Fatalf("a newly required operator action was dropped: %+v", got)
	}
}
