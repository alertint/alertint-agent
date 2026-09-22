// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import "context"

const (
	// ParkedReasonBudget is independent of material input and dependency recovery.
	// A persisted RetryAt permits another guarded admission attempt at that
	// time; nil requires manual intervention and never auto-recovers.
	ParkedReasonBudget       = "budget_deferred"
	BudgetDeferralErrorClass = "budget_deferred"
)

func (c *Controller) commitBudgetDeferred(ctx context.Context, claim Claim, basis historyBasis, base ControllerCommit, state ControllerState, retryEpoch, workAttempt int) error {
	base.LastErrorClass = stringPtrOf(BudgetDeferralErrorClass)
	state.SemanticRetry = SemanticRetryPhaseBlocked
	state.SemanticRetryAt = nil
	if base.RetryAt != nil {
		state.SemanticRetry = SemanticRetryPhaseDue
		state.SemanticRetryAt = base.RetryAt
	}
	base.Assessment, base.Attempt, base.Coverage = c.fallbackOrPreserve(claim.Situation.ID, basis.Snap, basis.In, state, retryEpoch, workAttempt, basis.Now)
	c.finalizeCheckpoint(&base, basis.Now)
	return c.commit(ctx, claim, basis, base)
}
