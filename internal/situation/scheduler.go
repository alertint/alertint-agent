// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// LeaseExtender is the narrow durable boundary needed by the scheduler.
type LeaseExtender interface {
	ExtendSituationLease(context.Context, string, string, int64, time.Time, time.Duration) error
}

// RunWithLeaseHeartbeat runs one reconciliation while extending ownership at
// the configured interval. A failed extension cancels the work context before
// the reconciler may start another context-aware operation.
func RunWithLeaseHeartbeat(ctx context.Context, extender LeaseExtender, situationID, owner string, claimToken int64, interval, lease time.Duration, reconcile func(context.Context) error) error {
	if extender == nil || reconcile == nil || interval <= 0 || lease <= interval || situationID == "" || owner == "" || claimToken <= 0 {
		return errors.New("situation: heartbeat requires ownership, positive interval, and longer lease")
	}
	workCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	heartbeatErr := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case now := <-ticker.C:
				if err := extender.ExtendSituationLease(workCtx, situationID, owner, claimToken, now.UTC(), lease); err != nil {
					wrapped := fmt.Errorf("situation: lease heartbeat: %w", err)
					heartbeatErr <- wrapped
					cancel(wrapped)
					return
				}
			}
		}
	}()

	reconcileErr := reconcile(workCtx)
	cancel(context.Canceled)
	<-done
	select {
	case err := <-heartbeatErr:
		return err
	default:
	}
	return reconcileErr
}

// WorkPriority is ordered from most urgent to ordinary observation work.
type WorkPriority int

const (
	PriorityCritical WorkPriority = iota
	PriorityPublishedMaterial
	PriorityNewSymptom
	PriorityRecoveryBoundary
	PriorityObserve
)

// PrioritySignals are deterministic scheduler inputs, not model judgments.
type PrioritySignals struct {
	DeterministicUrgent     bool
	PublishedMaterialChange bool
	NewSymptom              bool
	EnvelopeViolation       bool
	RecoveryBoundary        bool
	DeadlineBoundary        bool
}

// IsPublishedMaterialReason reports whether a durable due reason represents a
// new externally visible fact, rather than a timer, retry, or reassessment.
func IsPublishedMaterialReason(reason model.DueReason) bool {
	switch reason {
	case model.DueIncidentCreated,
		model.DueMembershipChanged,
		model.DueNewSymptom,
		model.DueAlertResolved,
		model.DueAlertRefired,
		model.DueConnectorHealthChanged,
		model.DueOperatorJudgment,
		model.DueEnvelopeChanged:
		return true
	default:
		return false
	}
}

// PriorityFor applies the fixed priority bands and promotes waiting work by
// one band for each complete aging interval.
func PriorityFor(signals PrioritySignals, waited, agingInterval time.Duration) WorkPriority {
	base := PriorityObserve
	switch {
	case signals.DeterministicUrgent:
		base = PriorityCritical
	case signals.PublishedMaterialChange:
		base = PriorityPublishedMaterial
	case signals.NewSymptom || signals.EnvelopeViolation:
		base = PriorityNewSymptom
	case signals.RecoveryBoundary || signals.DeadlineBoundary:
		base = PriorityRecoveryBoundary
	}
	if agingInterval <= 0 || waited <= 0 {
		return base
	}
	promotions := int(waited / agingInterval)
	aged := int(base) - promotions
	if aged < int(PriorityCritical) {
		aged = int(PriorityCritical)
	}
	return WorkPriority(aged)
}

var dueReasonOrder = map[model.DueReason]int{
	model.DueIncidentCreated:        0,
	model.DueMembershipChanged:      1,
	model.DueNewSymptom:             2,
	model.DueAlertResolved:          3,
	model.DueAlertRefired:           4,
	model.DueDurationMilestone:      5,
	model.DueConnectorHealthChanged: 6,
	model.DueSemanticProfileChanged: 7,
	model.DueOperatorJudgment:       8,
	model.DueEnvelopeChanged:        9,
	model.DueEnvelopeBoundary:       10,
	model.DueJudgmentBoundary:       11,
	model.DueManualReassessment:     12,
	model.DueRecoveryGraceExpired:   13,
	model.DueObservationDeadline:    14,
	model.DueRetry:                  15,
	model.DueUpgradeReconstruction:  16,
}

// MergeDueReasons returns a deterministic set without mutating existing.
func MergeDueReasons(existing []model.DueReason, additions ...model.DueReason) []model.DueReason {
	set := make(map[model.DueReason]struct{}, len(existing)+len(additions))
	for _, reason := range existing {
		set[reason] = struct{}{}
	}
	for _, reason := range additions {
		set[reason] = struct{}{}
	}
	merged := make([]model.DueReason, 0, len(set))
	for reason := range set {
		merged = append(merged, reason)
	}
	sort.Slice(merged, func(i, j int) bool {
		left, leftOK := dueReasonOrder[merged[i]]
		right, rightOK := dueReasonOrder[merged[j]]
		if leftOK != rightOK {
			return leftOK
		}
		if left != right {
			return left < right
		}
		return merged[i] < merged[j]
	})
	return merged
}

// EarlierAssessmentAt moves a schedule earlier, never later. Zero means the
// schedule has not yet been set.
func EarlierAssessmentAt(current, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return current.UTC()
	}
	if current.IsZero() || candidate.Before(current) {
		return candidate.UTC()
	}
	return current.UTC()
}
