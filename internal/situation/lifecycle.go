// SPDX-License-Identifier: FSL-1.1-ALv2

// Package situation implements deterministic Situation lifecycle and
// scheduling rules. It performs no outbound or operated-system writes.
package situation

import (
	"errors"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Event is a controller-owned lifecycle observation.
type Event string

const (
	EventRecoveryObserved      Event = "recovery_observed"
	EventRefired               Event = "refired"
	EventGraceExpired          Event = "grace_expired"
	EventLifecycleUnobservable Event = "lifecycle_unobservable"
)

// AdvanceLifecycle applies one legal lifecycle event. Terminal lifecycles
// (recovered, closed_unknown) never reopen: every event against them returns
// the original state plus an error.
func AdvanceLifecycle(from model.Lifecycle, event Event) (model.Lifecycle, error) {
	switch from {
	case model.LifecycleActive:
		switch event {
		case EventRecoveryObserved:
			return model.LifecycleRecoveryPending, nil
		case EventLifecycleUnobservable:
			return model.LifecycleClosedUnknown, nil
		case EventRefired:
			return model.LifecycleActive, nil
		case EventGraceExpired:
			// No grace runs while active.
		}
	case model.LifecycleRecoveryPending:
		switch event {
		case EventRefired:
			return model.LifecycleActive, nil
		case EventGraceExpired:
			return model.LifecycleRecovered, nil
		case EventLifecycleUnobservable:
			return model.LifecycleClosedUnknown, nil
		case EventRecoveryObserved:
			return model.LifecycleRecoveryPending, nil
		}
	case model.LifecycleRecovered, model.LifecycleClosedUnknown:
		// Terminal: no event advances a terminal lifecycle.
	}
	return from, errors.New("situation: invalid lifecycle transition")
}
