// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestAdvanceLifecycleLegalTransitions(t *testing.T) {
	tests := []struct {
		from  model.Lifecycle
		event Event
		want  model.Lifecycle
	}{
		{model.LifecycleActive, EventRecoveryObserved, model.LifecycleRecoveryPending},
		{model.LifecycleActive, EventRefired, model.LifecycleActive},
		{model.LifecycleActive, EventLifecycleUnobservable, model.LifecycleClosedUnknown},
		{model.LifecycleRecoveryPending, EventRefired, model.LifecycleActive},
		{model.LifecycleRecoveryPending, EventGraceExpired, model.LifecycleRecovered},
		{model.LifecycleRecoveryPending, EventLifecycleUnobservable, model.LifecycleClosedUnknown},
	}
	for _, tt := range tests {
		got, err := AdvanceLifecycle(tt.from, tt.event)
		if err != nil || got != tt.want {
			t.Fatalf("AdvanceLifecycle(%q, %q) = %q, %v; want %q", tt.from, tt.event, got, err, tt.want)
		}
	}
}

func TestTerminalLifecycleNeverReopens(t *testing.T) {
	for _, from := range []model.Lifecycle{model.LifecycleRecovered, model.LifecycleClosedUnknown} {
		for _, event := range []Event{EventRecoveryObserved, EventRefired, EventGraceExpired, EventLifecycleUnobservable} {
			got, err := AdvanceLifecycle(from, event)
			if err == nil || got != from {
				t.Fatalf("terminal transition %q + %q = %q, %v", from, event, got, err)
			}
		}
	}
}
