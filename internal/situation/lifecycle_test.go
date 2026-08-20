// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestAdvanceLifecycleEntersRecoveryPending(t *testing.T) {
	got, err := AdvanceLifecycle(model.LifecycleActive, EventRecoveryObserved)
	if err != nil {
		t.Fatal(err)
	}
	if got != model.LifecycleRecoveryPending {
		t.Fatalf("lifecycle = %q, want %q", got, model.LifecycleRecoveryPending)
	}
}

func TestAdvanceLifecycleEnforcesTerminalBoundary(t *testing.T) {
	cases := []struct {
		name  string
		from  model.Lifecycle
		event Event
		want  model.Lifecycle
		ok    bool
	}{
		{"pending refires", model.LifecycleRecoveryPending, EventRefired, model.LifecycleActive, true},
		{"grace expires", model.LifecycleRecoveryPending, EventGraceExpired, model.LifecycleRecovered, true},
		{"active lifecycle becomes unknowable", model.LifecycleActive, EventLifecycleUnobservable, model.LifecycleClosedUnknown, true},
		{"pending lifecycle becomes unknowable", model.LifecycleRecoveryPending, EventLifecycleUnobservable, model.LifecycleClosedUnknown, true},
		{"recovered never reopens", model.LifecycleRecovered, EventRefired, model.LifecycleRecovered, false},
		{"closed unknown ignores reassessment", model.LifecycleClosedUnknown, EventManualReassessment, model.LifecycleClosedUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AdvanceLifecycle(tc.from, tc.event)
			if (err == nil) != tc.ok {
				t.Fatalf("AdvanceLifecycle(%q, %q) = %q, %v", tc.from, tc.event, got, err)
			}
			if got != tc.want {
				t.Fatalf("lifecycle = %q, want %q", got, tc.want)
			}
		})
	}
}
