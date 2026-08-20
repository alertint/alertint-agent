// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func TestMergeDueReasonsUnionsInCanonicalOrder(t *testing.T) {
	got := MergeDueReasons(
		[]model.DueReason{model.DueAlertResolved, model.DueIncidentCreated},
		model.DueNewSymptom,
		model.DueIncidentCreated,
	)
	want := []model.DueReason{
		model.DueIncidentCreated,
		model.DueNewSymptom,
		model.DueAlertResolved,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
}

type failingLeaseExtender struct {
	calls      int
	claimToken int64
}

func (f *failingLeaseExtender) ExtendSituationLease(_ context.Context, _ string, _ string, claimToken int64, _ time.Time, _ time.Duration) error {
	f.calls++
	f.claimToken = claimToken
	return errors.New("store: situation lease lost")
}

func TestRunWithLeaseHeartbeatAbortsReconcileWhenOwnershipIsLost(t *testing.T) {
	extender := &failingLeaseExtender{}
	err := RunWithLeaseHeartbeat(
		context.Background(), extender, "situation-1", "worker-1", 42, time.Millisecond, time.Minute,
		func(ctx context.Context) error {
			<-ctx.Done()
			return context.Cause(ctx)
		},
	)
	if err == nil || !strings.Contains(err.Error(), "lease lost") {
		t.Fatalf("heartbeat err = %v", err)
	}
	if extender.calls != 1 {
		t.Fatalf("heartbeat calls = %d", extender.calls)
	}
	if extender.claimToken != 42 {
		t.Fatalf("heartbeat claim token = %d", extender.claimToken)
	}
}

func TestEarlierAssessmentAtNeverMovesLater(t *testing.T) {
	current := time.Date(2026, 8, 20, 10, 5, 0, 0, time.UTC)
	earlier := current.Add(-time.Minute)
	later := current.Add(time.Minute)
	if got := EarlierAssessmentAt(current, earlier); !got.Equal(earlier) {
		t.Fatalf("earlier candidate = %s, want %s", got, earlier)
	}
	if got := EarlierAssessmentAt(current, later); !got.Equal(current) {
		t.Fatalf("later candidate = %s, want %s", got, current)
	}
}

func TestPriorityForOrdersSignalsAndAgesOneBandAtATime(t *testing.T) {
	cases := []struct {
		name    string
		signals PrioritySignals
		want    WorkPriority
	}{
		{"urgent", PrioritySignals{DeterministicUrgent: true}, PriorityCritical},
		{"published material", PrioritySignals{PublishedMaterialChange: true}, PriorityPublishedMaterial},
		{"new symptom", PrioritySignals{NewSymptom: true}, PriorityNewSymptom},
		{"envelope violation", PrioritySignals{EnvelopeViolation: true}, PriorityNewSymptom},
		{"recovery", PrioritySignals{RecoveryBoundary: true}, PriorityRecoveryBoundary},
		{"deadline", PrioritySignals{DeadlineBoundary: true}, PriorityRecoveryBoundary},
		{"ordinary", PrioritySignals{}, PriorityObserve},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PriorityFor(tc.signals, 0, time.Minute); got != tc.want {
				t.Fatalf("priority = %d, want %d", got, tc.want)
			}
		})
	}
	if got := PriorityFor(PrioritySignals{}, 2*time.Minute, time.Minute); got != PriorityNewSymptom {
		t.Fatalf("aged observe priority = %d, want %d", got, PriorityNewSymptom)
	}
}

func TestIsPublishedMaterialReasonExcludesDurableWorkReasons(t *testing.T) {
	for _, reason := range []model.DueReason{model.DueMembershipChanged, model.DueAlertResolved, model.DueEnvelopeChanged} {
		if !IsPublishedMaterialReason(reason) {
			t.Fatalf("material reason %q was excluded", reason)
		}
	}
	for _, reason := range []model.DueReason{
		model.DueRecoveryGraceExpired,
		model.DueObservationDeadline,
		model.DueRetry,
		model.DueManualReassessment,
		model.DueDurationMilestone,
		model.DueSemanticProfileChanged,
		model.DueUpgradeReconstruction,
	} {
		if IsPublishedMaterialReason(reason) {
			t.Fatalf("non-material work reason %q was promoted", reason)
		}
	}
}
