// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// captureNotifier records the last Finding it was handed.
type captureNotifier struct {
	last *notify.Finding
}

func (c *captureNotifier) Notify(_ context.Context, f notify.Finding) error {
	c.last = &f
	return nil
}

func (c *captureNotifier) Name() string { return "capture" }

// TestRunSetsDrillOnFinding: an incident whose member alerts carry the
// Drill-alert marker label produces a Finding with Drill=true; a mixed member
// set stays flagged (any-not-all, ADR-0013); unmarked incidents stay false.
func TestRunSetsDrillOnFinding(t *testing.T) {
	cases := map[string]struct {
		labels []map[string]string
		want   bool
	}{
		"all members marked": {
			labels: []map[string]string{
				{store.DrillMarkerLabel: store.DrillMarkerValue, "service": "drill-checkout"},
				{store.DrillMarkerLabel: store.DrillMarkerValue, "service": "drill-checkout"},
			},
			want: true,
		},
		"mixed members stay flagged": {
			labels: []map[string]string{
				{"service": "checkout"},
				{store.DrillMarkerLabel: store.DrillMarkerValue, "service": "drill-checkout"},
			},
			want: true,
		},
		"no marker": {
			labels: []map[string]string{
				{"service": "checkout"},
			},
			want: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			st := newTestStore(t)
			inc := insertTestIncident(t, st, ctx)

			ids := make([]string, 0, len(tc.labels))
			for i, labels := range tc.labels {
				a := insertTestAlert(t, st, ctx, inc.ID, "fp-drill-"+name+string(rune('a'+i)), labels)
				ids = append(ids, a.ID)
			}

			fllm := &fakeLLM{response: validLLMResponse(ids)}
			capture := &captureNotifier{}
			skill := acutetriage.New(acutetriage.Config{WindowSeconds: 60}, st, fllm, audit.New(st.DB()), capture, nil)

			if err := skill.Run(ctx, inc); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if capture.last == nil {
				t.Fatal("notifier never received a finding")
			}
			if capture.last.Drill != tc.want {
				t.Errorf("Finding.Drill = %v, want %v", capture.last.Drill, tc.want)
			}
		})
	}
}
