// SPDX-License-Identifier: FSL-1.1-ALv2

package resolution

import (
	"context"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

type captureNotifier struct {
	last *notify.Finding
}

func (c *captureNotifier) Notify(_ context.Context, f notify.Finding) error {
	c.last = &f
	return nil
}

func (c *captureNotifier) Name() string { return "capture" }

// TestOnIncidentResolved_PreservesDrill: a resolving drill's finding keeps
// Drill=true so the in-place Slack card update keeps its banner (ADR-0013).
func TestOnIncidentResolved_PreservesDrill(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	cases := map[string]struct {
		labels map[string]string
		want   bool
	}{
		"drill": {labels: map[string]string{store.DemoMarkerLabel: store.DemoMarkerValue}, want: true},
		"real":  {labels: map[string]string{"service": "checkout"}, want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			inc := store.Incident{ID: "inc-" + name, GroupKey: "g=" + name, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now}
			if err := st.InsertIncident(ctx, inc); err != nil {
				t.Fatal(err)
			}
			a := store.Alert{ID: name + "-a", Fingerprint: name + "-fp", Status: "resolved", Labels: tc.labels, Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now}
			if _, err := st.UpsertAlertByFingerprint(ctx, a); err != nil {
				t.Fatal(err)
			}
			if err := st.AddAlertToIncident(ctx, inc.ID, a.ID, now); err != nil {
				t.Fatal(err)
			}

			capture := &captureNotifier{}
			if err := New(capture, st).OnIncidentResolved(ctx, inc); err != nil {
				t.Fatalf("OnIncidentResolved: %v", err)
			}
			if capture.last == nil || capture.last.Drill != tc.want {
				t.Fatalf("Drill = %+v, want %v", capture.last, tc.want)
			}
		})
	}

	t.Run("nil store degrades to false without panic", func(t *testing.T) {
		capture := &captureNotifier{}
		inc := store.Incident{ID: "inc-nil", GroupKey: "g", FirstAlertAt: now, LastAlertAt: now}
		if err := New(capture, nil).OnIncidentResolved(ctx, inc); err != nil {
			t.Fatalf("OnIncidentResolved: %v", err)
		}
		if capture.last == nil || capture.last.Drill {
			t.Fatalf("Drill = %+v, want false", capture.last)
		}
	})
}
