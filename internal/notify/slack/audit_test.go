// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// TestNotifyAudit_NewCardFlag pins the new_card field on notify.sent rows:
// true whenever a delivery puts a new top-level card in the channel — the
// first firing card, or a resolved card for an incident that resolved
// before it ever had a firing card — and false for in-place edits and
// threaded updates. alertint_usage_stats counts operator pokes off it.
func TestNotifyAudit_NewCardFlag(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	auditor := audit.New(st.DB())

	finding := func(status string) notify.Finding {
		return notify.Finding{
			IncidentID: "inc-1", GroupKey: "g", AnalysisName: "x", OverallIssue: "y",
			Severity: "high", Confidence: 0.9, AlertCount: 1, Status: status,
			FirstAlertAt: time.Now().Add(-time.Minute), AnalyzedAt: time.Now(),
		}
	}

	// Card lookups fail (no card yet) for the first two deliveries, then
	// succeed for the last two.
	fresh := NewWithClient(newFakeSlack(t), "chan", "", "", &fakeThreadStore{missing: true}, auditor)
	if err := fresh.Notify(ctx, finding("ongoing")); err != nil {
		t.Fatalf("first firing: %v", err)
	}
	if err := fresh.Notify(ctx, finding("resolved")); err != nil {
		t.Fatalf("resolved without prior card: %v", err)
	}
	existing := NewWithClient(newFakeSlack(t), "chan", "", "", &fakeThreadStore{}, auditor)
	if err := existing.Notify(ctx, finding("ongoing")); err != nil {
		t.Fatalf("rejudge on existing card: %v", err)
	}
	if err := existing.Notify(ctx, finding("resolved")); err != nil {
		t.Fatalf("resolved on existing card: %v", err)
	}

	rows, err := st.DB().QueryContext(ctx,
		`SELECT payload_json FROM audit_log WHERE actor = 'notify.slack' AND kind = 'notify.sent' ORDER BY seq`)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer func() { _ = rows.Close() }()

	type row struct {
		Event   string `json:"event"`
		NewCard bool   `json:"new_card"`
	}
	var got []row
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var r row
		if err := json.Unmarshal([]byte(payload), &r); err != nil {
			t.Fatalf("payload not JSON: %v", err)
		}
		got = append(got, r)
	}
	want := []row{
		{Event: "firing", NewCard: true},
		{Event: "resolved", NewCard: true},
		{Event: "rejudge", NewCard: false},
		{Event: "resolved", NewCard: false},
	}
	if len(got) != len(want) {
		t.Fatalf("notify.sent rows = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
