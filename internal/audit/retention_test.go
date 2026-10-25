// SPDX-License-Identifier: FSL-1.1-ALv2

package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

var retentionBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// appendHours appends one entry per hour starting at retentionBase.
func appendHours(t *testing.T, a *Auditor, ctx context.Context, from, to int) {
	t.Helper()
	for h := from; h < to; h++ {
		at := retentionBase.Add(time.Duration(h) * time.Hour)
		if err := a.withClock(func() time.Time { return at }).Append(ctx, "test", "test.hour", map[string]int{"hour": h}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPruneBeforeAnchorsTheChain(t *testing.T) {
	a, _, ctx := newAuditor(t)
	appendHours(t, a, ctx, 0, 10)
	a = a.withClock(func() time.Time { return retentionBase.Add(20 * time.Hour) })

	n, err := a.PruneBefore(ctx, retentionBase.Add(5*time.Hour))
	if err != nil || n != 5 {
		t.Fatalf("pruned %d, %v; want 5", n, err)
	}
	report, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v (%+v)", err, report)
	}
	if report.FirstSeq != 6 || report.PrunedThroughSeq != 5 || report.AnchorSeq != 11 || report.RowsChecked != 6 {
		t.Fatalf("report = %+v, want first 6, pruned through 5, anchor 11, 6 rows", report)
	}

	// A second prune removes the first anchor with the rest; the new anchor
	// accounts for the new start.
	appendHours(t, a, ctx, 10, 12)
	if n, err := a.PruneBefore(ctx, retentionBase.Add(11*time.Hour)); err != nil || n != 5 {
		t.Fatalf("second prune %d, %v; want 5 (seq 6-10)", n, err)
	}
	if report, err := a.Verify(ctx); err != nil || report.PrunedThroughSeq != 10 {
		t.Fatalf("verify after second prune: %+v, %v", report, err)
	}
	if oldest, ok, err := a.OldestEntry(ctx); err != nil || !ok || !oldest.Equal(retentionBase.Add(20*time.Hour)) {
		t.Fatalf("oldest entry %v %v %v; want the first anchor's time", oldest, ok, err)
	}
}

func TestPruneBeforeWholeLogLeavesAVerifiableAnchor(t *testing.T) {
	a, _, ctx := newAuditor(t)
	appendHours(t, a, ctx, 0, 4)
	a = a.withClock(func() time.Time { return retentionBase.Add(100 * time.Hour) })
	if n, err := a.PruneBefore(ctx, retentionBase.Add(99*time.Hour)); err != nil || n != 4 {
		t.Fatalf("pruned %d, %v; want 4", n, err)
	}
	report, err := a.Verify(ctx)
	if err != nil || report.RowsChecked != 1 || report.PrunedThroughSeq != 4 {
		t.Fatalf("verify: %+v, %v", report, err)
	}
}

func TestPruneBeforeStepsStayBounded(t *testing.T) {
	a, _, ctx := newAuditor(t)
	appendHours(t, a, ctx, 0, 10)
	defer func(step int, pause time.Duration) { auditPruneStep, auditPrunePause = step, pause }(auditPruneStep, auditPrunePause)
	auditPruneStep, auditPrunePause = 3, 0
	a = a.withClock(func() time.Time { return retentionBase.Add(50 * time.Hour) })
	if n, err := a.PruneBefore(ctx, retentionBase.Add(8*time.Hour)); err != nil || n != 8 {
		t.Fatalf("pruned %d, %v; want 8 in steps of at most 3", n, err)
	}
	if report, err := a.Verify(ctx); err != nil || report.PrunedThroughSeq != 8 {
		t.Fatalf("verify: %+v, %v", report, err)
	}
}

func TestVerifyRejectsAHeadRemovedWithoutAnchor(t *testing.T) {
	a, s, ctx := newAuditor(t)
	appendHours(t, a, ctx, 0, 5)
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM audit_log WHERE seq <= 2`); err != nil {
		t.Fatal(err)
	}
	report, err := a.Verify(ctx)
	if err == nil || report == nil || report.FailedSeq != 3 || !strings.Contains(report.Reason, "anchor") {
		t.Fatalf("verify = %+v, %v; want a failure at seq 3", report, err)
	}
}

func TestVerifyRejectsAnAnchorForOtherEntries(t *testing.T) {
	a, s, ctx := newAuditor(t)
	appendHours(t, a, ctx, 0, 6)
	a = a.withClock(func() time.Time { return retentionBase.Add(20 * time.Hour) })
	if _, err := a.PruneBefore(ctx, retentionBase.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Removing more of the head than the anchor records breaks the chain.
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM audit_log WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	if report, err := a.Verify(ctx); err == nil {
		t.Fatalf("verify accepted a head the anchor does not account for: %+v", report)
	}
}

func TestPruneBeforeNothingOld(t *testing.T) {
	a, _, ctx := newAuditor(t)
	appendHours(t, a, ctx, 0, 3)
	if n, err := a.PruneBefore(ctx, retentionBase); err != nil || n != 0 {
		t.Fatalf("pruned %d, %v; want 0", n, err)
	}
	var anchors int
	if err := a.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_log WHERE kind = ?`, KindAuditPruned).Scan(&anchors); err != nil || anchors != 0 {
		t.Fatalf("anchors = %d, %v; want none when nothing was pruned", anchors, err)
	}
}
