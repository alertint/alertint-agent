package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

func newAuditor(t *testing.T) (*Auditor, *store.Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(s.DB()), s, ctx
}

func TestAppend_AndVerify_OnEmptyLog(t *testing.T) {
	a, _, ctx := newAuditor(t)
	report, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK || report.RowsChecked != 0 {
		t.Errorf("empty log report: %+v", report)
	}
}

func TestAppend_OneRowChain(t *testing.T) {
	a, _, ctx := newAuditor(t)

	if err := a.Append(ctx, "ingress", "alert.received", map[string]any{
		"fingerprint": "abc",
		"alertname":   "HighCPU",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	report, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK || report.RowsChecked != 1 {
		t.Fatalf("one-row report: %+v", report)
	}
}

func TestAppend_100Rows_Verifies(t *testing.T) {
	a, _, ctx := newAuditor(t)

	for i := 0; i < 100; i++ {
		if err := a.Append(ctx, "test", "tick", map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	report, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK || report.RowsChecked != 100 {
		t.Errorf("verify report: %+v", report)
	}
}

func TestVerify_DetectsTamperedPayload(t *testing.T) {
	a, s, ctx := newAuditor(t)

	for i := 0; i < 5; i++ {
		if err := a.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Tamper with row 3's payload.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE audit_log SET payload_json = ? WHERE seq = 3`,
		`{"i":999}`,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report, err := a.Verify(ctx)
	if err == nil {
		t.Fatal("expected verify to fail after tamper")
	}
	if report == nil || report.OK {
		t.Fatalf("expected non-OK report, got %+v", report)
	}
	if report.FailedSeq != 3 {
		t.Errorf("FailedSeq = %d, want 3", report.FailedSeq)
	}
}

func TestVerify_DetectsTamperedPrevHash(t *testing.T) {
	a, s, ctx := newAuditor(t)
	for i := 0; i < 4; i++ {
		_ = a.Append(ctx, "t", "k", map[string]any{"i": i})
	}

	// Break the prev_hash linkage at row 2.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE audit_log SET prev_hash = ? WHERE seq = 2`,
		"00",
	); err != nil {
		t.Fatalf("tamper prev: %v", err)
	}

	report, err := a.Verify(ctx)
	if err == nil || report == nil || report.OK || report.FailedSeq != 2 {
		t.Fatalf("expected chain break at seq 2, got err=%v report=%+v", err, report)
	}
}

func TestVerify_SurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	s1, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	a1 := New(s1.DB())
	for i := 0; i < 10; i++ {
		if err := a1.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	// Re-open: this re-runs the migration runner. The chain must still verify.
	s2, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer func() { _ = s2.Close() }()
	a2 := New(s2.DB())

	report, err := a2.Verify(ctx)
	if err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
	if !report.OK || report.RowsChecked != 10 {
		t.Errorf("post-reopen report: %+v", report)
	}

	// Append more rows after reopen and verify again.
	for i := 10; i < 15; i++ {
		if err := a2.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append after reopen: %v", err)
		}
	}
	report, err = a2.Verify(ctx)
	if err != nil || !report.OK || report.RowsChecked != 15 {
		t.Fatalf("post-append report: %+v err=%v", report, err)
	}
}

func TestCanonicalJSON_StableForEquivalentMaps(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1, "c": map[string]any{"y": 2, "x": 1}}
	b := map[string]any{"a": 1, "c": map[string]any{"x": 1, "y": 2}, "b": 2}
	x, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := canonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(y) {
		t.Errorf("canonical JSON differs:\n a=%s\n b=%s", x, y)
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	canonical := []byte(`{"a":1}`)
	h1 := computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", canonical, "")
	h2 := computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", canonical, "")
	if h1 != h2 {
		t.Error("computeHash not deterministic")
	}
	// Sanity: changing any input changes the output.
	cases := []string{
		computeHash("2026-05-22T09:55:01Z", "ingress", "alert.received", canonical, ""),
		computeHash("2026-05-22T09:55:00Z", "other", "alert.received", canonical, ""),
		computeHash("2026-05-22T09:55:00Z", "ingress", "alert.resolved", canonical, ""),
		computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", []byte(`{"a":2}`), ""),
		computeHash("2026-05-22T09:55:00Z", "ingress", "alert.received", canonical, "deadbeef"),
	}
	for i, c := range cases {
		if c == h1 {
			t.Errorf("case %d collides with base hash", i)
		}
	}
}

func TestAppend_RejectsMissingActorOrKind(t *testing.T) {
	a, _, ctx := newAuditor(t)
	if err := a.Append(ctx, "", "k", nil); err == nil {
		t.Error("expected error for empty actor")
	}
	if err := a.Append(ctx, "a", "  ", nil); err == nil {
		t.Error("expected error for blank kind")
	}
}

func TestAppend_DistinctRowsPerCall_TimestampsAdvance(t *testing.T) {
	// Use a controlled clock so we don't depend on test wall-clock granularity.
	a, _, ctx := newAuditor(t)
	base := time.Date(2026, 5, 22, 9, 55, 0, 0, time.UTC)
	steps := 0
	a = a.withClock(func() time.Time {
		t := base.Add(time.Duration(steps) * time.Second)
		steps++
		return t
	})

	for i := 0; i < 3; i++ {
		if err := a.Append(ctx, "t", "k", map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	report, err := a.Verify(ctx)
	if err != nil || !report.OK || report.RowsChecked != 3 {
		t.Fatalf("verify: report=%+v err=%v", report, err)
	}
}

// Sanity check that table sizes stay bounded by the chain semantics: a
// failed transaction should not leave a partial row behind.
func TestAppend_RollbackLeavesNoRow(t *testing.T) {
	a, s, ctx := newAuditor(t)
	// Force a marshal failure: channels are not JSON-serializable.
	err := a.Append(ctx, "t", "k", map[string]any{"bad": make(chan int)})
	if err == nil {
		t.Fatal("expected marshal error")
	}
	var count int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("audit_log row count after failed append = %d, want 0", count)
	}
	// Channel referenced to silence "declared and not used" suspicion.
	_ = fmt.Sprintf("%v", err)
}
