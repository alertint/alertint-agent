// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/store"
)

// replayScriptedLLM returns queued responses in call order and records the
// prompts it received — the internal-package equivalent of
// acutetriage_test's scriptedLLM (unusable here across the package boundary).
type replayScriptedLLM struct {
	responses []json.RawMessage
	calls     int
	prompts   []string
}

func (f *replayScriptedLLM) Complete(_ context.Context, _ string, p llm.Prompt, _ []string) (llm.Completion, error) {
	i := f.calls
	f.calls++
	f.prompts = append(f.prompts, p.Prefix+p.Suffix)
	if i >= len(f.responses) {
		return llm.Completion{}, fmt.Errorf("replayScriptedLLM: unexpected call %d (only %d scripted)", i+1, len(f.responses))
	}
	return llm.Completion{Raw: f.responses[i], Model: "fake-model", InputTokens: 1, OutputTokens: 1, Latency: time.Millisecond}, nil
}

func draftJSON(t *testing.T, name, rootCause string, confidence float64, queries []map[string]any) json.RawMessage {
	t.Helper()
	resp := map[string]any{
		"analysis_name": name, "overall_issue": rootCause,
		"correlation_findings": []string{"c"}, "severity": "high",
		"confidence": confidence, "alerts": []map[string]string{},
	}
	if queries != nil {
		resp["verification"] = map[string]any{"queries": queries}
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func callTwoJSON(t *testing.T, name, rootCause string, confidence float64, verdict string) json.RawMessage {
	t.Helper()
	resp := map[string]any{
		"analysis_name": name, "overall_issue": rootCause,
		"correlation_findings": []string{"c"}, "severity": "medium",
		"confidence": confidence, "alerts": []map[string]string{},
	}
	if verdict != "" {
		resp["memory_verdict"] = verdict
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// countingPromServer answers every query with a healthy vector and counts
// requests, so a test can prove replay makes zero live calls to the SAME
// backend the original triage used.
func countingPromServer(t *testing.T) (*promclient.Client, *int32) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"cluster":"eu-west"},"value":[0,"3"]}]}}`))
	}))
	t.Cleanup(srv.Close)
	return promclient.NewClient(promclient.Config{BaseURL: srv.URL, TimeoutSeconds: 5}), &n
}

func seedReplayIncident(t *testing.T, st *store.Store, ctx context.Context) string {
	t.Helper()
	now := time.Now()
	id := uuid.NewString()
	if err := st.InsertIncident(ctx, store.Incident{
		ID: id, GroupKey: "alertname=TargetDown,namespace=prod",
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now,
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	a := store.Alert{
		ID: uuid.NewString(), Fingerprint: "fp-" + id, Status: "firing",
		Labels:      map[string]string{"alertname": "TargetDown", "namespace": "prod", "instance": "worker-14"},
		Annotations: map[string]string{"summary": "target down"},
		StartsAt:    now, ReceivedAt: now,
	}
	stored, err := st.UpsertAlertByFingerprint(ctx, a)
	if err != nil {
		t.Fatalf("upsert alert: %v", err)
	}
	if err := st.AddAlertToIncident(ctx, id, stored.ID, now); err != nil {
		t.Fatalf("add alert: %v", err)
	}
	return id
}

func refuteMarksOf(t *testing.T, st *store.Store, id string) int {
	t.Helper()
	var marks int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, id).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	return marks
}

func TestReplayIncident_HermeticFullPipeline(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	incID := seedReplayIncident(t, st, ctx)
	prom, reqCount := countingPromServer(t)
	cfg := Config{
		MinAlerts:     1,
		Prometheus:    prom,
		MetricParams:  MetricParams{TimeoutSeconds: 5},
		Verification:  VerificationParams{Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 5, MaxSeries: 100},
		PromptCaching: true,
	}

	// 1. Seed: run a REAL pipeline against the prom server and a scripted LLM
	// (draft proposing one promql query + call-2 re-judge), producing an
	// analyzed incident with a persisted verification round.
	seedLLM := &replayScriptedLLM{responses: []json.RawMessage{
		draftJSON(t, "TargetDown", "flapping NIC", 0.80, []map[string]any{
			{"kind": "promql", "expr": "node_network_up", "why": "discriminates NIC flap"},
		}),
		callTwoJSON(t, "TargetDown", "flapping NIC on worker-14", 0.85, ""),
	}}
	seedSkill := New(cfg, st, seedLLM, audit.New(st.DB()), nil, slog.Default())
	inc, err := st.GetIncidentByID(ctx, incID)
	if err != nil {
		t.Fatalf("reload before run: %v", err)
	}
	if err := seedSkill.Run(ctx, *inc); err != nil {
		t.Fatalf("seed Run: %v", err)
	}
	if seedLLM.calls != 2 {
		t.Fatalf("seed calls = %d, want 2 (draft + re-judge)", seedLLM.calls)
	}

	// 2. Reset the request counter after seeding, snapshot state to diff later.
	atomic.StoreInt32(reqCount, 0)
	before, err := st.GetIncidentByID(ctx, incID)
	if err != nil {
		t.Fatalf("reload before replay: %v", err)
	}
	if before.OutputJSON == "" {
		t.Fatal("seed did not persist a finding")
	}
	beforeMarks := refuteMarksOf(t, st, incID)
	beforeAlerts, err := st.GetIncidentAlertsWithRoles(ctx, incID)
	if err != nil {
		t.Fatalf("load roles before replay: %v", err)
	}
	var beforeAuditCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&beforeAuditCount); err != nil {
		t.Fatal(err)
	}

	// 3. Build the skill with a FRESH scriptedLLM scripted for draft + call-2.
	replayLLM := &replayScriptedLLM{responses: []json.RawMessage{
		draftJSON(t, "TargetDown", "flapping NIC", 0.80, []map[string]any{
			{"kind": "promql", "expr": "node_network_up", "why": "discriminates NIC flap"},
		}),
		callTwoJSON(t, "TargetDown", "flapping NIC on worker-14", 0.85, ""),
	}}
	replaySkill := New(cfg, st, replayLLM, nil, nil, slog.Default())

	// 4. Replay.
	rep, err := replaySkill.replayIncident(ctx, *before)
	if err != nil {
		t.Fatalf("replayIncident: %v", err)
	}

	if rep.fidelity != "full" {
		t.Errorf("fidelity = %q, want full", rep.fidelity)
	}
	if got := atomic.LoadInt32(reqCount); got != 0 {
		t.Errorf("live prometheus requests during replay = %d, want 0", got)
	}

	after, err := st.GetIncidentByID(ctx, incID)
	if err != nil {
		t.Fatalf("reload after replay: %v", err)
	}
	if after.OutputJSON != before.OutputJSON || after.Summary != before.Summary ||
		after.RootCause != before.RootCause || after.Confidence != before.Confidence {
		t.Errorf("store finding changed by replay:\nbefore=%+v\nafter=%+v", before, after)
	}
	if got := refuteMarksOf(t, st, incID); got != beforeMarks {
		t.Errorf("memory_refute_marks changed by replay: before=%d after=%d", beforeMarks, got)
	}
	afterAlerts, err := st.GetIncidentAlertsWithRoles(ctx, incID)
	if err != nil {
		t.Fatalf("load roles after replay: %v", err)
	}
	if len(afterAlerts) != len(beforeAlerts) {
		t.Fatalf("alert count changed: before=%d after=%d", len(beforeAlerts), len(afterAlerts))
	}
	for i := range beforeAlerts {
		if beforeAlerts[i].Role != afterAlerts[i].Role {
			t.Errorf("alert %s role changed by replay: before=%q after=%q", beforeAlerts[i].ID, beforeAlerts[i].Role, afterAlerts[i].Role)
		}
	}
	var afterAuditCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&afterAuditCount); err != nil {
		t.Fatal(err)
	}
	if afterAuditCount != beforeAuditCount {
		t.Errorf("audit rows changed by replay: before=%d after=%d", beforeAuditCount, afterAuditCount)
	}

	// The scripted call-2 prompt carries the frozen verification Result
	// strings verbatim — served from the snapshot, not recomputed.
	frozen := decodeFrozenEnvelope(before.EnrichmentJSON)
	if frozen.Verification == nil || len(frozen.Verification.Rounds) == 0 {
		t.Fatal("seed did not persist a verification round")
	}
	if len(replayLLM.prompts) != 2 {
		t.Fatalf("replay calls = %d, want 2 (draft + re-judge)", len(replayLLM.prompts))
	}
	for _, q := range frozen.Verification.Rounds[0].Queries {
		if !strings.Contains(replayLLM.prompts[1], q.Result) {
			t.Errorf("call-2 replay prompt missing frozen Result verbatim: %q", q.Result)
		}
	}
}

func TestReplayIncident_NoFindingErrors(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	incID := seedReplayIncident(t, st, ctx)
	inc, err := st.GetIncidentByID(ctx, incID)
	if err != nil {
		t.Fatal(err)
	}

	sk := New(Config{MinAlerts: 1}, st, &replayScriptedLLM{}, nil, nil, slog.Default())
	_, err = sk.replayIncident(ctx, *inc)
	if err == nil || !strings.Contains(err.Error(), "no finding") {
		t.Fatalf("want an error mentioning 'no finding', got %v", err)
	}
}
