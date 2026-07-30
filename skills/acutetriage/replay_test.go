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
	"github.com/alertint/alertint-agent/internal/zabbix"
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

// seedZabbixReplayIncident mirrors seedReplayIncident but tags the alert with
// a "host" label so the Zabbix topology class (host-label-only) has something
// to fetch.
func seedZabbixReplayIncident(t *testing.T, st *store.Store, ctx context.Context) string {
	t.Helper()
	now := time.Now()
	id := uuid.NewString()
	if err := st.InsertIncident(ctx, store.Incident{
		ID: id, GroupKey: "alertname=WebDown,host=web01",
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now,
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, id); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	a := store.Alert{
		ID: uuid.NewString(), Fingerprint: "fp-" + id, Status: "firing",
		Labels:      map[string]string{"alertname": "WebDown", "host": "web01"},
		Annotations: map[string]string{"summary": "web01 unreachable"},
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

// poisonedZabbix fails the test if ANY method is invoked — proof that replay
// serves the zabbix section from the frozen envelope, never a live call.
type poisonedZabbix struct{ t *testing.T }

func (p *poisonedZabbix) TriggerContext(context.Context, string) (zabbix.Operator, error) {
	p.t.Fatal("replay must not call TriggerContext")
	return zabbix.Operator{}, nil
}
func (p *poisonedZabbix) ProblemContext(context.Context, string) (zabbix.ProblemDetail, error) {
	p.t.Fatal("replay must not call ProblemContext")
	return zabbix.ProblemDetail{}, nil
}
func (p *poisonedZabbix) HostContext(context.Context, string) (zabbix.Topology, error) {
	p.t.Fatal("replay must not call HostContext")
	return zabbix.Topology{}, nil
}
func (p *poisonedZabbix) FlapCount(context.Context, string, time.Time) (int, error) {
	p.t.Fatal("replay must not call FlapCount")
	return 0, nil
}
func (p *poisonedZabbix) OpenProblems(context.Context, string, zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	p.t.Fatal("replay must not call OpenProblems")
	return nil, nil
}
func (p *poisonedZabbix) HostGroups(context.Context, []string) ([]zabbix.HostGroupInfo, error) {
	p.t.Fatal("replay must not call HostGroups")
	return nil, nil
}
func (p *poisonedZabbix) GroupOpenProblems(context.Context, []string, zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	p.t.Fatal("replay must not call GroupOpenProblems")
	return nil, nil
}

func TestReplayIncident_NoLiveZabbixCall(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	incID := seedZabbixReplayIncident(t, st, ctx)
	zbxSeed := &fakeZabbix{host: zabbix.Topology{VisibleName: "web01"}}
	cfg := Config{
		MinAlerts:    1,
		Zabbix:       zbxSeed,
		ZabbixParams: ZabbixParams{TimeoutSeconds: 5, HostLabel: "host"},
	}
	seedLLM := &replayScriptedLLM{responses: []json.RawMessage{
		draftJSON(t, "WebDown", "web01 unreachable", 0.7, nil),
	}}
	seedSkill := New(cfg, st, seedLLM, audit.New(st.DB()), nil, slog.Default())
	inc, err := st.GetIncidentByID(ctx, incID)
	if err != nil {
		t.Fatalf("reload before run: %v", err)
	}
	if err := seedSkill.Run(ctx, *inc); err != nil {
		t.Fatalf("seed Run: %v", err)
	}

	before, err := st.GetIncidentByID(ctx, incID)
	if err != nil {
		t.Fatalf("reload before replay: %v", err)
	}
	frozen := decodeFrozenEnvelope(before.EnrichmentJSON)
	if frozen.Zabbix == nil || frozen.Zabbix.Topology == nil {
		t.Fatal("seed did not persist a zabbix section")
	}

	replayCfg := cfg
	replayCfg.Zabbix = &poisonedZabbix{t: t}
	replayLLM := &replayScriptedLLM{responses: []json.RawMessage{
		draftJSON(t, "WebDown", "web01 unreachable", 0.7, nil),
	}}
	replaySkill := New(replayCfg, st, replayLLM, nil, nil, slog.Default())
	rep, err := replaySkill.replayIncident(ctx, *before)
	if err != nil {
		t.Fatalf("replayIncident: %v", err)
	}
	if rep.fidelity != "full" {
		t.Errorf("fidelity = %q, want full", rep.fidelity)
	}
}

func TestSnapshotKey_ZabbixKindsMatchOnHosts(t *testing.T) {
	frozen := VerificationQuery{Kind: kindZabbixReachability,
		Params:  map[string]any{"hosts": []any{"db-01", "web-01"}}, // post-JSON shape
		Outcome: OutcomeFetched, Result: "db-01 reachable (1 interface); not in maintenance"}
	exec := newSnapshotExecutor([]VerificationQuery{frozen})
	live := VerificationQuery{Kind: kindZabbixReachability,
		Params: map[string]any{"hosts": []string{"db-01", "web-01"}}} // live Go shape
	exec.execute(context.Background(), &live)
	if live.Outcome != OutcomeFetched || live.Result != frozen.Result {
		t.Fatalf("snapshot miss: outcome=%s result=%q", live.Outcome, live.Result)
	}
	// Different host set → miss → the existing no-data path.
	other := VerificationQuery{Kind: kindZabbixReachability,
		Params: map[string]any{"hosts": []string{"cache-01"}}}
	exec.execute(context.Background(), &other)
	if other.Result != "no data (replay)" {
		t.Fatalf("expected replay miss, got %q", other.Result)
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
