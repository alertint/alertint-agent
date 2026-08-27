// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// --------------------------------------------------------------------------
// Scripted two-call fake LLM
// --------------------------------------------------------------------------

// scriptResp is one queued reply: a raw JSON body OR an error (the LLM call
// failing). err takes precedence when set.
type scriptResp struct {
	raw       json.RawMessage
	err       error
	cacheRead int // scripted cache_read_input_tokens for this reply
}

// scriptedLLM returns queued responses in order (call 1, call 2, …) and records
// the exact system/user prompts it received, so the verification tests can
// assert on both what the model was told (call 2's continuation) and how many
// calls happened (the kill switch). An out-of-script call fails loudly rather
// than silently replaying the last reply — a two-call test that made three
// calls is a bug, not a pass.
type scriptedLLM struct {
	responses []scriptResp
	calls     int
	systems   []string
	prompts   []string
	records   []llm.Prompt // full structured prompts, for marking/prefix assertions
}

func (f *scriptedLLM) Complete(_ context.Context, system string, p llm.Prompt, _ []string) (llm.Completion, error) {
	i := f.calls
	f.calls++
	f.systems = append(f.systems, system)
	f.prompts = append(f.prompts, p.Prefix+p.Suffix)
	f.records = append(f.records, p)
	if i >= len(f.responses) {
		return llm.Completion{}, fmt.Errorf("scriptedLLM: unexpected call %d (only %d scripted)", i+1, len(f.responses))
	}
	r := f.responses[i]
	return llm.Completion{
		Raw:                  r.raw,
		Model:                "fake-model",
		InputTokens:          11,
		OutputTokens:         22,
		Latency:              5 * time.Millisecond,
		CacheReadInputTokens: r.cacheRead,
	}, r.err
}

// --------------------------------------------------------------------------
// Response + fixture builders
// --------------------------------------------------------------------------

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// draftResp builds a call-1 draft carrying an optional verification plan
// (queries). A nil queries slice omits the "verification" key entirely (the
// model proposed no targeted checks — the floor still runs).
func draftResp(t *testing.T, name, rootCause string, confidence float64, queries []map[string]any) json.RawMessage {
	t.Helper()
	resp := map[string]any{
		"analysis_name":        name,
		"overall_issue":        rootCause,
		"correlation_findings": []string{"c"},
		"severity":             "high",
		"confidence":           confidence,
		"alerts":               []map[string]string{},
	}
	if queries != nil {
		resp["verification"] = map[string]any{"queries": queries}
	}
	return mustJSON(t, resp)
}

// callTwoResp builds a call-2 re-judged verdict: the same schema, no
// "verification" key, with an optional memory_verdict (empty = omitted).
func callTwoResp(t *testing.T, name, rootCause string, confidence float64, verdict string) json.RawMessage {
	t.Helper()
	resp := map[string]any{
		"analysis_name":        name,
		"overall_issue":        rootCause,
		"correlation_findings": []string{"c"},
		"severity":             "medium",
		"confidence":           confidence,
		"alerts":               []map[string]string{},
	}
	if verdict != "" {
		resp["memory_verdict"] = verdict
	}
	return mustJSON(t, resp)
}

// --------------------------------------------------------------------------
// Fake Prometheus backends (httptest servers behind the real client)
// --------------------------------------------------------------------------

const vectorValue3 = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"cluster":"eu-west"},"value":[0,"3"]}]}}`
const vectorEmpty = `{"status":"success","data":{"resultType":"vector","result":[]}}`

func isUpQuery(q string) bool {
	return strings.HasPrefix(q, "sum(up") || strings.HasPrefix(q, "count(up")
}

// promServer wires an httptest Prometheus whose response is chosen per query
// expression by pick, and returns the real client pointed at it.
func promServer(t *testing.T, pick func(query string) (status int, body string)) *promclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		status, body := pick(q)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return promclient.NewClient(promclient.Config{BaseURL: srv.URL, TimeoutSeconds: 5})
}

// promHealthy answers every query with a healthy 3-value vector.
func promHealthy(t *testing.T) *promclient.Client {
	t.Helper()
	return promServer(t, func(string) (int, string) { return 200, vectorValue3 })
}

// promUpHealthyElseEmpty answers up_ratio with a healthy vector and everything
// else (the metric-enrichment selector) with an empty vector — so verification
// has live PromQL evidence while pack enrichment has none.
func promUpHealthyElseEmpty(t *testing.T) *promclient.Client {
	t.Helper()
	return promServer(t, func(q string) (int, string) {
		if isUpQuery(q) {
			return 200, vectorValue3
		}
		return 200, vectorEmpty
	})
}

// promUpHealthyElseFails answers up_ratio healthy and fails every other query
// (both the metric-enrichment selector and any model-proposed promql).
func promUpHealthyElseFails(t *testing.T) *promclient.Client {
	t.Helper()
	return promServer(t, func(q string) (int, string) {
		if isUpQuery(q) {
			return 200, vectorValue3
		}
		return 500, `{"status":"error"}`
	})
}

// promAllFail fails every query — the floor up_ratio cannot fetch.
func promAllFail(t *testing.T) *promclient.Client {
	t.Helper()
	return promServer(t, func(string) (int, string) { return 500, `{"status":"error"}` })
}

// --------------------------------------------------------------------------
// Persisted-state readers
// --------------------------------------------------------------------------

// persistedFinding is the denormalized incident row the verification tests
// assert on.
type persistedFinding struct {
	rootCause  string
	confidence float64
	enrichment string
	output     string
}

func readFinding(t *testing.T, st *store.Store, id string) persistedFinding {
	t.Helper()
	var f persistedFinding
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COALESCE(root_cause,''), COALESCE(confidence,0), COALESCE(enrichment_json,''), COALESCE(output_json,'')
		 FROM incidents WHERE id = ?`, id,
	).Scan(&f.rootCause, &f.confidence, &f.enrichment, &f.output); err != nil {
		t.Fatalf("read finding %s: %v", id, err)
	}
	return f
}

// verificationOf extracts the persisted "verification" envelope key.
func verificationOf(t *testing.T, enrichmentJSON string) *acutetriage.VerificationEnrichment {
	t.Helper()
	var env struct {
		Verification *acutetriage.VerificationEnrichment `json:"verification"`
	}
	if err := json.Unmarshal([]byte(enrichmentJSON), &env); err != nil {
		t.Fatalf("unmarshal enrichment envelope: %v\n%s", err, enrichmentJSON)
	}
	return env.Verification
}

func auditCount(t *testing.T, st *store.Store, kind string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE kind = ?`, kind).Scan(&n); err != nil {
		t.Fatalf("count audit %s: %v", kind, err)
	}
	return n
}

// verifyConfig is the shared verification-enabled skill config; prom may be nil.
func verifyConfig(prom *promclient.Client) acutetriage.Config {
	return acutetriage.Config{
		MinAlerts:    1,
		Prometheus:   prom,
		MetricParams: acutetriage.MetricParams{TimeoutSeconds: 5},
		Verification: acutetriage.VerificationParams{
			Enabled: true, MaxQueries: 4, QueryTimeoutSeconds: 5, MaxSeries: 100,
		},
		PromptCaching: true,
	}
}

// strongRecallReader returns a reader whose exact-key recall folds one strong
// prior pointing at priorID, so a call-2 memory_verdict routes marks onto it.
func strongRecallReader(priorID string) *stubMemoryReader {
	return &stubMemoryReader{view: &store.MemoryView{
		GroupKey: "alertname=DiskFull,host=web1", Episodes: 3,
		PriorFindings: []store.PriorFinding{
			{IncidentID: priorID, AnalyzedAt: time.Now(), Confidence: 0.7, RootCause: "prior cause"},
		},
	}}
}

// --------------------------------------------------------------------------
// T3 — the 28cfd3e2 regional-verdict regression fixture
// --------------------------------------------------------------------------

// TestVerificationRevisesRegionalVerdict pins the headline behavior: a confident
// draft claiming regional scope is contradicted by the computed round (healthy
// peers, nothing else firing) and the second call revises down to a single
// cluster. The persisted finding is the REVISED one; the envelope records the
// round with the draft it started from; call 2's prompt carries every query's
// rendered Result verbatim (persist-as-rendered byte-check); both audit events
// fire; and the call-2 verdict routes the contradiction mark.
func TestVerificationRevisesRegionalVerdict(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	prior := insertTestIncident(t, st, ctx)

	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-t3", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "regional event", "regional infrastructure event", 0.95, []map[string]any{
			{"kind": "promql", "expr": "sum by(cluster)(up)", "why": "peers healthy would refute a regional outage"},
		})},
		{raw: callTwoResp(t, "cluster reconcile", "single cluster reconcile loop", 0.80, "refutes")},
	}}

	cfg := verifyConfig(promHealthy(t))
	cfg.Memory = strongRecallReader(prior.ID)
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls (draft + re-judge), got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if f.rootCause != "single cluster reconcile loop" {
		t.Errorf("persisted root cause = %q, want the REVISED verdict", f.rootCause)
	}
	if f.confidence != 0.80 {
		t.Errorf("persisted confidence = %v, want 0.80 (revised)", f.confidence)
	}

	ver := verificationOf(t, f.enrichment)
	if ver == nil {
		t.Fatalf("envelope missing verification key:\n%s", f.enrichment)
	}
	if ver.Outcome != "revised" {
		t.Errorf("outcome = %q, want revised", ver.Outcome)
	}
	if len(ver.Rounds) != 1 {
		t.Fatalf("want 1 round, got %d", len(ver.Rounds))
	}
	round := ver.Rounds[0]
	if round.Draft.Confidence != 0.95 {
		t.Errorf("round draft confidence = %v, want 0.95", round.Draft.Confidence)
	}
	// floor (up_ratio + incidents_in_window) + one model promql = 3 queries.
	if len(round.Queries) != 3 {
		t.Fatalf("want 3 queries (2 floor + 1 model), got %d", len(round.Queries))
	}
	for i, q := range round.Queries {
		if q.Result == "" {
			t.Errorf("query %d (%s/%s) has empty Result", i, q.Source, q.Kind)
		}
		// Persist-as-rendered: call 2's prompt contains each Result verbatim.
		if !strings.Contains(scripted.prompts[1], q.Result) {
			t.Errorf("call-2 prompt missing query %d Result verbatim: %q\nprompt:\n%s", i, q.Result, scripted.prompts[1])
		}
	}

	if n := auditCount(t, st, "incident.verification_planned"); n != 1 {
		t.Errorf("verification_planned audit rows = %d, want 1", n)
	}
	if n := auditCount(t, st, "incident.verification_executed"); n != 1 {
		t.Errorf("verification_executed audit rows = %d, want 1", n)
	}

	// R11: incident.analyzed carries the verification outcome field.
	var analyzedPayload string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT payload_json FROM audit_log WHERE kind = 'incident.analyzed'`).Scan(&analyzedPayload); err != nil {
		t.Fatalf("query incident.analyzed audit: %v", err)
	}
	if !strings.Contains(analyzedPayload, `"verification_outcome":"revised"`) {
		t.Errorf("incident.analyzed payload missing verification_outcome=revised: %s", analyzedPayload)
	}

	// The call-2 "refutes" verdict routes a contradiction mark onto the prior.
	if got := refuteMarks(t, st, prior.ID); got != 1 {
		t.Errorf("prior refute marks = %d, want 1 (call-2 refutes routed)", got)
	}
}

// TestAuditVerificationPlannedIncludesOperatorQueries regression-tests the
// audit-parity bug: auditVerificationPlanned used to be called before the
// governing verdict's operator-sourced steering queries (ADR-0029) were even
// computed, and its own plan assembly had no way to include them — so a
// steering-active triage's "planned" audit row silently undercounted relative
// to the round that actually executed. A governing correction verdict here
// contributes one operator query (buildSteeringQueries), no model queries are
// proposed, so the round is floor(2) + operator(1) = 3 — and the planned audit
// row must show exactly that, with the operator query present.
func TestAuditVerificationPlannedIncludesOperatorQueries(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "disk event", "disk pressure", 0.9, nil)},
		{raw: callTwoResp(t, "disk event", "disk pressure", 0.9, "")},
	}}

	cfg := verifyConfig(promHealthy(t))
	cfg.Memory = &stubMemoryReader{
		view: &store.MemoryView{GroupKey: "alertname=DiskFull,host=web1"},
		governing: &store.IncidentVerdict{
			IncidentID:      inc.ID,
			Version:         1,
			Verdict:         "correction",
			ExpectationJSON: `{"cause_series":["pvc_bytes"]}`,
			CreatedAt:       time.Now(),
		},
	}
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	f := readFinding(t, st, inc.ID)
	ver := verificationOf(t, f.enrichment)
	if ver == nil || len(ver.Rounds) != 1 {
		t.Fatalf("expected one verification round, got %+v", ver)
	}
	round := ver.Rounds[0]
	if len(round.Queries) != 3 { // 2 floor + 1 operator, no model queries proposed
		t.Fatalf("want 3 executed queries (2 floor + 1 operator), got %d: %+v", len(round.Queries), round.Queries)
	}

	var payload string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT payload_json FROM audit_log WHERE kind = 'incident.verification_planned'`).Scan(&payload); err != nil {
		t.Fatalf("query incident.verification_planned audit: %v", err)
	}
	var planned struct {
		Queries []map[string]string `json:"queries"`
	}
	if err := json.Unmarshal([]byte(payload), &planned); err != nil {
		t.Fatalf("unmarshal planned payload: %v\n%s", err, payload)
	}
	if len(planned.Queries) != len(round.Queries) {
		t.Fatalf("planned audit query count (%d) must match executed round query count (%d): planned=%+v executed=%+v",
			len(planned.Queries), len(round.Queries), planned.Queries, round.Queries)
	}
	found := false
	for _, q := range planned.Queries {
		if q["source"] == "operator" {
			found = true
		}
	}
	if !found {
		t.Fatalf("planned audit payload must include the operator-sourced steering query: %+v", planned.Queries)
	}
}

// --------------------------------------------------------------------------
// T4(a) — clamp on a partial failure
// --------------------------------------------------------------------------

// TestClampOnPartialFailure: the floor fetched but a targeted model query
// failed, so the round has unfetched evidence. Call 2 tries to RAISE confidence
// (0.99 > draft 0.9); the clamp rail holds it at the draft's 0.9. The verdict is
// unchanged, so the outcome is "supported".
func TestClampOnPartialFailure(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-t4a", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.9, []map[string]any{
			{"kind": "promql", "expr": "broken_metric_query", "why": "would refute"},
		})},
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.99, "")},
	}}

	skill := acutetriage.New(verifyConfig(promUpHealthyElseFails(t)), st, scripted, nil, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if f.confidence != 0.9 {
		t.Errorf("persisted confidence = %v, want 0.9 (clamped down from 0.99, unfetched evidence)", f.confidence)
	}
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.Outcome != "supported" {
		t.Errorf("outcome = %v, want supported (verdict unchanged)", ver)
	}
}

// --------------------------------------------------------------------------
// T4(b) — degraded when the floor cannot fetch
// --------------------------------------------------------------------------

// TestDegradedWhenFloorFails: every Prometheus call fails, so the floor's
// up_ratio cannot fetch. The re-judge still runs, but the round is degraded and
// the shipped Finding is flagged Unverified.
func TestDegradedWhenFloorFails(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-t4b", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.8, []map[string]any{
			{"kind": "promql", "expr": "some_metric", "why": "would refute"},
		})},
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.7, "")},
	}}

	notifier := &capturingNotifier{}
	skill := acutetriage.New(verifyConfig(promAllFail(t)), st, scripted, nil, notifier, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.Outcome != "degraded" {
		t.Errorf("outcome = %v, want degraded (floor failed)", ver)
	}
	if !notifier.last.Unverified {
		t.Errorf("degraded round must flag Finding.Unverified, got %+v", notifier.last)
	}
}

// --------------------------------------------------------------------------
// T4(c) — draft ships when call 2 misses
// --------------------------------------------------------------------------

// TestDraftShipsWhenCallTwoMisses: the second LLM call errors (deadline
// exceeded). The DRAFT persists as the final finding, the outcome is degraded,
// and — critically — the draft's memory_verdict is discarded so no marks move on
// stale grounds (R16). Draft confidence 0.5 is below the metadata cap, so the
// persisted number is unambiguous.
func TestDraftShipsWhenCallTwoMisses(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	prior := insertTestIncident(t, st, ctx)

	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-t4c", map[string]string{"alertname": "DiskFull", "host": "web1"})

	draft := draftResp(t, "draft", "draft cause", 0.5, []map[string]any{
		{"kind": "promql", "expr": "m", "why": "would refute"},
	})
	// The draft carries a "refutes" verdict; the lost call 2 must NOT let it move
	// marks (the verdict belongs to call 2 when verification is enabled).
	var draftMap map[string]any
	if err := json.Unmarshal(draft, &draftMap); err != nil {
		t.Fatalf("unmarshal draft: %v", err)
	}
	draftMap["memory_verdict"] = "refutes"
	draft = mustJSON(t, draftMap)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draft},
		{err: context.DeadlineExceeded},
	}}

	cfg := verifyConfig(nil) // prom absent: irrelevant, call 2 errors before the round matters
	cfg.Memory = strongRecallReader(prior.ID)
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run must not fail when call 2 misses: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls (draft + attempted re-judge), got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if f.rootCause != "draft cause" {
		t.Errorf("persisted root cause = %q, want the DRAFT (call 2 missed)", f.rootCause)
	}
	if f.confidence != 0.5 {
		t.Errorf("persisted confidence = %v, want the draft's 0.5", f.confidence)
	}
	if f.output != string(draft) {
		t.Errorf("output_json must be the draft's exact bytes (a lost call 2 preserves the draft verbatim):\n--- got ---\n%s\n--- want ---\n%s", f.output, draft)
	}
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.Outcome != "degraded" {
		t.Errorf("outcome = %v, want degraded (call 2 missed)", ver)
	}
	if got := refuteMarks(t, st, prior.ID); got != 0 {
		t.Errorf("a lost call 2 must move no marks, got %d", got)
	}
}

// --------------------------------------------------------------------------
// T4(d) — degraded round must discard call 2's verdict (R16)
// --------------------------------------------------------------------------

// TestDegradedFloorFailsCallTwoVerdictDiscarded: the floor cannot fetch (every
// Prometheus call fails, so !floorFetched(round)), but call 2 itself succeeds
// and parses fine, returning a non-empty memory_verdict. This is the path
// degradedDraft does NOT cover — degradedDraft only runs on a call-2 LLM error
// or malformed JSON. Per R16, a degraded/unverified round must produce no
// verdict regardless of why it degraded, so the "refutes" verdict must NOT
// route a contradiction mark onto the recalled prior.
func TestDegradedFloorFailsCallTwoVerdictDiscarded(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	prior := insertTestIncident(t, st, ctx)

	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-t4d", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.7, []map[string]any{
			{"kind": "promql", "expr": "some_metric", "why": "would refute"},
		})},
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.65, "refutes")},
	}}

	cfg := verifyConfig(promAllFail(t))
	cfg.Memory = strongRecallReader(prior.ID)
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls (draft + re-judge), got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.Outcome != "degraded" {
		t.Errorf("outcome = %v, want degraded (floor failed even though call 2 succeeded)", ver)
	}

	// R16: a degraded round must produce no verdict, even though call 2 parsed
	// fine and returned "refutes" — the contradiction mark must NOT move.
	if got := refuteMarks(t, st, prior.ID); got != 0 {
		t.Errorf("a degraded round's call-2 verdict must move no marks, got %d", got)
	}
}

// --------------------------------------------------------------------------
// T5 — kill switch: exactly one call, no verification, byte-identical prompt
// --------------------------------------------------------------------------

// TestKillSwitchSingleCall: with verification disabled the pipeline makes ONE
// LLM call, persists no "verification" envelope key, and the call-1 prompt is
// byte-identical to what UserPrompt produces with a zero VerificationParams.
func TestKillSwitchSingleCall(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-t5", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.7, "")},
	}}
	// No Verification field → zero value → disabled (the kill switch).
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, scripted, nil, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 1 {
		t.Fatalf("kill switch must make exactly 1 call, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if strings.Contains(f.enrichment, "verification") {
		t.Errorf("disabled verification must not persist a verification key: %s", f.enrichment)
	}

	// Byte-identical prompt: rebuild the reference from the same inc + alerts.
	alerts, err := st.GetIncidentAlerts(ctx, inc.ID)
	if err != nil {
		t.Fatalf("load alerts: %v", err)
	}
	pack := acutetriage.BuildEvidencePack(inc, alerts, 0)
	want := acutetriage.UserPrompt(pack, string(mustJSON(t, pack)), nil, nil, nil, nil, nil, nil, acutetriage.VerificationParams{})
	if scripted.prompts[0] != want {
		t.Errorf("call-1 prompt drifted from the pre-feature fixture:\n--- got ---\n%s\n--- want ---\n%s", scripted.prompts[0], want)
	}
}

// --------------------------------------------------------------------------
// T6 — cap interaction (R17)
// --------------------------------------------------------------------------

// TestCapInteraction: live verification PromQL evidence counts as live evidence
// for the metadata-only cap. With a fetched up_ratio and no pack evidence, a
// 0.9 confidence survives; with Prometheus absent (state-only floor), the same
// finding is capped to 0.6.
func TestCapInteraction(t *testing.T) {
	run := func(t *testing.T, prom *promclient.Client) float64 {
		t.Helper()
		ctx := context.Background()
		st := newTestStore(t)
		inc := insertTestIncident(t, st, ctx)
		insertTestAlert(t, st, ctx, inc.ID, "fp-t6", map[string]string{"alertname": "DiskFull", "host": "web1"})

		scripted := &scriptedLLM{responses: []scriptResp{
			// No model queries → floor-only round.
			{raw: draftResp(t, "draft", "disk pressure on web1", 0.9, nil)},
			{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.9, "")},
		}}
		skill := acutetriage.New(verifyConfig(prom), st, scripted, nil, nil, nil)
		if err := skill.Run(ctx, inc); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return readFinding(t, st, inc.ID).confidence
	}

	t.Run("up_ratio_fetched_survives_cap", func(t *testing.T) {
		if got := run(t, promUpHealthyElseEmpty(t)); got != 0.9 {
			t.Errorf("confidence = %v, want 0.9 (live verification evidence lifts the cap)", got)
		}
	})

	t.Run("prom_absent_cap_applies", func(t *testing.T) {
		if got := run(t, nil); got != acutetriage.MaxMetadataOnlyConfidence {
			t.Errorf("confidence = %v, want %v (state-only floor is not live evidence)", got, acutetriage.MaxMetadataOnlyConfidence)
		}
	})
}

// --------------------------------------------------------------------------
// Prompt caching (Task 4): conditional marking, the shared-prefix guarantee,
// and the cache-engagement WARN.
// --------------------------------------------------------------------------

// runVerifiedPair runs one enabled two-call triage against a scripted fake
// and returns the fake for prompt/marking assertions. call2CacheRead scripts
// call 2's cache_read_input_tokens; logger may be nil.
func runVerifiedPair(t *testing.T, call2CacheRead int, logger *slog.Logger) *scriptedLLM {
	t.Helper()
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-cache", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "disk", "disk pressure on web1", 0.7, nil)},
		{raw: callTwoResp(t, "disk", "disk pressure on web1", 0.7, ""), cacheRead: call2CacheRead},
	}}
	skill := acutetriage.New(verifyConfig(promHealthy(t)), st, scripted, nil, nil, logger)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}
	return scripted
}

// TestConditionalMarking pins the marking rule: a lone marked call pays the
// cache write premium with no read, so call 1 marks iff verification is
// enabled; call 2 (which only exists when enabled) always marks.
func TestConditionalMarking(t *testing.T) {
	// Verification disabled — one call, unmarked, no suffix (kill-switch shape).
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-nomark", map[string]string{"alertname": "DiskFull", "host": "web1"})
	off := &scriptedLLM{responses: []scriptResp{
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.7, "")},
	}}
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1, PromptCaching: true}, st, off, nil, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := off.records[0]; got.CachePrefix || got.Suffix != "" {
		t.Errorf("verification off: call 1 must be unmarked and suffix-less, got CachePrefix=%v Suffix=%q", got.CachePrefix, got.Suffix)
	}

	// Verification enabled — both calls marked, call 2 carries the suffix.
	on := runVerifiedPair(t, 3400, nil)
	if !on.records[0].CachePrefix {
		t.Error("verification on: call 1 must mark the shared prefix")
	}
	if !on.records[1].CachePrefix || on.records[1].Suffix == "" {
		t.Errorf("call 2 must be marked and carry the continuation suffix, got CachePrefix=%v Suffix=%q", on.records[1].CachePrefix, on.records[1].Suffix)
	}
}

// TestCallTwoPrefixIsCallOnePrompt pins the Shared prefix guarantee
// (CONTEXT.md): the re-judge call's prompt opens with the draft call's
// prompt, verbatim.
func TestCallTwoPrefixIsCallOnePrompt(t *testing.T) {
	f := runVerifiedPair(t, 3400, nil)
	if f.records[0].Suffix != "" {
		t.Errorf("call 1 must have no suffix, got %q", f.records[0].Suffix)
	}
	if f.records[1].Prefix != f.records[0].Prefix {
		t.Error("call 2 prefix != call 1 prompt: the shared prefix drifted")
	}
	if !strings.Contains(f.records[1].Suffix, "## Your draft verdict") {
		t.Error("call 2 suffix lost the draft-verdict continuation")
	}
}

// TestWarnWhenCallTwoReadNoCachedPrefix: cacheRead 0 on call 2 → one WARN;
// cacheRead > 0 → none. The WARN stays per-pair because below-floor and
// prefix-drift are indistinguishable at log time.
func TestWarnWhenCallTwoReadNoCachedPrefix(t *testing.T) {
	var buf bytes.Buffer
	runVerifiedPair(t, 0, slog.New(slog.NewTextHandler(&buf, nil)))
	if !strings.Contains(buf.String(), "read no cached prefix") {
		t.Error("expected WARN for zero cache read on call 2")
	}

	buf.Reset()
	runVerifiedPair(t, 3400, slog.New(slog.NewTextHandler(&buf, nil)))
	if strings.Contains(buf.String(), "read no cached prefix") {
		t.Error("unexpected WARN when the cache engaged")
	}
}

// TestPromptCachingFalseSuppressesMarkAndWarn: with PromptCaching false
// (openai-compatible wiring), neither call marks CachePrefix, and a zero
// cache read on call 2 does not WARN — on a provider without client-side
// caching, zero reads are normal, not a drift signal. The shared-prefix
// guarantee itself is provider-independent and must survive.
func TestPromptCachingFalseSuppressesMarkAndWarn(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-nocache", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "disk", "disk pressure on web1", 0.7, nil)},
		{raw: callTwoResp(t, "disk", "disk pressure on web1", 0.7, ""), cacheRead: 0},
	}}
	var buf bytes.Buffer
	cfg := verifyConfig(promHealthy(t))
	cfg.PromptCaching = false
	skill := acutetriage.New(cfg, st, scripted, nil, nil, slog.New(slog.NewTextHandler(&buf, nil)))
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}
	if scripted.records[0].CachePrefix || scripted.records[1].CachePrefix {
		t.Errorf("PromptCaching false: no call may mark CachePrefix, got call1=%v call2=%v",
			scripted.records[0].CachePrefix, scripted.records[1].CachePrefix)
	}
	if scripted.records[1].Prefix != scripted.records[0].Prefix {
		t.Error("shared-prefix guarantee must hold regardless of caching")
	}
	if strings.Contains(buf.String(), "read no cached prefix") {
		t.Error("PromptCaching false: zero cache read must not WARN")
	}
}

// --------------------------------------------------------------------------
// Verdict steering (Tasks 7-8): the ruling contract — call-2 demand, soft
// parse, audit, loud failure (ADR-0029) — plus the deterministic confidence
// backstop that clamps off the recorded ruling (applySteeringCap).
//
// Every test here seeds the REAL store with a captured verdict via
// PersistVerdictCapture (Config.Memory = st) so FetchMemory's real
// GoverningVerdict query populates MemoryEnrichment.Governing end-to-end —
// not a stubbed reader. TestSteering_UnverifiableClamps /
// AbsentRulingKeepsRevisionAndClamps / UnbackedContradictionClamps assert on
// the steering-specific backstop; their fixtures deliberately keep live
// verification evidence flowing (a fetched floor up_ratio) so the
// PRE-EXISTING annotations-only cap (applyEvidenceCap) cannot accidentally
// paper over the steering-specific clamp under test.
// --------------------------------------------------------------------------

// callTwoRespWithRuling builds a call-2 re-judged verdict carrying an
// optional operator_ruling key (empty ruling omits the key entirely — the
// soft-parse path under test).
func callTwoRespWithRuling(t *testing.T, name, rootCause string, conf float64, ruling, basis string) json.RawMessage {
	t.Helper()
	resp := map[string]any{
		"analysis_name":        name,
		"overall_issue":        rootCause,
		"correlation_findings": []string{"c"},
		"severity":             "medium",
		"confidence":           conf,
		"alerts":               []map[string]string{},
	}
	if ruling != "" {
		resp["operator_ruling"] = map[string]string{"ruling": ruling, "basis": basis}
	}
	return mustJSON(t, resp)
}

// callTwoRespWithBareStringRuling builds a call-2 response whose
// "operator_ruling" key is a bare string ("supported") rather than the
// documented {"ruling":...,"basis":...} object — plausibly the single most
// likely real-world shape mismatch (small/local models are especially prone
// to this). Used to pin that a wrong-typed operator_ruling degrades exactly
// like an omitted key (soft validation) rather than failing the unmarshal of
// the whole call-2 response.
func callTwoRespWithBareStringRuling(t *testing.T, name, rootCause string, conf float64) json.RawMessage {
	t.Helper()
	resp := map[string]any{
		"analysis_name":        name,
		"overall_issue":        rootCause,
		"correlation_findings": []string{"c"},
		"severity":             "medium",
		"confidence":           conf,
		"alerts":               []map[string]string{},
		"operator_ruling":      "supported", // wrong shape: bare string, not an object
	}
	return mustJSON(t, resp)
}

// seedGoverningVerdict captures a verdict of the given kind ("correction" |
// "confirmation") against incidentID via the real PersistVerdictCapture path,
// so the group key's GoverningVerdict query (joined by group_key, not a fake)
// picks it up for any incident sharing that key.
func seedGoverningVerdict(t *testing.T, st *store.Store, ctx context.Context, incidentID, kind, expectationJSON string) *store.IncidentVerdict {
	t.Helper()
	v, _, err := st.PersistVerdictCapture(ctx, store.VerdictCapture{
		IncidentID:      incidentID,
		Verdict:         kind,
		Source:          store.VerdictSourceHuman,
		LabelConfidence: 1,
		ExpectationJSON: expectationJSON,
		AnnotationNote:  "operator " + kind + " note",
	})
	if err != nil {
		t.Fatalf("seed governing %s: %v", kind, err)
	}
	return v
}

// recordingHandler is a minimal slog.Handler that captures every record it
// sees so a test can assert on the structured Level, not just grep formatted
// text (a TextHandler line always contains "level=ERROR" as a substring of
// its own formatting, which is not the same as asserting the Record's Level).
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) firstAtLevel(lvl slog.Level) (slog.Record, bool) {
	for _, r := range h.records {
		if r.Level == lvl {
			return r, true
		}
	}
	return slog.Record{}, false
}

// TestSteering_SupportedAdoptsUncapped: a fetched steering query (operator
// query hits promHealthy) plus ruling "supported" records the ruling as
// backed, persists the corrected cause call 2 adopted, and leaves confidence
// exactly as the model returned it (0.85, uncapped) — a supported ruling
// never clamps, today or after Task 8.
func TestSteering_SupportedAdoptsUncapped(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer-a", map[string]string{"alertname": "DiskFull", "host": "web1"})
	v := seedGoverningVerdict(t, st, ctx, inc.ID, "correction", `{"cause_series":["pvc_bytes"]}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "generic disk pressure on web1", 0.85, nil)},
		{raw: callTwoRespWithRuling(t, "corrected", "pvc exhaustion on web1", 0.85,
			"supported", "pvc_bytes shows near-zero free space")},
	}}

	cfg := verifyConfig(promHealthy(t))
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if f.confidence != 0.85 {
		t.Errorf("confidence = %v, want 0.85 (supported ruling never clamps)", f.confidence)
	}
	if f.rootCause != "pvc exhaustion on web1" {
		t.Errorf("root cause = %q, want the adopted corrected cause", f.rootCause)
	}
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.OperatorRuling == nil {
		t.Fatalf("expected an operator_ruling record, got %+v", ver)
	}
	r := ver.OperatorRuling
	if r.Ruling != "supported" {
		t.Errorf("ruling = %q, want supported", r.Ruling)
	}
	if !r.Backed {
		t.Error("backed = false, want true (operator query fetched)")
	}
	if r.VerdictID != v.ID || r.VerdictVersion != v.Version {
		t.Errorf("ruling verdict id/version = %d/%d, want %d/%d", r.VerdictID, r.VerdictVersion, v.ID, v.Version)
	}
}

// TestSteering_ContradictedIsNotClamped: the money check — a fetched
// steering query plus ruling "contradicted" records contradicted+backed, and
// confidence is whatever the model itself returned (0.9 — above
// MaxMetadataOnlyConfidence, so the exemption itself, not just the
// early-return guard for already-low confidence, is what's under test),
// never clamped by steering. Backed contradictions are never clamped, today
// or after Task 8.
func TestSteering_ContradictedIsNotClamped(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer-b", map[string]string{"alertname": "DiskFull", "host": "web1"})
	seedGoverningVerdict(t, st, ctx, inc.ID, "correction", `{"cause_series":["pvc_bytes"]}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.85, nil)},
		{raw: callTwoRespWithRuling(t, "draft", "disk pressure on web1", 0.9,
			"contradicted", "pvc_bytes shows ample free space")},
	}}

	cfg := verifyConfig(promHealthy(t))
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	f := readFinding(t, st, inc.ID)
	if f.confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9 (model's own, above the cap; contradicted+backed is never clamped)", f.confidence)
	}
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.OperatorRuling == nil {
		t.Fatalf("expected an operator_ruling record, got %+v", ver)
	}
	r := ver.OperatorRuling
	if r.Ruling != "contradicted" {
		t.Errorf("ruling = %q, want contradicted", r.Ruling)
	}
	if !r.Backed {
		t.Error("backed = false, want true (operator query fetched)")
	}
}

// runSteeringUnbackedFixture is the shared fixture for TestSteering_
// UnverifiableClamps and TestSteering_UnbackedContradictionClamps: both seed
// a governing correction, run a two-call triage where the floor's up_ratio
// fetches (live evidence, so the pre-existing annotations-only cap cannot
// paper over the still-missing steering backstop) but the operator's
// steering query returns empty (promUpHealthyElseEmpty — unfetched, so
// Backed must be false either way) — they differ only in what call 2 rules
// and what root cause it settles on.
func runSteeringUnbackedFixture(t *testing.T, fp, rootCause, ruling, basis string) (persistedFinding, *acutetriage.VerificationEnrichment) {
	t.Helper()
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, fp, map[string]string{"alertname": "DiskFull", "host": "web1"})
	seedGoverningVerdict(t, st, ctx, inc.ID, "correction", `{"cause_series":["pvc_bytes"]}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.85, nil)},
		{raw: callTwoRespWithRuling(t, "draft", rootCause, 0.85, ruling, basis)},
	}}

	cfg := verifyConfig(promUpHealthyElseEmpty(t))
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := readFinding(t, st, inc.ID)
	return f, verificationOf(t, f.enrichment)
}

// TestSteering_UnverifiableClamps: the operator steering query returns an
// empty series (the floor's up_ratio still fetches, so live verification
// evidence IS present and the pre-existing annotations-only cap does not
// apply here) and the model rules "unverifiable". Per ADR-0029/Task 8, an
// unverifiable ruling must clamp confidence to MaxMetadataOnlyConfidence
// regardless of live evidence elsewhere.
func TestSteering_UnverifiableClamps(t *testing.T) {
	f, ver := runSteeringUnbackedFixture(t, "fp-steer-c",
		"per operator correction of 2026-07-28, not verifiable from current evidence",
		"unverifiable", "pvc_bytes returned no series")

	if f.confidence != acutetriage.MaxMetadataOnlyConfidence {
		t.Errorf("confidence = %v, want %v (unverifiable steering ruling must clamp — Task 8 backstop)",
			f.confidence, acutetriage.MaxMetadataOnlyConfidence)
	}
	if ver == nil || ver.OperatorRuling == nil {
		t.Fatalf("expected an operator_ruling record, got %+v", ver)
	}
	r := ver.OperatorRuling
	if r.Ruling != "unverifiable" {
		t.Errorf("ruling = %q, want unverifiable", r.Ruling)
	}
	if r.Backed {
		t.Error("backed = true, want false (operator query returned empty, not fetched)")
	}
}

// TestSteering_AbsentRulingKeepsRevisionAndClamps: call 2 succeeds and
// revises the root cause, but omits the operator_ruling key entirely. Soft
// validation means the revision is KEPT regardless (never a triage failure),
// and the record defaults to "absent". Per ADR-0029/Task 8, an absent ruling
// must clamp exactly like unverifiable.
func TestSteering_AbsentRulingKeepsRevisionAndClamps(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer-d", map[string]string{"alertname": "DiskFull", "host": "web1"})
	seedGoverningVerdict(t, st, ctx, inc.ID, "correction", `{"cause_series":["pvc_bytes"]}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.85, nil)},
		{raw: callTwoRespWithRuling(t, "revised", "pvc exhaustion on web1", 0.85, "", "")}, // no operator_ruling key
	}}

	// Live evidence present throughout (promHealthy): isolates the assertion to
	// the steering-specific backstop rather than the pre-existing evidence cap.
	cfg := verifyConfig(promHealthy(t))
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, auditor, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	f := readFinding(t, st, inc.ID)
	if f.rootCause != "pvc exhaustion on web1" {
		t.Errorf("root cause = %q, want the revision KEPT despite the absent ruling (soft validation)", f.rootCause)
	}
	if f.confidence != acutetriage.MaxMetadataOnlyConfidence {
		t.Errorf("confidence = %v, want %v (absent ruling must clamp — Task 8 backstop)",
			f.confidence, acutetriage.MaxMetadataOnlyConfidence)
	}
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.OperatorRuling == nil {
		t.Fatalf("expected an operator_ruling record even when call 2 omitted the key, got %+v", ver)
	}
	r := ver.OperatorRuling
	if r.Ruling != "absent" {
		t.Errorf("ruling = %q, want absent", r.Ruling)
	}
	if !r.Backed {
		t.Error("backed = false, want true (operator query fetched)")
	}

	var analyzedPayload string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT payload_json FROM audit_log WHERE kind = 'incident.analyzed'`).Scan(&analyzedPayload); err != nil {
		t.Fatalf("query incident.analyzed audit: %v", err)
	}
	if !strings.Contains(analyzedPayload, `"operator_ruling":"absent"`) {
		t.Errorf("incident.analyzed payload missing operator_ruling=absent: %s", analyzedPayload)
	}
}

// TestSteering_MalformedRulingShapeKeepsRevisionAndClamps (review Finding 1):
// call 2 answers with "operator_ruling" as a bare string ("supported")
// instead of the documented {"ruling":...,"basis":...} object — plausibly
// the single most likely real-world malformation, especially from smaller
// local models behind the openai-compatible provider. Because
// llmResponse.OperatorRuling is captured as json.RawMessage (untyped) rather
// than a typed *modelRuling, this shape mismatch must NOT fail the
// unmarshal of the whole call-2 response: the revision is KEPT (never routed
// through the degraded-JSON path, which would discard the whole verdict),
// the ruling record degrades to "absent" — same as an omitted key — and the
// existing soft-validation WARN fires. That "absent" record is structurally
// identical to TestSteering_AbsentRulingKeepsRevisionAndClamps's, so the
// Task 8 backstop (applySteeringCap: clamp unless a fetched-query-backed
// ruling of supported or contradicted exists) applies here exactly the same
// way — confidence clamps to MaxMetadataOnlyConfidence regardless of the
// live evidence (promHealthy) that keeps the pre-existing annotations-only
// cap from firing on its own.
func TestSteering_MalformedRulingShapeKeepsRevisionAndClamps(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer-i", map[string]string{"alertname": "DiskFull", "host": "web1"})
	seedGoverningVerdict(t, st, ctx, inc.ID, "correction", `{"cause_series":["pvc_bytes"]}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.85, nil)},
		{raw: callTwoRespWithBareStringRuling(t, "revised", "pvc exhaustion on web1", 0.85)},
	}}

	var buf bytes.Buffer
	cfg := verifyConfig(promHealthy(t))
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, nil, nil, slog.New(slog.NewTextHandler(&buf, nil)))

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run must not fail on a wrong-shaped operator_ruling: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if f.rootCause != "pvc exhaustion on web1" {
		t.Errorf("root cause = %q, want the revision KEPT despite the malformed ruling shape (soft validation)", f.rootCause)
	}
	if f.confidence != acutetriage.MaxMetadataOnlyConfidence {
		t.Errorf("confidence = %v, want %v (an absent ruling clamps regardless of shape — same backstop as the omitted-key case)",
			f.confidence, acutetriage.MaxMetadataOnlyConfidence)
	}
	ver := verificationOf(t, f.enrichment)
	if ver == nil {
		t.Fatalf("expected a verification envelope (a wrong-shaped ruling must not force the degraded path)")
	}
	if ver.Outcome == "degraded" {
		t.Errorf("outcome = degraded, want revised/supported — a malformed operator_ruling shape must not discard the whole call-2 verdict")
	}
	if ver.OperatorRuling == nil {
		t.Fatalf("expected an operator_ruling record even when the shape is wrong, got %+v", ver)
	}
	r := ver.OperatorRuling
	if r.Ruling != "absent" {
		t.Errorf("ruling = %q, want absent (malformed shape degrades exactly like an omitted key)", r.Ruling)
	}
	if !r.Backed {
		t.Error("backed = false, want true (operator query fetched)")
	}
	if !strings.Contains(buf.String(), "model omitted or mangled operator_ruling") {
		t.Errorf("expected the soft-validation WARN to fire for the malformed shape, got log:\n%s", buf.String())
	}
}

// TestSteering_UnbackedContradictionClamps: the model rules "contradicted"
// but the operator query never fetched data (promUpHealthyElseEmpty — empty,
// not fetched) — Backed must be false. Per ADR-0029/Task 8, a contradiction
// needs data: an unbacked one must clamp same as unverifiable.
func TestSteering_UnbackedContradictionClamps(t *testing.T) {
	f, ver := runSteeringUnbackedFixture(t, "fp-steer-e", "disk pressure on web1",
		"contradicted", "no data supports the correction, but I conclude it anyway")

	if f.confidence != acutetriage.MaxMetadataOnlyConfidence {
		t.Errorf("confidence = %v, want %v (unbacked contradiction must clamp — Task 8 backstop)",
			f.confidence, acutetriage.MaxMetadataOnlyConfidence)
	}
	if ver == nil || ver.OperatorRuling == nil {
		t.Fatalf("expected an operator_ruling record, got %+v", ver)
	}
	r := ver.OperatorRuling
	if r.Ruling != "contradicted" {
		t.Errorf("ruling = %q, want contradicted", r.Ruling)
	}
	if r.Backed {
		t.Error("backed = true, want false (zero fetched operator queries — a contradiction needs data)")
	}
}

// TestSteering_CallTwoFailureLogsErrorAndClamps: call 2 dies outright with
// steering active. The degraded draft ships, the record is "unruled", and an
// ERROR-level log fires naming the LLM failure and the unruled correction
// (captured via a recording slog.Handler, asserted on the structured Level —
// not a text grep). No Prometheus is configured here, so there is NO live
// verification evidence at all: the PRE-EXISTING annotations-only cap
// (applyEvidenceCap, built before this task) already clamps confidence to
// MaxMetadataOnlyConfidence on its own — this test exercises the ERROR log
// and the "unruled" record (Task 7) without depending on the steering-specific
// backstop (Task 8) to produce the clamp.
func TestSteering_CallTwoFailureLogsErrorAndClamps(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer-f", map[string]string{"alertname": "DiskFull", "host": "web1"})
	v := seedGoverningVerdict(t, st, ctx, inc.ID, "correction", `{"cause_series":["pvc_bytes"]}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.9, nil)},
		{err: context.DeadlineExceeded},
	}}

	handler := &recordingHandler{}
	cfg := verifyConfig(nil) // no Prometheus: no live verification evidence anywhere
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, nil, nil, slog.New(handler))

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run must not fail when call 2 misses: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if f.confidence != acutetriage.MaxMetadataOnlyConfidence {
		t.Errorf("confidence = %v, want %v (no live evidence anywhere: the pre-existing metadata-only cap applies)",
			f.confidence, acutetriage.MaxMetadataOnlyConfidence)
	}
	ver := verificationOf(t, f.enrichment)
	if ver == nil || ver.OperatorRuling == nil {
		t.Fatalf("expected an operator_ruling record, got %+v", ver)
	}
	r := ver.OperatorRuling
	if r.Ruling != "unruled" {
		t.Errorf("ruling = %q, want unruled (call 2 never completed)", r.Ruling)
	}
	if r.VerdictID != v.ID {
		t.Errorf("verdict id = %d, want %d", r.VerdictID, v.ID)
	}

	rec, ok := handler.firstAtLevel(slog.LevelError)
	if !ok {
		t.Fatalf("expected an ERROR-level log record, got none: %+v", handler.records)
	}
	if !strings.Contains(rec.Message, "unruled") {
		t.Errorf("ERROR message must name the unruled correction, got: %q", rec.Message)
	}
	if !strings.Contains(rec.Message, "call 2 failed") {
		t.Errorf("ERROR message must name the LLM failure, got: %q", rec.Message)
	}
}

// TestSteering_VerificationOffClampsQuietly: verification disabled entirely
// (the kill switch) with a governing correction present — exactly one LLM
// call, no round ever runs, and no ERROR fires (nothing failed; there was
// simply nothing to run). No Prometheus/metrics/logs/changes/Sentry are
// configured, so there is no live evidence anywhere: the PRE-EXISTING
// annotations-only cap already clamps confidence — this test PASSES today.
// The audit's steering_verdict_id/version still ride the trail even though
// no round executed (FetchMemory runs independently of Verification.Enabled).
func TestSteering_VerificationOffClampsQuietly(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer-g", map[string]string{"alertname": "DiskFull", "host": "web1"})
	v := seedGoverningVerdict(t, st, ctx, inc.ID, "correction", `{"cause_series":["pvc_bytes"]}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.9, nil)},
	}}

	var buf bytes.Buffer
	cfg := acutetriage.Config{MinAlerts: 1} // Verification zero value: disabled (kill switch)
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, auditor, nil, slog.New(slog.NewTextHandler(&buf, nil)))

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 1 {
		t.Fatalf("verification disabled: want exactly 1 LLM call, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	if f.confidence != acutetriage.MaxMetadataOnlyConfidence {
		t.Errorf("confidence = %v, want %v (no live evidence anywhere: the pre-existing metadata-only cap applies)",
			f.confidence, acutetriage.MaxMetadataOnlyConfidence)
	}
	if strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("no ERROR expected: nothing failed, got log:\n%s", buf.String())
	}

	var analyzedPayload string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT payload_json FROM audit_log WHERE kind = 'incident.analyzed'`).Scan(&analyzedPayload); err != nil {
		t.Fatalf("query incident.analyzed audit: %v", err)
	}
	if !strings.Contains(analyzedPayload, fmt.Sprintf(`"steering_verdict_id":%d`, v.ID)) {
		t.Errorf("incident.analyzed payload missing steering_verdict_id: %s", analyzedPayload)
	}
}

// TestSteering_ConfirmationRetiresSteering: a retiring confirmation governs
// (Steers=false) — no operator-sourced query joins the round (floor-only, 2
// queries), the call-2 suffix carries no operator_ruling demand, no ruling is
// recorded, and confidence is uncapped (live evidence via promHealthy rules
// out the unrelated evidence-basis cap, isolating "confirmation never
// steers" as the only thing under test).
func TestSteering_ConfirmationRetiresSteering(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-steer-h", map[string]string{"alertname": "DiskFull", "host": "web1"})
	seedGoverningVerdict(t, st, ctx, inc.ID, "confirmation", `{}`)

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.85, nil)},
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.85, "")},
	}}

	cfg := verifyConfig(promHealthy(t))
	cfg.Memory = st
	cfg.MemoryParams = acutetriage.MemoryParams{LookbackDays: 90}
	skill := acutetriage.New(cfg, st, scripted, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls, got %d", scripted.calls)
	}

	f := readFinding(t, st, inc.ID)
	ver := verificationOf(t, f.enrichment)
	if ver == nil || len(ver.Rounds) != 1 {
		t.Fatalf("expected one verification round, got %+v", ver)
	}
	if len(ver.Rounds[0].Queries) != 2 {
		t.Errorf("want 2 queries (floor only, confirmation contributes no steering query), got %d: %+v",
			len(ver.Rounds[0].Queries), ver.Rounds[0].Queries)
	}
	if ver.OperatorRuling != nil {
		t.Errorf("confirmation must not demand or record an operator ruling, got %+v", ver.OperatorRuling)
	}
	if strings.Contains(scripted.prompts[1], "operator_ruling") {
		t.Errorf("call-2 suffix must not demand an operator_ruling when a confirmation governs:\n%s", scripted.prompts[1])
	}
	if f.confidence != 0.85 {
		t.Errorf("confidence = %v, want 0.85 (no clamp — confirmation does not steer)", f.confidence)
	}
}

// --------------------------------------------------------------------------
// Task 9 — the Zabbix verification floor's acceptance test: a Zabbix-only
// install (no Prometheus configured anywhere) must still clear the
// metadata-only caveat and ship uncapped confidence, and the floor's
// own-event exclusion must actually drop the incident's own open problem out
// of the neighbor-problems render rather than reporting the incident back to
// itself as a "neighbor" — proving Tasks 1-8's composeFloor + floorFetched +
// own-event-exclusion chain works end to end on a real pipeline run, not
// just in isolated unit tests.
//
// Note on what confidence assertion 4 below proves: this test's alert
// carries a host label, so FetchZabbixContext (the separate chunk-02
// enrichment path) also runs against the same pipelineZabbix fake — but
// pipelineZabbix's fixture (no VisibleName/Inventory, MaintenanceActive
// false, no OtherOpenProblems, suppression "none" explicitly excluded)
// resolves that enrichment to OutcomeEmpty, not OutcomeFetched, so it does
// NOT independently trip hasLiveEvidence. With no metrics/logs/changes/
// Sentry wired either (verifyConfig(nil)), annotationsOnlyBasis reduces to
// !verificationLive(ver) — so this test's uncapped 0.85 IS carried solely by
// the verification floor's fetched zabbix_reachability query. The unit-level
// isolation of that same mechanism also lives in
// TestVerificationLive_ZabbixFloorCounts.
// --------------------------------------------------------------------------

// pipelineZabbix is the minimal exported-interface fake for the Zabbix-only
// integration case: one healthy host in one functional group ("Databases",
// 17 hosts total in HostGroups — 16 peers once the checked host itself is
// excluded). GroupOpenProblems returns two open problems: the incident's own
// (event id 5001, matching the test alert's zabbix_event_id ANNOTATION
// below — the real receiver's shape, internal/ingress/zabbix.go — which the
// floor's own-event exclusion must filter out) and one genuine neighbor
// (event id 9002), which must render. TriggerContext still returns a loud
// error as a tripwire: this alert carries no zabbix_trigger_id label, so it
// is never actually called. ProblemContext, unlike before, DOES get called —
// FetchZabbixContext's problem class keys on the zabbix_event_id annotation,
// which is now populated — so it returns a real answer instead of an error.
type pipelineZabbix struct{}

func (pipelineZabbix) TriggerContext(context.Context, string) (zabbix.Operator, error) {
	return zabbix.Operator{}, fmt.Errorf("zabbix: no trigger")
}
func (pipelineZabbix) ProblemContext(context.Context, string) (zabbix.ProblemDetail, error) {
	return zabbix.ProblemDetail{Severity: "4", Ongoing: true, DurationSecs: 900,
		Suppression: zabbix.Suppression{Kind: "none"}}, nil
}
func (pipelineZabbix) HostContext(context.Context, string) (zabbix.Topology, error) {
	return zabbix.Topology{Groups: []string{"Databases"},
		Interfaces: []zabbix.IfaceState{{Addr: "10.0.0.1", Available: "1"}}}, nil
}
func (pipelineZabbix) FlapCount(context.Context, string, time.Time) (int, error) { return 0, nil }
func (pipelineZabbix) OpenProblems(context.Context, string, zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	return nil, nil
}
func (pipelineZabbix) HostGroups(context.Context, []string) ([]zabbix.HostGroupInfo, error) {
	return []zabbix.HostGroupInfo{{GroupID: "1", Name: "Databases", Hosts: 17}}, nil
}
func (pipelineZabbix) GroupOpenProblems(context.Context, []string, zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	return []zabbix.Problem{
		{EventID: "5001", Name: "db1 unreachable", Severity: "4"},    // the incident's own open problem — must be excluded
		{EventID: "9002", Name: "cache-02 disk full", Severity: "2"}, // a genuine neighbor — must render
	}, nil
}

func TestVerification_ZabbixOnlyInstall_ClearsCaveat(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	// zabbix_event_id belongs in Annotations on a receiver-realistic alert
	// (internal/ingress/zabbix.go), never Labels — insertTestAlert only takes
	// labels, so the event id is attached with a follow-up upsert.
	alert := insertTestAlert(t, st, ctx, inc.ID, "fp-zbx-only", map[string]string{
		"alertname": "HostDown", "host": "db1",
	})
	alert.Annotations = map[string]string{"zabbix_event_id": "5001"}
	if _, err := st.UpsertAlertByFingerprint(ctx, alert); err != nil {
		t.Fatalf("attach zabbix_event_id annotation: %v", err)
	}

	rootCause := "db1 host pressure inside the Databases group"
	scripted := &scriptedLLM{responses: []scriptResp{
		// Call 1: draft with no verification key at all — the model proposes
		// nothing (the Zabbix floor already covers this incident).
		{raw: draftResp(t, "draft", rootCause, 0.85, nil)},
		{raw: callTwoResp(t, "draft", rootCause, 0.85, "")},
	}}

	// NO Prometheus (verifyConfig's prom stays nil): Zabbix is the only
	// configured backend on this install.
	cfg := verifyConfig(nil)
	cfg.Zabbix = pipelineZabbix{}
	cfg.ZabbixParams = acutetriage.ZabbixParams{HostLabel: "host", TimeoutSeconds: 5}

	notifier := &capturingNotifier{}
	skill := acutetriage.New(cfg, st, scripted, auditor, notifier, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if scripted.calls != 2 {
		t.Fatalf("want 2 LLM calls (draft + re-judge), got %d", scripted.calls)
	}

	// 1. The shipped finding must not carry the unverified caveat.
	if notifier.last.Unverified {
		t.Errorf("shipped finding must not be Unverified (the Zabbix floor cleared the caveat), got %+v", notifier.last)
	}

	f := readFinding(t, st, inc.ID)
	ver := verificationOf(t, f.enrichment)
	if ver == nil {
		t.Fatalf("envelope missing verification key:\n%s", f.enrichment)
	}

	// 2. The round outcome is "supported" (call 2 kept the same root cause).
	if ver.Outcome != "supported" {
		t.Errorf("outcome = %q, want supported", ver.Outcome)
	}
	if len(ver.Rounds) != 1 {
		t.Fatalf("want 1 round, got %d", len(ver.Rounds))
	}
	round := ver.Rounds[0]

	// 3. The round contains the Zabbix floor pair plus incidents_in_window,
	// and NO up_ratio (no Prometheus configured on this install).
	if len(round.Queries) != 3 {
		t.Fatalf("want 3 queries (zabbix_reachability + zabbix_neighbor_problems + incidents_in_window), got %d: %+v",
			len(round.Queries), round.Queries)
	}
	byKind := make(map[string]acutetriage.VerificationQuery, len(round.Queries))
	for _, q := range round.Queries {
		byKind[q.Kind] = q
	}
	reach, ok := byKind["zabbix_reachability"]
	if !ok {
		t.Fatalf("round missing zabbix_reachability: %+v", round.Queries)
	}
	if reach.Outcome != acutetriage.OutcomeFetched {
		t.Errorf("zabbix_reachability outcome = %q, want fetched", reach.Outcome)
	}
	neighbors, ok := byKind["zabbix_neighbor_problems"]
	if !ok {
		t.Fatalf("round missing zabbix_neighbor_problems: %+v", round.Queries)
	}
	if neighbors.Outcome != acutetriage.OutcomeFetched {
		t.Errorf("zabbix_neighbor_problems outcome = %q, want fetched (one genuine neighbor problem)", neighbors.Outcome)
	}
	if !strings.Contains(neighbors.Result, "16 peer hosts") {
		t.Errorf("zabbix_neighbor_problems result missing the 16-peer scope line: %q", neighbors.Result)
	}
	// Own-event exclusion (Finding 1, exercised end to end): GroupOpenProblems
	// returns both the incident's own open problem (event id 5001) and a
	// genuine neighbor (event id 9002) — only the neighbor may render.
	if strings.Contains(neighbors.Result, "db1 unreachable") {
		t.Errorf("own-event exclusion failed: the incident's own problem rendered as a neighbor: %q", neighbors.Result)
	}
	if !strings.Contains(neighbors.Result, "cache-02 disk full") {
		t.Errorf("genuine neighbor problem missing from the render: %q", neighbors.Result)
	}
	if _, ok := byKind["incidents_in_window"]; !ok {
		t.Errorf("round missing incidents_in_window: %+v", round.Queries)
	}
	if _, ok := byKind["up_ratio"]; ok {
		t.Errorf("round must NOT contain up_ratio on a Prometheus-less install: %+v", round.Queries)
	}

	// 4. Confidence ships uncapped at 0.85: the chunk-02 Zabbix enrichment
	// resolves to OutcomeEmpty on this fixture (see the file-level note
	// above), so the fetched zabbix_reachability floor query is what carries
	// verificationLive true and lifts the metadata-only cap here — the same
	// mechanism TestVerificationLive_ZabbixFloorCounts isolates at the unit
	// level.
	if f.confidence != 0.85 {
		t.Errorf("persisted confidence = %v, want 0.85 (uncapped)", f.confidence)
	}
	if notifier.last.Confidence != 0.85 {
		t.Errorf("shipped confidence = %v, want 0.85 (uncapped)", notifier.last.Confidence)
	}

	// 5. Call 1's prompt must not offer the promql kind — no Prometheus is
	// configured on this install.
	if strings.Contains(scripted.prompts[0], `"kind":"promql"`) {
		t.Errorf("call-1 prompt must not offer the promql kind on a Zabbix-only install:\n%s", scripted.prompts[0])
	}
}

// --------------------------------------------------------------------------
// One bounded batch repair of the model's own invalid PromQL (issue #62)
// --------------------------------------------------------------------------

// issue62Invalid is the shape that started this: a valid-looking aggregation
// the Prometheus parser rejects outright (`by` may only follow an aggregator).
// Before repair it was sent to Prometheus, rejected there, and the round
// degraded on a query the model could have fixed in one line.
const issue62Invalid = `increase(metric_name[1h]) by (type)`

// issue62Repaired is the same query, syntax-only: same metric, same window,
// same grouping — so promclient.ValidateSyntaxRepair accepts it.
const issue62Repaired = `sum by (type) (increase(metric_name[1h]))`

// repairResp builds the repair call's reply envelope: one replacement for the
// query at index idx.
func repairResp(idx int, expr string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"queries":[{"index":%d,"expr":%q}]}`, idx, expr))
}

// promRecorder wires a Prometheus that answers everything healthy and records
// every expression it was actually asked to run.
func promRecorder(t *testing.T) (*promclient.Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	client := promServer(t, func(q string) (int, string) {
		mu.Lock()
		seen = append(seen, q)
		mu.Unlock()
		return 200, vectorValue3
	})
	return client, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// auditPayload returns the single audit payload of the given kind.
func auditPayload(t *testing.T, st *store.Store, kind string) string {
	t.Helper()
	var payload string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT payload_json FROM audit_log WHERE kind = ?`, kind).Scan(&payload); err != nil {
		t.Fatalf("query %s audit: %v", kind, err)
	}
	return payload
}

// modelQueryOf returns the round's single model-sourced promql query.
func modelQueryOf(t *testing.T, round acutetriage.VerificationRound) acutetriage.VerificationQuery {
	t.Helper()
	for _, q := range round.Queries {
		if q.Source == "model" && q.Kind == "promql" {
			return q
		}
	}
	t.Fatalf("round has no model-sourced promql query: %+v", round.Queries)
	return acutetriage.VerificationQuery{}
}

// TestVerificationRepairsInvalidModelQuery is the acceptance test for issue
// #62: a draft proposing an unparseable PromQL query costs exactly ONE extra
// LLM call (draft → repair → re-judge), capped at 512 output tokens, and the
// query that reaches Prometheus is the CORRECTED one — the invalid expression
// never leaves the process.
func TestVerificationRepairsInvalidModelQuery(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-repair", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.8, []map[string]any{
			{"kind": "promql", "expr": issue62Invalid, "why": "would refute"},
		})},
		{raw: repairResp(0, issue62Repaired)},
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.8, "")},
	}}

	prom, sent := promRecorder(t)
	skill := acutetriage.New(verifyConfig(prom), st, scripted, auditor, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if scripted.calls != 3 {
		t.Fatalf("calls = %d, want draft + one repair + re-judge", scripted.calls)
	}
	if scripted.records[1].MaxOutputTokens != 512 {
		t.Fatalf("repair cap = %d, want 512", scripted.records[1].MaxOutputTokens)
	}
	// Only the repair call is capped; the draft and re-judge keep the
	// operator's configured ceiling.
	if scripted.records[0].MaxOutputTokens != 0 || scripted.records[2].MaxOutputTokens != 0 {
		t.Errorf("only the repair call may lower the output ceiling: %d / %d",
			scripted.records[0].MaxOutputTokens, scripted.records[2].MaxOutputTokens)
	}
	if !strings.Contains(scripted.records[1].Prefix, issue62Invalid) {
		t.Errorf("repair call did not carry the invalid expression:\n%s", scripted.records[1].Prefix)
	}
	// The repair prompt is standalone and must never be cache-marked, and it
	// must not disturb the shared prefix bytes between the draft and the
	// final re-judge (Global Constraint: preserve shared-prefix semantics for
	// draft/final calls).
	if scripted.records[1].CachePrefix {
		t.Error("repair call must never be cache-marked")
	}
	if scripted.records[2].Prefix != scripted.records[0].Prefix {
		t.Error("re-judge prefix != draft prompt: the repair call sitting in between disturbed the shared prefix")
	}

	receivedQueries := sent()
	for _, sent := range receivedQueries {
		if sent == issue62Invalid {
			t.Fatalf("invalid query reached Prometheus: %q", sent)
		}
	}
	corrected := 0
	for _, sent := range receivedQueries {
		if sent == issue62Repaired {
			corrected++
		}
	}
	if corrected != 1 {
		t.Fatalf("corrected query ran %d times, want exactly 1: %q", corrected, receivedQueries)
	}

	f := readFinding(t, st, inc.ID)
	ver := verificationOf(t, f.enrichment)
	if ver == nil || len(ver.Rounds) != 1 {
		t.Fatalf("expected one verification round, got %+v", ver)
	}
	q := modelQueryOf(t, ver.Rounds[0])
	if q.Expr != issue62Repaired {
		t.Errorf("persisted expr = %q, want the repaired one", q.Expr)
	}
	if q.Outcome != acutetriage.OutcomeFetched && q.Outcome != acutetriage.OutcomeEmpty {
		t.Errorf("repaired query outcome = %q, want fetched/empty (it actually ran)", q.Outcome)
	}
	if q.Why != "would refute" {
		t.Errorf("repair rewrote the model's stated intent: %q", q.Why)
	}

	if n := auditCount(t, st, "incident.verification_repair"); n != 1 {
		t.Fatalf("verification_repair audit rows = %d, want 1", n)
	}
	payload := auditPayload(t, st, "incident.verification_repair")
	var repair struct {
		Attempted          int `json:"attempted"`
		Repaired           int `json:"repaired"`
		InvalidAfterRepair int `json:"invalid_after_repair"`
	}
	if err := json.Unmarshal([]byte(payload), &repair); err != nil {
		t.Fatalf("unmarshal repair payload: %v\n%s", err, payload)
	}
	if repair.Attempted != 1 || repair.Repaired != 1 || repair.InvalidAfterRepair != 0 {
		t.Errorf("repair audit counts = %+v, want attempted=1 repaired=1 invalid_after_repair=0", repair)
	}
	// Counts only: no expression, no parser string, no model output.
	for _, leak := range []string{issue62Invalid, issue62Repaired, "parse error", "promql"} {
		if strings.Contains(payload, leak) {
			t.Errorf("repair audit payload leaked %q: %s", leak, payload)
		}
	}
}

// TestVerificationRepairFailureLeavesQueryInvalid: the one repair call answers
// with something still unparseable. There is no second attempt — the query is
// marked invalid, never sent to Prometheus, and the round carries that as its
// own outcome so the re-judge sees an honest "this check did not run".
func TestVerificationRepairFailureLeavesQueryInvalid(t *testing.T) {
	// Still invalid: `by` needs a parenthesized aggregation body after it.
	const stillInvalid = `sum by (type) increase(metric_name[1h])`

	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-repair-fail", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.8, []map[string]any{
			{"kind": "promql", "expr": issue62Invalid, "why": "would refute"},
		})},
		{raw: repairResp(0, stillInvalid)},
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.8, "")},
	}}

	prom, sent := promRecorder(t)
	var buf bytes.Buffer
	notifier := &capturingNotifier{}
	skill := acutetriage.New(verifyConfig(prom), st, scripted, auditor, notifier,
		slog.New(slog.NewTextHandler(&buf, nil)))
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if scripted.calls != 3 {
		t.Fatalf("calls = %d, want draft + ONE repair + re-judge (never a second repair)", scripted.calls)
	}

	// The pipeline's one wire from a residual-invalid query to the
	// operator-visible Slack/stdout caveat: VerificationInvalidQueries must be
	// set through the REAL pipeline, and — the important half — it must be
	// wired independently of Unverified, which only reflects connector/round
	// degradation, not an invalid model query (the floor still fetched fine
	// here, so the round is not degraded).
	if notifier.last.VerificationInvalidQueries != 1 {
		t.Errorf("notified VerificationInvalidQueries = %d, want 1", notifier.last.VerificationInvalidQueries)
	}
	if notifier.last.Unverified {
		t.Errorf("an invalid model query alone must not flag Unverified, got %+v", notifier.last)
	}
	for _, q := range sent() {
		if q == issue62Invalid || q == stillInvalid {
			t.Fatalf("invalid query reached Prometheus: %q", q)
		}
	}

	logs := buf.String()
	if !strings.Contains(logs, "invalid after one repair") {
		t.Errorf("logs missing the residual-invalid warning:\n%s", logs)
	}
	if !strings.Contains(logs, stillInvalid) {
		t.Errorf("logs missing the residual expression %q:\n%s", stillInvalid, logs)
	}

	f := readFinding(t, st, inc.ID)
	ver := verificationOf(t, f.enrichment)
	if ver == nil || len(ver.Rounds) != 1 {
		t.Fatalf("expected one verification round, got %+v", ver)
	}
	q := modelQueryOf(t, ver.Rounds[0])
	if q.Outcome != acutetriage.OutcomeInvalid {
		t.Errorf("outcome = %q, want invalid", q.Outcome)
	}
	if q.Result != "invalid query (not executed)" {
		t.Errorf("result = %q, want the never-executed text", q.Result)
	}
	// Apply-then-revalidate: the persisted expression is the last one actually
	// tried (the rejected replacement), marked invalid so it never executes.
	if q.Expr != stillInvalid {
		t.Errorf("persisted expr = %q, want the rejected replacement", q.Expr)
	}
	if q.Why != "would refute" {
		t.Errorf("a failed repair must not touch the model's stated intent: %q", q.Why)
	}

	var executed struct {
		Invalid int `json:"invalid"`
		Fetched int `json:"fetched"`
	}
	payload := auditPayload(t, st, "incident.verification_executed")
	if err := json.Unmarshal([]byte(payload), &executed); err != nil {
		t.Fatalf("unmarshal executed payload: %v\n%s", err, payload)
	}
	if executed.Invalid != 1 {
		t.Errorf("executed audit invalid = %d, want 1: %s", executed.Invalid, payload)
	}

	var repair struct {
		Attempted          int `json:"attempted"`
		Repaired           int `json:"repaired"`
		InvalidAfterRepair int `json:"invalid_after_repair"`
	}
	if err := json.Unmarshal([]byte(auditPayload(t, st, "incident.verification_repair")), &repair); err != nil {
		t.Fatalf("unmarshal repair payload: %v", err)
	}
	if repair.Attempted != 1 || repair.Repaired != 0 || repair.InvalidAfterRepair != 1 {
		t.Errorf("repair audit counts = %+v, want attempted=1 repaired=0 invalid_after_repair=1", repair)
	}
}

// TestVerificationRepairSkippedWhenPlanValid pins the other half of the
// call-count contract: repair costs nothing when there is nothing to repair.
// A syntactically valid plan still makes exactly the two calls it always did,
// and emits no repair audit row at all. (The verification-disabled path's
// single call is pinned by TestKillSwitchSingleCall.)
func TestVerificationRepairSkippedWhenPlanValid(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	inc := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, inc.ID, "fp-norepair", map[string]string{"alertname": "DiskFull", "host": "web1"})

	scripted := &scriptedLLM{responses: []scriptResp{
		{raw: draftResp(t, "draft", "disk pressure on web1", 0.8, []map[string]any{
			{"kind": "promql", "expr": issue62Repaired, "why": "would refute"},
			{"kind": "incidents_in_window", "why": "anything else?"},
		})},
		{raw: callTwoResp(t, "draft", "disk pressure on web1", 0.8, "")},
	}}

	prom, sent := promRecorder(t)
	skill := acutetriage.New(verifyConfig(prom), st, scripted, auditor, nil, nil)
	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if scripted.calls != 2 {
		t.Fatalf("calls = %d, want draft + re-judge only (a valid plan needs no repair)", scripted.calls)
	}
	if n := auditCount(t, st, "incident.verification_repair"); n != 0 {
		t.Errorf("verification_repair audit rows = %d, want 0 (nothing was repaired)", n)
	}
	ran := false
	for _, q := range sent() {
		if q == issue62Repaired {
			ran = true
		}
	}
	if !ran {
		t.Errorf("valid model query never reached Prometheus: %q", sent())
	}
}
