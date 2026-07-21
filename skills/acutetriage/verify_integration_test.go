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
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/store"
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
	want := acutetriage.UserPrompt(pack, string(mustJSON(t, pack)), nil, nil, nil, nil, nil, acutetriage.VerificationParams{})
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
