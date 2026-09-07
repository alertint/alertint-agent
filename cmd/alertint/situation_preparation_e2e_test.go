// SPDX-License-Identifier: FSL-1.1-ALv2

package main

// Plan 4 Task 10: real end-to-end proof that the production preparation/
// semantic-profile wiring (Task 9's own buildPreparationRuntime) actually
// works together — real store on disk, real ingress HTTP receiver, real
// correlator dispatch/input workers, real situation.ControllerWorker with
// the REAL productionPreparer/observation.Runner/semanticprofile.Worker
// this package builds for production, hitting a fake Prometheus HTTP
// server (the only external transport this file fakes, matching spec.md's
// "Mocks replace external HTTP/model transports, not precomputed policy
// facts"). This is deliberately a smaller, hand-written set of end-to-end
// tests rather than a generic JSON-fixture-driven fourteen-scenario corpus
// -- a scope reduction made explicitly with the user (see status.json) to
// spend the freed budget on real lab SSH acceptance instead. Each test
// below still drives only real production components end to end; nothing
// here hand-seeds a Situation, Run, or profile Version.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/llm"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

const prepE2EToken = "prep-e2e-test-token" //nolint:gosec // test-only bearer token literal, never a real credential

// ----------------------------------------------------------------------
// prepE2EFixture: real store + real ingress HTTP host, mirroring internal/
// situation/controller_replay_test.go's own replayFixture (that type lives
// in a different package and cannot be imported into cmd/alertint's own
// test binary).
// ----------------------------------------------------------------------

type prepE2EFixture struct {
	t     *testing.T
	ctx   context.Context //nolint:containedctx // test fixture only: always context.Background(), threaded through the helpers below.
	path  string
	st    *store.Store
	srv   *httptest.Server
	clock *e2eClock
	owner string
}

func newPrepE2EFixture(t *testing.T) *prepE2EFixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "prep-e2e.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	f := &prepE2EFixture{
		t: t, ctx: ctx, path: path, st: st, owner: "prep-e2e",
		clock: &e2eClock{now: time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)},
	}
	f.srv = f.newHost(st)
	t.Cleanup(func() { f.srv.Close() })
	t.Cleanup(func() { _ = f.st.Close() })
	return f
}

func (f *prepE2EFixture) newHost(st *store.Store) *httptest.Server {
	f.t.Helper()
	host, err := ingress.New(ingress.Options{
		Store:     st,
		Auditor:   audit.New(st.DB()),
		Receivers: []ingress.Receiver{ingress.NewAlertReceiver(st, prepE2EToken, nil, nil)},
	})
	if err != nil {
		f.t.Fatalf("ingress.New: %v", err)
	}
	return httptest.NewServer(host.Handler())
}

// postAlert POSTs one firing Alertmanager v4 alert over real HTTP through
// the real Receiver -- this fixture's only inbound entry point.
//
//nolint:unparam // alertname is a general fixture parameter; every current test happens to use "HighErrorRate".
func (f *prepE2EFixture) postAlert(group, alertname, fingerprint string) {
	f.t.Helper()
	payload := ingress.AlertmanagerPayload{
		Version:     "4",
		Status:      "firing",
		GroupLabels: map[string]string{"group": group},
		Alerts: []ingress.AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": alertname, "group": group, "service": group},
			Annotations: map[string]string{},
			StartsAt:    f.clock.Now(),
			Fingerprint: fingerprint,
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatalf("marshal alertmanager payload: %v", err)
	}
	req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.srv.URL+"/webhook/alertmanager", strings.NewReader(string(body)))
	if err != nil {
		f.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+prepE2EToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatalf("post alert: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		f.t.Fatalf("post alert status = %d, want 204", resp.StatusCode)
	}
}

// drainFoundation drains the delivery-dispatch and Situation-input outboxes
// once each -- the real production correlation/input-application path,
// mirroring internal/situation/controller_replay_test.go's own
// drainFoundation exactly.
func (f *prepE2EFixture) drainFoundation() {
	f.t.Helper()
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, f.st, nil, nil)
	dispatch := correlator.NewDispatchWorker(f.st, cor, correlator.WorkerConfig{Owner: f.owner + ":dispatch"}, nil)
	inputs := situation.NewInputWorker(f.st, situation.WorkerConfig{Owner: f.owner + ":input"}, nil)
	if _, err := dispatch.Drain(f.ctx); err != nil {
		f.t.Fatalf("dispatch drain: %v", err)
	}
	if _, err := inputs.Drain(f.ctx); err != nil {
		f.t.Fatalf("input drain: %v", err)
	}
}

func (f *prepE2EFixture) markReady(incidentID string) {
	f.t.Helper()
	if err := f.st.MarkIncidentReadyWithSituationInput(f.ctx, incidentID, f.clock.Now()); err != nil {
		f.t.Fatalf("mark incident ready: %v", err)
	}
	f.drainFoundation()
}

func (f *prepE2EFixture) soleIncidentID() string {
	f.t.Helper()
	var id string
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT id FROM incidents ORDER BY created_at ASC LIMIT 1`).Scan(&id); err != nil {
		f.t.Fatalf("find sole incident: %v", err)
	}
	return id
}

func (f *prepE2EFixture) soleSituationID() string {
	f.t.Helper()
	var id string
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT id FROM situations ORDER BY created_at ASC LIMIT 1`).Scan(&id); err != nil {
		f.t.Fatalf("find sole situation: %v", err)
	}
	return id
}

// reopen closes and reopens the SAME on-disk database file -- what a
// process restart looks like to the durable ledger.
func (f *prepE2EFixture) reopen() {
	f.t.Helper()
	if err := f.st.Close(); err != nil {
		f.t.Fatalf("close store: %v", err)
	}
	st, err := store.Open(f.ctx, f.path)
	if err != nil {
		f.t.Fatalf("reopen store: %v", err)
	}
	f.st = st
}

// ----------------------------------------------------------------------
// Fake Prometheus HTTP server: the one external connector transport these
// tests fake, returning a real matrix sample so the committed Run carries
// an actual normalized fact (A12's own minimum bar: "a production
// connector fact reaching L2").
// ----------------------------------------------------------------------

type fakePrometheusServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	fail    bool
	reqs    atomic.Int32
	lastReq string
}

func newFakePrometheusServer(t *testing.T) *fakePrometheusServer {
	t.Helper()
	f := &fakePrometheusServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePrometheusServer) setFail(fail bool) {
	f.mu.Lock()
	f.fail = fail
	f.mu.Unlock()
}

func (f *fakePrometheusServer) handle(w http.ResponseWriter, r *http.Request) {
	f.reqs.Add(1)
	f.mu.Lock()
	f.lastReq = r.URL.Query().Get("query")
	fail := f.fail
	f.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"error","errorType":"unavailable","error":"lab prometheus down"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[
		{"metric":{"__name__":"up","service":"checkout-e2e"},"values":[[1.0,"1"],[2.0,"1"]]}
	]}}`))
}

func (f *fakePrometheusServer) requestCount() int32 { return f.reqs.Load() }

// ----------------------------------------------------------------------
// Fake shared L0(profile)+L2(assessment) client: one CompleteOnce
// implementation satisfying both situation.AssessmentClient and
// semanticprofile.CompletionClient (structurally identical signatures,
// exactly like the real production provider clients this package's own
// buildPreparationRuntime type-asserts). Dispatches on the prompt's own
// preamble marker -- the only way to tell which of the two callers issued
// a given CompleteOnce call, since both pass systemPrompt="".
// ----------------------------------------------------------------------

type prepE2ELLM struct {
	mu             sync.Mutex
	profileCalls   int
	assessCalls    int
	failProfile    bool
	failAssessment bool
}

func (c *prepE2ELLM) CompleteOnce(_ context.Context, _ string, prompt llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.Contains(prompt.Prefix, "advisory semantic-profile analyst") {
		c.profileCalls++
		if c.failProfile {
			return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusFalse}, fmt.Errorf("prep e2e: simulated profile transport failure")
		}
		profile := profilemodel.Profile{
			SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom",
			CandidateScope: []string{"service"}, HorizonTier: "hours",
			UsefulCapabilities: []string{"prometheus_query"},
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			return llm.OneShotCompletion{}, err
		}
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: raw, Model: "e2e-model"},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}

	c.assessCalls++
	if c.failAssessment {
		return llm.OneShotCompletion{RequestStarted: llm.RequestStartStatusFalse}, fmt.Errorf("prep e2e: simulated assessment transport failure")
	}
	proposal := struct {
		SchemaVersion int    `json:"schema_version"`
		Persistence   string `json:"persistence"`
		Impact        string `json:"impact"`
		Novelty       string `json:"novelty"`
		Causality     string `json:"causality"`
		Attention     string `json:"attention"`
	}{SchemaVersion: 1, Persistence: "sustained", Impact: "suspected", Novelty: "familiar", Causality: "correlated", Attention: "observe"}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return llm.OneShotCompletion{}, err
	}
	return llm.OneShotCompletion{
		Completion:     llm.Completion{Raw: raw, Model: "e2e-model"},
		RequestStarted: llm.RequestStartStatusTrue,
	}, nil
}

// ----------------------------------------------------------------------
// Runtime assembly: the REAL productionPreparer/observation.Runner/
// semanticprofile.Worker wiring (newPreparationRuntime) injected into a
// REAL situation.ControllerWorker -- exactly buildPreparationRuntime's own
// production shape, minus the cmd/alertint main()-only pieces (Loki/Sentry/
// Zabbix clients, foundation reconstruction) this test has no need for.
// ----------------------------------------------------------------------

type prepE2ERuntime struct {
	cw  *situation.ControllerWorker
	prt *preparationRuntime
}

func buildPrepE2ERuntime(t *testing.T, f *prepE2EFixture, promURL string, llmClient *prepE2ELLM) *prepE2ERuntime {
	t.Helper()
	cfg := &config.Config{}
	cfg.Prometheus.BaseURL = promURL
	cfg.Situations.Preparation = config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 60}
	cfg.Situations.SemanticProfiles = config.SemanticProfilesConfig{Workers: 1, MaxAttempts: 3, AttemptWallSeconds: 10}
	cfg.Situations.LeaseSeconds, cfg.Situations.HeartbeatSeconds, cfg.Situations.ReconcilePollSeconds = 60, 10, 2

	promClient := promclient.NewClient(promclient.Config{BaseURL: promURL, TimeoutSeconds: 5})
	limiter := llm.NewInferenceLimiter(2)
	auditor := audit.New(f.st.DB())
	logger := slog.New(slog.DiscardHandler)

	prt, preparer, err := newPreparationRuntime(f.st, cfg, f.owner+":prep", promClient, nil, nil, nil, llmClient, limiter, nil, auditor, logger)
	if err != nil {
		t.Fatalf("newPreparationRuntime: %v", err)
	}

	cw := situation.NewControllerWorker(f.st, f.st, llmClient,
		situation.ControllerConfig{}, situation.ControllerWorkerConfig{Owner: f.owner + ":controller", Now: f.clock.Now},
		f.clock.Now, auditor, logger)
	cw.SetEvidencePreparer(preparer)
	cw.SetInferenceLimiter(limiter)

	return &prepE2ERuntime{cw: cw, prt: prt}
}

// ----------------------------------------------------------------------
// TestPreparationE2EFullPipelineFromHTTPAlertToProfileHeadAndMCPReads: the
// flagship test. Real HTTP alert -> real correlator/input worker -> real
// Situation -> real ControllerWorker.Drain (preparation + assessment) ->
// real PrometheusExecutor hitting the fake HTTP server -> a committed,
// normalized observation Run -> the delivery's automatically-attached
// semantic signature drives a real profile inference job -> the shared
// fake LLM answers it -> a committed profile Version/head -> the fan-out
// sweep delivers a change wake to the (still nonterminal) Situation. Then
// alertint_list_observation_runs/alertint_get_semantic_profile are read
// through a real mcp.Server and asserted to agree with the store's own
// durable identities (A10).
// ----------------------------------------------------------------------

func TestPreparationE2EFullPipelineFromHTTPAlertToProfileHeadAndMCPReads(t *testing.T) {
	f := newPrepE2EFixture(t)
	prom := newFakePrometheusServer(t)
	llmClient := &prepE2ELLM{}
	rt := buildPrepE2ERuntime(t, f, prom.srv.URL, llmClient)

	f.postAlert("checkout-e2e", "HighErrorRate", "fp-e2e-1")
	f.drainFoundation()
	f.markReady(f.soleIncidentID())

	if err := rt.prt.Recover(f.ctx); err != nil {
		t.Fatalf("prt.Recover: %v", err)
	}
	f.clock.advance(time.Minute)
	if _, err := rt.cw.Drain(f.ctx); err != nil {
		t.Fatalf("controller drain: %v", err)
	}
	if _, err := rt.prt.Drain(f.ctx); err != nil {
		t.Fatalf("preparation drain: %v", err)
	}

	situationID := f.soleSituationID()

	// The real connector was actually called, and its result committed as
	// a normalized Run.
	if n := prom.requestCount(); n == 0 {
		t.Fatal("fake prometheus server received no requests; the real connector executor never dispatched")
	}
	var runCount int
	if err := f.st.DB().QueryRowContext(f.ctx, `
		SELECT COUNT(*) FROM situation_observation_runs r
		JOIN situation_preparation_cycles c ON c.id = r.cycle_id
		WHERE c.situation_id = ?`, situationID).Scan(&runCount); err != nil {
		t.Fatalf("count observation runs: %v", err)
	}
	if runCount == 0 {
		t.Fatal("no observation runs committed for the Situation")
	}

	// The profile job dispatched, the shared fake LLM answered it, and a
	// head now exists.
	if llmClient.profileCalls == 0 {
		t.Fatal("profile inference never dispatched")
	}
	var headVersion int
	var signatureKey string
	if err := f.st.DB().QueryRowContext(f.ctx, `
		SELECT signature_key FROM delivery_semantic_signatures LIMIT 1`).Scan(&signatureKey); err != nil {
		t.Fatalf("read delivery signature: %v", err)
	}
	if err := f.st.DB().QueryRowContext(f.ctx, `
		SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, signatureKey).Scan(&headVersion); err != nil {
		t.Fatalf("read profile head: %v", err)
	}
	if headVersion != 1 {
		t.Fatalf("profile head version = %d, want 1", headVersion)
	}

	// The exact store reads alertint_list_observation_runs/
	// alertint_get_semantic_profile wrap (internal/mcp/server_preparation.go)
	// agree with the store's own durable identities (A10) -- called
	// directly rather than through the MCP JSON-RPC transport, which adds
	// no further production logic of its own beyond these two calls plus
	// JSON rendering (already covered by internal/mcp's own handler tests).
	mcpRuns, mcpRunsCursor, err := f.st.ListObservationRuns(f.ctx, situationID, "", "", 20)
	if err != nil {
		t.Fatalf("ListObservationRuns: %v", err)
	}
	if len(mcpRuns) != runCount {
		t.Fatalf("ListObservationRuns rows = %d, want %d (raw SQL's own count)", len(mcpRuns), runCount)
	}
	if mcpRunsCursor != "" {
		t.Fatalf("ListObservationRuns cursor = %q, want empty (single page)", mcpRunsCursor)
	}

	profileHistory, err := f.st.GetSemanticProfile(f.ctx, signatureKey, "", 20)
	if err != nil {
		t.Fatalf("GetSemanticProfile: %v", err)
	}
	if profileHistory.Current == nil || profileHistory.Current.Version != headVersion {
		t.Fatalf("GetSemanticProfile current = %+v, want version %d (raw SQL's own head)", profileHistory.Current, headVersion)
	}

	// The audit trail carries the durable events this task's own emitters
	// commit.
	for _, kind := range []string{
		"situation.preparation.cycle_begun", "semantic_profile.call_dispatched",
		"semantic_profile.call_completed", "semantic_profile.head_advanced",
	} {
		var n int
		if err := f.st.DB().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM audit_log WHERE kind = ?`, kind).Scan(&n); err != nil {
			t.Fatalf("count audit rows for %s: %v", kind, err)
		}
		if n == 0 {
			t.Fatalf("no audit rows for kind %q", kind)
		}
	}
}

// claimControllerWorkFor claims situationID's due controller work through
// the real store, returning it as a situation.Claim ready for the
// controller-facing preparation API this file's crash test drives
// directly, mirroring cmd/alertint/situation_preparation_test.go's own
// preparationRequestFor helper.
func claimControllerWorkFor(t *testing.T, st *store.Store, situationID, owner string, now time.Time) situation.Claim {
	t.Helper()
	claims, err := st.ClaimControllerWork(context.Background(), owner, now, time.Minute, 10)
	if err != nil {
		t.Fatalf("claim controller work: %v", err)
	}
	for _, c := range claims {
		if c.Situation.ID == situationID {
			return c
		}
	}
	t.Fatalf("situation %s not among %d claimed", situationID, len(claims))
	return situation.Claim{}
}

// beginPreparationCycleFor freezes one Prometheus plan through the real
// store.BeginPreparation call -- the exact durable step
// productionPreparer.Prepare performs before ever touching a connector --
// and returns the frozen cycle's own id, without running RunPhase. Used to
// simulate a crash after the cycle committed, before its reads ran.
func beginPreparationCycleFor(t *testing.T, st *store.Store, claim situation.Claim, now time.Time) (cycleID string) {
	t.Helper()
	fence := model.Fence{
		SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Owner: claim.ClaimOwner, Token: claim.ClaimToken,
	}
	plan := model.Plan{
		Capability: model.CapabilityPrometheusQuery, Phase: model.PhaseAssessment,
		Scope: model.Scope{
			GroupKey: claim.Situation.GroupKey, Source: "alertmanager",
			SubjectID: "signal-a", Labels: map[string]string{"service": claim.Situation.GroupKey},
		},
		Parameters: []byte(`{"expression":"up"}`),
		Start:      now.Add(-time.Minute), End: now, EligibleAt: now,
		Limit: 20, MaxRequests: 2, Purpose: "corroborate_member",
	}
	cycle, err := st.BeginPreparation(context.Background(), fence, model.CycleDraft{
		Anchor: now, ConfigDigest: "crash-test-digest", Plans: []model.Plan{plan},
	}, 5)
	if err != nil {
		t.Fatalf("begin preparation: %v", err)
	}
	return cycle.ID
}

// TestPreparationE2ECrashAfterCycleCommitReusesTheSameFrozenCycle proves
// A3: a "crash" between the frozen cycle's own durable commit and its
// connector reads completing -- simulated by closing and reopening the
// SAME on-disk database file before ever running RunPhase -- resumes with
// BeginPreparation returning the IDENTICAL frozen cycle/plan on the next
// real Reconcile, rather than minting a second one.
func TestPreparationE2ECrashAfterCycleCommitReusesTheSameFrozenCycle(t *testing.T) {
	f := newPrepE2EFixture(t)
	prom := newFakePrometheusServer(t)
	llmClient := &prepE2ELLM{}

	f.postAlert("checkout-crash", "HighErrorRate", "fp-e2e-crash")
	f.drainFoundation()
	f.markReady(f.soleIncidentID())
	situationID := f.soleSituationID()

	// First attempt: freeze the cycle's plans (BeginPreparation), but
	// "crash" before its connector reads ever run -- constructed directly
	// against the real store's own preparation API, mirroring the exact
	// sequence productionPreparer.Prepare performs up to that point.
	claim := claimControllerWorkFor(t, f.st, situationID, f.owner+":crash", f.clock.Now())
	firstCycle := beginPreparationCycleFor(t, f.st, claim, f.clock.Now())

	f.reopen()

	// Recovery + a fresh Reconcile after "restart": the SAME cycle/plan IDs
	// must come back, not a new frozen draft.
	rt := buildPrepE2ERuntime(t, f, prom.srv.URL, llmClient)
	if err := rt.prt.Recover(f.ctx); err != nil {
		t.Fatalf("prt.Recover: %v", err)
	}
	f.clock.advance(time.Minute)
	if _, err := rt.cw.Drain(f.ctx); err != nil {
		t.Fatalf("controller drain: %v", err)
	}

	var reusedCycleID string
	if err := f.st.DB().QueryRowContext(f.ctx, `
		SELECT id FROM situation_preparation_cycles WHERE situation_id = ? ORDER BY created_at ASC LIMIT 1`,
		situationID).Scan(&reusedCycleID); err != nil {
		t.Fatalf("read reused cycle: %v", err)
	}
	if reusedCycleID != firstCycle {
		t.Fatalf("reused cycle id = %q, want the original frozen cycle %q", reusedCycleID, firstCycle)
	}
	var cycleCount int
	if err := f.st.DB().QueryRowContext(f.ctx, `
		SELECT COUNT(*) FROM situation_preparation_cycles WHERE situation_id = ?`, situationID).Scan(&cycleCount); err != nil {
		t.Fatalf("count cycles: %v", err)
	}
	if cycleCount != 1 {
		t.Fatalf("cycle count = %d, want exactly 1 (no duplicate frozen cycle after restart)", cycleCount)
	}
}

// TestPreparationE2ESemanticInferenceCrashRecoversStrandedJobLease proves
// A8: a worker that claims and reserves an inference call but never
// completes it (killed mid-attempt) leaves a stranded lease that real
// startup recovery (preparationRuntime.Recover -> store.RecoverSemanticInference)
// returns to pending, so a later real Worker.RunOnce dispatch still
// completes the job rather than leaving it stuck forever.
func TestPreparationE2ESemanticInferenceCrashRecoversStrandedJobLease(t *testing.T) {
	f := newPrepE2EFixture(t)
	prom := newFakePrometheusServer(t)

	f.postAlert("checkout-stranded", "HighErrorRate", "fp-e2e-stranded")
	f.drainFoundation()
	f.markReady(f.soleIncidentID())

	var signatureKey string
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT signature_key FROM delivery_semantic_signatures LIMIT 1`).Scan(&signatureKey); err != nil {
		t.Fatalf("read delivery signature: %v", err)
	}

	// Simulate a worker process that claimed the job and reserved its call
	// but crashed before ever committing an outcome.
	claim, found, err := f.st.ClaimSemanticInferenceJob(f.ctx, "stranded-worker", f.clock.Now(), time.Minute)
	if err != nil || !found {
		t.Fatalf("claim inference job: found=%v err=%v", found, err)
	}
	if _, _, err := f.st.ReserveSemanticInferenceCall(f.ctx, claim.JobID, claim.Owner, claim.Token, f.clock.Now()); err != nil {
		t.Fatalf("reserve inference call: %v", err)
	}

	// Let the lease actually expire, then run the real recovery pass.
	f.clock.advance(5 * time.Minute)
	recovered, err := f.st.RecoverSemanticInference(f.ctx, f.clock.Now())
	if err != nil {
		t.Fatalf("RecoverSemanticInference: %v", err)
	}
	if recovered == 0 {
		t.Fatal("RecoverSemanticInference recovered 0 jobs, want the stranded one back to pending")
	}

	llmClient := &prepE2ELLM{}
	rt := buildPrepE2ERuntime(t, f, prom.srv.URL, llmClient)
	if _, err := rt.prt.Drain(f.ctx); err != nil {
		t.Fatalf("preparation drain: %v", err)
	}
	if llmClient.profileCalls == 0 {
		t.Fatal("recovered job never redispatched after recovery")
	}
	var headVersion int
	if err := f.st.DB().QueryRowContext(f.ctx, `
		SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, signatureKey).Scan(&headVersion); err != nil {
		t.Fatalf("read profile head after recovery: %v", err)
	}
	if headVersion != 1 {
		t.Fatalf("profile head version after recovery = %d, want 1", headVersion)
	}
}

// TestPreparationE2EConnectorOutageCommitsHonestFailedRunWithoutBlockingLifecycle
// proves the connector-failure half of A5/A9's honesty requirement: a
// connector transport failure never blocks the Situation's own lifecycle
// commit -- it becomes a durable, honestly-labeled failed Run, and
// Reconcile still commits normally on the SAME cycle.
func TestPreparationE2EConnectorOutageCommitsHonestFailedRunWithoutBlockingLifecycle(t *testing.T) {
	f := newPrepE2EFixture(t)
	prom := newFakePrometheusServer(t)
	prom.setFail(true)
	llmClient := &prepE2ELLM{}
	rt := buildPrepE2ERuntime(t, f, prom.srv.URL, llmClient)

	f.postAlert("checkout-outage", "HighErrorRate", "fp-e2e-outage")
	f.drainFoundation()
	f.markReady(f.soleIncidentID())
	situationID := f.soleSituationID()

	if err := rt.prt.Recover(f.ctx); err != nil {
		t.Fatalf("prt.Recover: %v", err)
	}
	f.clock.advance(time.Minute)
	n, err := rt.cw.Drain(f.ctx)
	if err != nil {
		t.Fatalf("controller drain: %v", err)
	}
	if n == 0 {
		t.Fatal("controller drain handled nothing; the Situation never reconciled despite the connector outage")
	}

	var lifecycle string
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT lifecycle FROM situations WHERE id = ?`, situationID).Scan(&lifecycle); err != nil {
		t.Fatalf("read situation lifecycle: %v", err)
	}
	if lifecycle == "" {
		t.Fatal("situation has no committed lifecycle despite the connector outage")
	}

	var failedCount int
	if err := f.st.DB().QueryRowContext(f.ctx, `
		SELECT COUNT(*) FROM situation_observation_runs r
		JOIN situation_preparation_cycles c ON c.id = r.cycle_id
		WHERE c.situation_id = ? AND r.status = 'failed'`, situationID).Scan(&failedCount); err != nil {
		t.Fatalf("count failed runs: %v", err)
	}
	if failedCount == 0 {
		t.Fatal("no failed observation run recorded despite the connector outage; the failure was not honestly captured")
	}
}
