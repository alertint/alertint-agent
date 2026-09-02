// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// controllerRuntime construction
// ----------------------------------------------------------------------

func TestSituationControllerRuntimePanicsOnEmptyOwner(t *testing.T) {
	st := newTestFoundationStore(t)
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for an empty owner")
		}
	}()
	newControllerRuntime(st, &fakeOneShotClient{}, nil, config.SituationsConfig{}, "  ", nil, nil)
}

// TestSituationsConfigToControllerConfigMapsEveryField pins Task 8's own
// documented mapping (Task 8 report) exactly, field for field.
func TestSituationsConfigToControllerConfigMapsEveryField(t *testing.T) {
	cfg := config.SituationsConfig{
		Workers:                     4,
		ReconcilePollSeconds:        2,
		LeaseSeconds:                301,
		HeartbeatSeconds:            31,
		WebhookRecoveryGraceSeconds: 121,
		MaxL2CallsPerAttempt:        2,
		MaxWorkAttemptsPerInput:     5,
		AttemptWallSeconds:          181,
		LLMConcurrency:              3,
		Retry: config.SituationsRetryConfig{
			MinSeconds:    6,
			MaxSeconds:    301,
			JitterPercent: 21,
		},
	}
	controllerCfg, workerCfg := situationsConfigToControllerConfig(cfg, "owner-1")

	if controllerCfg.MaxL2CallsPerAttempt != 2 || controllerCfg.MaxWorkAttemptsPerInput != 5 {
		t.Fatalf("controllerCfg budgets = %+v", controllerCfg)
	}
	if controllerCfg.AttemptWall != 181*time.Second {
		t.Fatalf("AttemptWall = %v, want 181s", controllerCfg.AttemptWall)
	}
	if controllerCfg.WebhookRecoveryGrace != 121*time.Second {
		t.Fatalf("WebhookRecoveryGrace = %v, want 121s", controllerCfg.WebhookRecoveryGrace)
	}
	if controllerCfg.Retry.Min != 6*time.Second || controllerCfg.Retry.Max != 301*time.Second || controllerCfg.Retry.JitterPercent != 21 {
		t.Fatalf("Retry = %+v", controllerCfg.Retry)
	}
	// PollingIntervalSeconds has no config.SituationsConfig source — must
	// stay at its zero-value default (ControllerConfig's own doc comment).
	if controllerCfg.PollingIntervalSeconds != 0 {
		t.Fatalf("PollingIntervalSeconds = %d, want 0 (no source in this build)", controllerCfg.PollingIntervalSeconds)
	}

	if workerCfg.Owner != "owner-1:controller" {
		t.Fatalf("workerCfg.Owner = %q, want owner-1:controller", workerCfg.Owner)
	}
	if workerCfg.Lease != 301*time.Second || workerCfg.Heartbeat != 31*time.Second || workerCfg.Interval != 2*time.Second {
		t.Fatalf("workerCfg lease/heartbeat/interval = %v/%v/%v", workerCfg.Lease, workerCfg.Heartbeat, workerCfg.Interval)
	}
	if workerCfg.Workers != 4 {
		t.Fatalf("workerCfg.Workers = %d, want 4", workerCfg.Workers)
	}
	if workerCfg.L2Concurrency != 3 {
		t.Fatalf("workerCfg.L2Concurrency = %d, want 3", workerCfg.L2Concurrency)
	}
}

// ----------------------------------------------------------------------
// controllerRuntime.RecoverAndBackfill / Start / Drain / Stop, against a
// real (empty) store — proves the plumbing runs cleanly with nothing due,
// mirroring situation_foundation_test.go's own light-integration style.
// ----------------------------------------------------------------------

func TestSituationControllerRuntimeRecoverAndBackfillOnEmptyStoreIsANoOp(t *testing.T) {
	st := newTestFoundationStore(t)
	rt := newControllerRuntime(st, &fakeOneShotClient{}, nil, config.SituationsConfig{}, "test-owner", nil, nil)

	report, err := rt.RecoverAndBackfill(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("RecoverAndBackfill: %v", err)
	}
	if report.TriageBackfilled != 0 || report.AssessmentCallsRecovered != 0 ||
		report.TriageAttemptsRecovered != 0 || report.TriageStartupHorizonExhausted != 0 {
		t.Fatalf("report = %+v, want all zero on an empty store", report)
	}
}

func TestSituationControllerRuntimeStartDrainStop(t *testing.T) {
	st := newTestFoundationStore(t)
	cfg := config.SituationsConfig{ReconcilePollSeconds: 3600, LeaseSeconds: 300, HeartbeatSeconds: 30}
	rt := newControllerRuntime(st, &fakeOneShotClient{}, nil, cfg, "test-owner", nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.Start(ctx)

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	if err := rt.Drain(drainCtx); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := rt.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// ----------------------------------------------------------------------
// buildAssessmentClient
// ----------------------------------------------------------------------

// fakeOneShotClient implements both acutetriage.LLMClient's Complete (the
// ordinary retry-capable method) and situation.AssessmentClient's
// CompleteOnce, structurally — mirroring the concrete llm/anthropic and
// llm/openaicompat clients this build actually configures.
type fakeOneShotClient struct {
	completeOnceCalls int
	completeOnceErr   error
}

func (c *fakeOneShotClient) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	return llm.Completion{}, nil
}

func (c *fakeOneShotClient) CompleteOnce(context.Context, string, llm.Prompt, []string) (llm.OneShotCompletion, error) {
	c.completeOnceCalls++
	return llm.OneShotCompletion{}, c.completeOnceErr
}

// completeOnlyClient implements ONLY Complete — a client type that (if this
// build ever configured one) could not back the Situation controller's own
// L2 dispatch.
type completeOnlyClient struct{}

func (completeOnlyClient) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	return llm.Completion{}, nil
}

func newTestTracker(t *testing.T) *llmhealth.Tracker {
	t.Helper()
	st := newTestFoundationStore(t)
	tracker, err := llmhealth.New(context.Background(), st, llmhealth.Options{})
	if err != nil {
		t.Fatalf("llmhealth.New: %v", err)
	}
	return tracker
}

func TestBuildAssessmentClientRejectsClientWithoutCompleteOnce(t *testing.T) {
	_, err := buildAssessmentClient(completeOnlyClient{}, newTestTracker(t))
	if err == nil {
		t.Fatal("expected an error for a client lacking CompleteOnce")
	}
}

// TestBuildAssessmentClientObservesEveryCallInInstallationLLMHealth proves
// the wrapped client reports its outcome to the installation LLM-health
// tracker under CapabilityAssessment — the L2 sibling of Acute Triage's own
// already-wired L1 (CapabilityTriageDraft) observations.
func TestBuildAssessmentClientObservesEveryCallInInstallationLLMHealth(t *testing.T) {
	inner := &fakeOneShotClient{}
	tracker := newTestTracker(t)
	client, err := buildAssessmentClient(inner, tracker)
	if err != nil {
		t.Fatalf("buildAssessmentClient: %v", err)
	}

	if _, err := client.CompleteOnce(context.Background(), "", llm.Prompt{}, nil); err != nil {
		t.Fatalf("CompleteOnce: %v", err)
	}
	if inner.completeOnceCalls != 1 {
		t.Fatalf("inner CompleteOnce calls = %d, want 1", inner.completeOnceCalls)
	}

	snap := tracker.Snapshot()
	found := false
	for _, c := range snap.Capabilities {
		if c.Capability == llmhealth.CapabilityAssessment {
			found = true
			if !c.Healthy {
				t.Fatalf("capability %q healthy = false after a successful call", c.Capability)
			}
		}
	}
	if !found {
		t.Fatalf("capabilities = %+v, want an entry for %q", snap.Capabilities, llmhealth.CapabilityAssessment)
	}
}

// TestBuildAssessmentClientTreatsATransportFailureAsDependencyUnhealthy
// proves a genuine transport failure IS observed as a dependency failure —
// the counterpart proof to controller.go's own "a late/stale completion
// race is stale, not a provider failure": here, a REAL failure (the wrapped
// CompleteOnce call itself returning an error) is correctly NOT swallowed.
func TestBuildAssessmentClientTreatsATransportFailureAsDependencyUnhealthy(t *testing.T) {
	inner := &fakeOneShotClient{completeOnceErr: errors.New("dial tcp: connection refused")}
	tracker := newTestTracker(t)
	client, err := buildAssessmentClient(inner, tracker)
	if err != nil {
		t.Fatalf("buildAssessmentClient: %v", err)
	}

	if _, err := client.CompleteOnce(context.Background(), "", llm.Prompt{}, nil); err == nil {
		t.Fatal("expected CompleteOnce to propagate the inner transport error")
	}

	snap := tracker.Snapshot()
	if snap.State == llmhealth.StateHealthy {
		t.Fatalf("installation LLM health state = %q, want degraded/unavailable after a transport failure", snap.State)
	}
}

// ----------------------------------------------------------------------
// llmHealthDependencyWaker
// ----------------------------------------------------------------------

func TestLLMHealthDependencyWakerNoOpsWhenNotHealthy(t *testing.T) {
	st := newTestFoundationStore(t)
	tracker, err := llmhealth.New(context.Background(), st, llmhealth.Options{})
	if err != nil {
		t.Fatalf("llmhealth.New: %v", err)
	}
	// Force unhealthy: a dependency-class failure.
	tracker.Begin(llmhealth.CapabilityAssessment, "").Finish(errors.New("dial tcp: connection refused"))
	if tracker.Snapshot().State == llmhealth.StateHealthy {
		t.Fatal("test setup: expected an unhealthy tracker after a dependency failure")
	}

	waker := llmHealthDependencyWaker{tracker: tracker, st: st}
	n, err := waker.WakeDependencyRecoveredSituations(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("WakeDependencyRecoveredSituations: %v", err)
	}
	if n != 0 {
		t.Fatalf("woke = %d, want 0 while not healthy", n)
	}
}

// TestLLMHealthDependencyWakerWakesParkedSituationsWhenHealthy drives a
// real outage-then-recovery cycle through the tracker (so OutageGeneration
// is genuinely > 0), seeds a real Situation parked on
// ParkedReasonDependency, and proves the waker's own delegation to
// store.WakeDependencyRecoveredSituations actually clears it.
func TestLLMHealthDependencyWakerWakesParkedSituationsWhenHealthy(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	sitID := seedControllerRuntimeSituation(t, st, "group-waker", now)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE situations SET controller_parked_at = ?, controller_parked_reason = ?
		WHERE id = ?`, now.UTC().Format(time.RFC3339Nano), situation.ParkedReasonDependency, sitID); err != nil {
		t.Fatal(err)
	}

	tracker, err := llmhealth.New(context.Background(), st, llmhealth.Options{})
	if err != nil {
		t.Fatalf("llmhealth.New: %v", err)
	}
	// Outage, then recovery: OutageGeneration increments on the outage.
	tracker.Begin(llmhealth.CapabilityAssessment, "").Finish(errors.New("dial tcp: connection refused"))
	tracker.Begin(llmhealth.CapabilityAssessment, "").Finish(nil)
	snap := tracker.Snapshot()
	if snap.State != llmhealth.StateHealthy {
		t.Fatalf("tracker state = %q, want healthy after recovery", snap.State)
	}
	if snap.OutageGeneration == 0 {
		t.Fatal("test setup: expected a nonzero outage generation after an outage")
	}

	waker := llmHealthDependencyWaker{tracker: tracker, st: st}
	n, err := waker.WakeDependencyRecoveredSituations(context.Background(), now)
	if err != nil {
		t.Fatalf("WakeDependencyRecoveredSituations: %v", err)
	}
	if n != 1 {
		t.Fatalf("woke = %d, want 1", n)
	}

	var parkedReason *string
	if err := st.DB().QueryRowContext(context.Background(), `SELECT controller_parked_reason FROM situations WHERE id = ?`, sitID).Scan(&parkedReason); err != nil {
		t.Fatal(err)
	}
	if parkedReason != nil {
		t.Fatalf("controller_parked_reason = %v, want cleared (NULL) after the wake", *parkedReason)
	}
}

// ----------------------------------------------------------------------
// triage store/lister adapters
// ----------------------------------------------------------------------

func TestMapTriageStoreErrorMapsEveryKnownSentinel(t *testing.T) {
	cases := []struct {
		in   error
		want error
	}{
		{store.ErrTriageNotDue, situation.ErrTriageAttemptNotDue},
		{store.ErrTriageNotDecided, situation.ErrTriageAttemptNotDecided},
		{store.ErrTriageAttemptLeaseLost, situation.ErrTriageAttemptLeaseLost},
		{store.ErrTriageAttemptCompletedDifferently, situation.ErrTriageAttemptCompletedDifferently},
	}
	for _, tc := range cases {
		if got := mapTriageStoreError(tc.in); !errors.Is(got, tc.want) {
			t.Fatalf("mapTriageStoreError(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	other := errors.New("some other store error")
	if got := mapTriageStoreError(other); !errors.Is(got, other) {
		t.Fatalf("mapTriageStoreError(unmapped) = %v, want passthrough of %v", got, other)
	}
}

func TestTriageScheduleListerAdapterProjectsIncidentIDs(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	seedControllerRuntimeSituation(t, st, "group-lister", now)
	incID := "inc-group-lister"
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, next_at, updated_at)
		VALUES (?, 'pending', 0, ?, ?)`,
		incID, now.Add(-time.Minute).UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	adapter := &triageScheduleListerAdapter{Store: st}
	ids, err := adapter.ListDueIncidentTriage(context.Background(), now)
	if err != nil {
		t.Fatalf("ListDueIncidentTriage: %v", err)
	}
	if len(ids) != 1 || ids[0] != incID {
		t.Fatalf("ids = %v, want [%s]", ids, incID)
	}
}

// ----------------------------------------------------------------------
// RecoverAndBackfill's own startup-horizon audit emission (Task 9 fix
// round, Finding #2).
// ----------------------------------------------------------------------

// auditRecordEntry is one Append call fakeControllerRuntimeAuditSink
// observed.
type auditRecordEntry struct {
	actor, kind string
	payload     any
}

// fakeControllerRuntimeAuditSink implements situation.AuditSink for this
// file's own controllerRuntime-level tests — controller_audit_test.go's
// fakeAuditSink (package situation_test) is not reachable from here.
type fakeControllerRuntimeAuditSink struct {
	records []auditRecordEntry
}

func (s *fakeControllerRuntimeAuditSink) Append(_ context.Context, actor, kind string, payload any) error {
	s.records = append(s.records, auditRecordEntry{actor: actor, kind: kind, payload: payload})
	return nil
}

func (s *fakeControllerRuntimeAuditSink) payloadsOfKind(kind string) []any {
	var out []any
	for _, r := range s.records {
		if r.kind == kind {
			out = append(out, r.payload)
		}
	}
	return out
}

// TestSituationControllerRuntimeRecoverAndBackfillAuditsStartupHorizonExhaustion
// proves a real startup-horizon exhaustion (Task 9's new
// ExhaustOverdueUnclaimedIncidentTriage primitive, internal/store/
// triage_controller.go) produces a real incident.triage_exhausted audit row
// — restoring the operator-visible signal the deleted pre-Plan-2
// applyStartupHorizon/exhaustTriage produced, which the new primitive had
// none of at all before this fix (Task 9 fix round, Finding #2). Seeds a
// genuine overdue pending row against a real store (never a hand-built
// fixture standing in for one), so this exercises the exact
// RecoverAndBackfill -> ExhaustOverdueUnclaimedIncidentTriage ->
// auditStartupHorizonExhaustions path production runs at boot.
func TestSituationControllerRuntimeRecoverAndBackfillAuditsStartupHorizonExhaustion(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	sitID := seedControllerRuntimeSituation(t, st, "group-horizon-audit", now)
	incID := "inc-group-horizon-audit"

	// A pending row more than the one-hour startup horizon overdue, with
	// situation_id already set — mirrors what
	// BackfillUpgradedIncidentTriageSchedule guarantees is already true by
	// the time RecoverAndBackfill calls ExhaustOverdueUnclaimedIncidentTriage
	// in its own startup sequence.
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO incident_triage (incident_id, phase, attempts, next_at, situation_id, updated_at)
		VALUES (?, 'pending', 2, ?, ?, ?)`,
		incID, now.Add(-2*time.Hour).UTC().Format(time.RFC3339Nano), sitID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	audit := &fakeControllerRuntimeAuditSink{}
	rt := newControllerRuntime(st, &fakeOneShotClient{}, nil, config.SituationsConfig{}, "test-owner", audit, nil)

	report, err := rt.RecoverAndBackfill(context.Background(), now)
	if err != nil {
		t.Fatalf("RecoverAndBackfill: %v", err)
	}
	if report.TriageStartupHorizonExhausted != 1 {
		t.Fatalf("TriageStartupHorizonExhausted = %d, want 1", report.TriageStartupHorizonExhausted)
	}

	rows := audit.payloadsOfKind("incident.triage_exhausted")
	if len(rows) != 1 {
		t.Fatalf("incident.triage_exhausted audit rows = %d, want exactly 1: %+v", len(rows), audit.records)
	}
	payload, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("payload type = %T", rows[0])
	}
	if payload["incident_id"] != incID {
		t.Fatalf("incident_id = %v, want %v", payload["incident_id"], incID)
	}
	if payload["situation_id"] != sitID {
		t.Fatalf("situation_id = %v, want %v", payload["situation_id"], sitID)
	}
	if payload["reason"] != "startup_retry_window_expired" {
		t.Fatalf("reason = %v, want startup_retry_window_expired", payload["reason"])
	}
	if payload["code"] != "startup_retry_window_expired" {
		t.Fatalf("code = %v, want startup_retry_window_expired", payload["code"])
	}
	if payload["attempts"] != 2 {
		t.Fatalf("attempts = %v, want 2", payload["attempts"])
	}
}

// seedControllerRuntimeSituation seeds one fresh Situation for groupKey via
// a real Incident + situation_input_outbox round trip (mirrors internal/
// store's own test fixtures), returning its id. incidentID is always
// "inc-"+groupKey.
func seedControllerRuntimeSituation(t *testing.T, st *store.Store, groupKey string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	incID := "inc-" + groupKey
	if err := st.InsertIncident(ctx, store.Incident{
		ID: incID, GroupKey: groupKey,
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, incID); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}
	inputID := "input-" + groupKey
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, 'incident_created', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incID, groupKey, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert situation input: %v", err)
	}
	claims, err := st.ClaimSituationInputs(ctx, "seed:"+groupKey, now, time.Minute, 1)
	if err != nil {
		t.Fatalf("claim situation input: %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("claimed = %d, want 1", len(claims))
	}
	if err := st.ApplySituationInput(ctx, claims[0]); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}
	var sitID string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&sitID); err != nil {
		t.Fatalf("find situation: %v", err)
	}
	return sitID
}
