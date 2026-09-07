// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// seedDeliveredSituation accepts one real Delivery (store.AcceptDeliveries)
// and attaches it to a fresh Situation via the real membership_changed
// situation-input path (mirrors internal/store's own
// signatureDeliveryFixture/insertIncidentAndDeliveryInput test fixtures) so
// productionPreparer.Prepare has at least one real member to plan for.
func seedDeliveredSituation(t *testing.T, st *store.Store, id, groupKey string, now time.Time) (deliveryID, situationID string) {
	t.Helper()
	ctx := context.Background()
	deliveryID = "delivery-" + id
	del := store.DeliveryInput{
		ID: deliveryID,
		Alert: store.Alert{
			ID: "alert-" + id, Fingerprint: "fp-" + id, Status: "firing",
			Labels:      map[string]string{"alertname": "test", "service": "checkout"},
			Annotations: map[string]string{"summary": "test alert"},
			StartsAt:    now, ReceivedAt: now,
		},
		Source:                   "alertmanager",
		SourceEpisodeKey:         "alertmanager:fp-" + id + ":" + now.UTC().Format(time.RFC3339Nano),
		StartedAtBasis:           situationmodel.SourceTimeBasisSourcePayload,
		ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "group:fp-" + id,
		PayloadDigest:            "sha256:" + id,
		SourceProvenance:         store.SourceProvenance{AcquisitionMode: store.SourceAcquisitionWebhook},
	}
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{del}); err != nil {
		t.Fatalf("accept delivery %s: %v", deliveryID, err)
	}

	incID, inputID := "inc-"+id, "input-"+id
	if err := st.InsertIncident(ctx, store.Incident{
		ID: incID, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident %s: %v", incID, err)
	}
	if err := st.MarkIncidentReady(ctx, incID); err != nil {
		t.Fatalf("mark incident %s ready: %v", incID, err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incID, deliveryID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("link delivery %s to incident %s: %v", deliveryID, incID, err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, 'membership_changed', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incID, deliveryID, groupKey, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert situation input %s: %v", inputID, err)
	}
	claims, err := st.ClaimSituationInputs(ctx, "seed:"+id, now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim situation input: claims=%d err=%v", len(claims), err)
	}
	if err := st.ApplySituationInput(ctx, claims[0]); err != nil {
		t.Fatalf("apply situation input for delivery %s: %v", deliveryID, err)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&situationID); err != nil {
		t.Fatalf("find situation for group %s: %v", groupKey, err)
	}
	return deliveryID, situationID
}

// appendResolvedRepeatDelivery attaches a SECOND delivery for the SAME
// underlying Alert (same Alert.ID, a later ReceivedAt, status "resolved")
// to sitID's incident — a routine Alertmanager repeat-send, not a new
// member. Used to prove membersFromDeliveries collapses it into the
// existing member rather than manufacturing a second one.
func appendResolvedRepeatDelivery(t *testing.T, st *store.Store, firstDeliveryID, groupKey string, now time.Time) (deliveryID string) {
	t.Helper()
	ctx := context.Background()
	deliveryID = firstDeliveryID + "-repeat"
	del := store.DeliveryInput{
		ID: deliveryID,
		Alert: store.Alert{
			ID: "alert-wall", Fingerprint: "fp-wall", Status: "resolved",
			Labels:      map[string]string{"alertname": "test", "service": "checkout"},
			Annotations: map[string]string{"summary": "test alert"},
			StartsAt:    now, ReceivedAt: now.Add(time.Minute),
		},
		Source:                   "alertmanager",
		SourceEpisodeKey:         "alertmanager:fp-wall:" + now.UTC().Format(time.RFC3339Nano),
		StartedAtBasis:           situationmodel.SourceTimeBasisSourcePayload,
		ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "group:fp-wall",
		PayloadDigest:            "sha256:" + deliveryID,
		SourceProvenance:         store.SourceProvenance{AcquisitionMode: store.SourceAcquisitionWebhook},
	}
	if _, err := st.AcceptDeliveries(ctx, []store.DeliveryInput{del}); err != nil {
		t.Fatalf("accept repeat delivery %s: %v", deliveryID, err)
	}
	incID := "inc-wall"
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		incID, deliveryID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("link repeat delivery %s: %v", deliveryID, err)
	}
	inputID := "input-" + deliveryID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, delivery_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, 'incident_resolved', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incID, deliveryID, groupKey, now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert repeat situation input %s: %v", inputID, err)
	}
	claims, err := st.ClaimSituationInputs(ctx, "seed:repeat", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim repeat situation input: claims=%d err=%v", len(claims), err)
	}
	if err := st.ApplySituationInput(ctx, claims[0]); err != nil {
		t.Fatalf("apply repeat situation input %s: %v", deliveryID, err)
	}
	return deliveryID
}

// TestMembersFromDeliveriesCollapsesARepeatSendIntoItsExistingMember proves
// membersFromDeliveries reduces multiple deliveries of the SAME Alert
// (Alertmanager's routine re-send of an unchanged or now-resolved alert) to
// ONE MemberSubject, keyed by AlertID, taking the chronologically latest
// delivery's own Status — exactly internal/situation's own
// incidentSymptomStatus convention (this file's own doc comment).
func TestMembersFromDeliveriesCollapsesARepeatSendIntoItsExistingMember(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Now().UTC()
	firstDeliveryID, sitID := seedDeliveredSituation(t, st, "wall", "service=checkout-wall", now)
	appendResolvedRepeatDelivery(t, st, firstDeliveryID, "service=checkout-wall", now)

	req := preparationRequestFor(t, st, sitID, "members-owner", model.PhaseAssessment, now.Add(2*time.Minute))
	members := membersFromDeliveries(req.Input)

	if len(members) != 1 {
		t.Fatalf("members = %+v, want exactly 1 (the repeat must collapse, not add a second member)", members)
	}
	if members[0].Firing {
		t.Fatalf("member = %+v, want Firing=false (the latest delivery resolved)", members[0])
	}
}

// preparationRequestFor claims sitID's controller work and loads its
// reconciliation input through the real store, building the exact
// situation.PreparationRequest productionPreparer.Prepare receives from
// Controller.reconcile in production.
func preparationRequestFor(t *testing.T, st *store.Store, sitID, owner string, phase model.Phase, now time.Time) situation.PreparationRequest {
	t.Helper()
	ctx := context.Background()
	claims, err := st.ClaimControllerWork(ctx, owner, now, time.Minute, 10)
	if err != nil {
		t.Fatalf("claim controller work: %v", err)
	}
	var claim situation.Claim
	found := false
	for _, c := range claims {
		if c.Situation.ID == sitID {
			claim = c
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("situation %s was not among %d claimed", sitID, len(claims))
	}
	input, err := st.LoadReconciliationInput(ctx, claim, now)
	if err != nil {
		t.Fatalf("load reconciliation input: %v", err)
	}
	return situation.PreparationRequest{Claim: claim, Input: input, Phase: phase, Now: now}
}

// ctxCapturingExecutor records the context.Context it was actually called
// with, so a test can inspect the deadline Prepare derived for it.
type ctxCapturingExecutor struct {
	seen  context.Context //nolint:containedctx // test double: deliberately retains the ctx it was called with so the test can inspect its deadline
	calls int
}

func (e *ctxCapturingExecutor) Execute(ctx context.Context, plan model.Plan, recorder observation.RequestRecorder) (model.Run, error) {
	e.seen = ctx
	e.calls++
	if _, err := recorder.BeforeRequest(ctx); err != nil {
		return model.Run{}, err
	}
	_ = recorder.AfterRequest(ctx, model.RequestOutcome{
		ReservationID: "req", RequestStarted: model.RequestStartedTrue, Code: "ok", CompletedAt: time.Now().UTC(),
	})
	return model.Run{
		ID: "run-" + plan.ID, CycleID: plan.CycleID, PlanID: plan.ID,
		Status: model.ResultConfirmedEmpty, ObservedAt: time.Now().UTC(), CompletedAt: time.Now().UTC(),
	}, nil
}

func testProductionPreparer(st *store.Store, exec observation.Executor, prepCfg config.SituationPreparationConfig) *productionPreparer {
	runner := observation.NewRunner(st, map[model.Capability]observation.Executor{
		model.CapabilityPrometheusQuery: exec,
	}, func() time.Time { return time.Now().UTC() })
	return &productionPreparer{
		st:     st,
		runner: runner,
		capabilities: []observation.CapabilityDescriptor{
			{Capability: model.CapabilityPrometheusQuery, DefaultWindow: time.Hour, DefaultLimit: 100, MaxRequestsHint: 1},
		},
		configDigest: "test-digest",
		prepCfg:      prepCfg,
		logger:       slog.Default(),
	}
}

// TestProductionPreparerAppliesSharedMaxWallSecondsDeadline proves Prepare
// derives its own bounded ctx deadline from req.Now + prepCfg.MaxWallSeconds
// (spec.md: the preparation wall is "shared by both the lifecycle and
// assessment phases" of one Reconcile cycle) rather than running unbounded
// on whatever ctx its caller happened to pass in.
func TestProductionPreparerAppliesSharedMaxWallSecondsDeadline(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Now().UTC()
	_, sitID := seedDeliveredSituation(t, st, "wall", "service=checkout-wall", now)

	exec := &ctxCapturingExecutor{}
	prepCfg := config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 7, RefreshSeconds: 60}
	p := testProductionPreparer(st, exec, prepCfg)

	req := preparationRequestFor(t, st, sitID, "wall-owner", model.PhaseAssessment, now)

	if _, err := p.Prepare(context.Background(), req); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if exec.calls != 1 {
		t.Fatalf("executor calls = %d, want 1 (fixture expected to admit exactly one plan)", exec.calls)
	}
	deadline, ok := exec.seen.Deadline()
	if !ok {
		t.Fatal("executor ctx carries no deadline, want one derived from req.Now + MaxWallSeconds")
	}
	want := req.Now.Add(7 * time.Second)
	if !deadline.Equal(want) {
		t.Fatalf("executor ctx deadline = %v, want %v (req.Now + MaxWallSeconds)", deadline, want)
	}
}

// TestProductionPreparerMaxWallSecondsDeadlineIsIdenticalAcrossBothPhaseCalls
// proves the SAME wall-clock anchor (req.Now) drives the deadline on both a
// lifecycle-phase and an assessment-phase call within one Reconcile cycle —
// the mechanism by which one shared preparation wall budget covers both
// phases, per spec.md, without either Prepare call needing to know how much
// of the budget a sibling phase call already spent.
func TestProductionPreparerMaxWallSecondsDeadlineIsIdenticalAcrossBothPhaseCalls(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Now().UTC()
	_, sitID := seedDeliveredSituation(t, st, "shared", "service=checkout-shared", now)

	prepCfg := config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 11, RefreshSeconds: 60}

	// Mirrors Controller.reconcile's own contract: ONE claim, ONE loaded
	// SnapshotInput, ONE captured req.Now — reused as the shared anchor for
	// both this cycle's lifecycle- and assessment-phase Prepare calls.
	base := preparationRequestFor(t, st, sitID, "shared-owner", model.PhaseLifecycle, now)

	lifecycleExec := &ctxCapturingExecutor{}
	pLifecycle := testProductionPreparer(st, lifecycleExec, prepCfg)
	lifecycleReq := base
	lifecycleReq.Phase = model.PhaseLifecycle
	if _, err := pLifecycle.Prepare(context.Background(), lifecycleReq); err != nil {
		t.Fatalf("lifecycle Prepare: %v", err)
	}

	assessExec := &ctxCapturingExecutor{}
	pAssess := testProductionPreparer(st, assessExec, prepCfg)
	assessReq := base
	assessReq.Phase = model.PhaseAssessment
	if _, err := pAssess.Prepare(context.Background(), assessReq); err != nil {
		t.Fatalf("assessment Prepare: %v", err)
	}

	if lifecycleExec.calls == 0 && assessExec.calls == 0 {
		t.Fatal("neither phase call reached the executor; fixture did not admit a plan in either phase")
	}
	var lifecycleDeadline, assessDeadline time.Time
	if lifecycleExec.calls > 0 {
		d, ok := lifecycleExec.seen.Deadline()
		if !ok {
			t.Fatal("lifecycle executor ctx carries no deadline")
		}
		lifecycleDeadline = d
	}
	if assessExec.calls > 0 {
		d, ok := assessExec.seen.Deadline()
		if !ok {
			t.Fatal("assessment executor ctx carries no deadline")
		}
		assessDeadline = d
	}
	want := now.Add(11 * time.Second)
	if lifecycleExec.calls > 0 && !lifecycleDeadline.Equal(want) {
		t.Fatalf("lifecycle deadline = %v, want %v", lifecycleDeadline, want)
	}
	if assessExec.calls > 0 && !assessDeadline.Equal(want) {
		t.Fatalf("assessment deadline = %v, want %v", assessDeadline, want)
	}
}

// TestProductionPreparerAuditsCycleBegun proves Prepare emits a
// "situation.preparation.cycle_begun" audit row immediately after
// BeginPreparation's cycle durably commits — Task 9's own "Audit cycle
// creation/sealing" requirement.
func TestProductionPreparerAuditsCycleBegun(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Now().UTC()
	_, sitID := seedDeliveredSituation(t, st, "audit", "service=checkout-audit", now)

	exec := &ctxCapturingExecutor{}
	prepCfg := config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 60}
	p := testProductionPreparer(st, exec, prepCfg)
	p.auditor = audit.New(st.DB())

	req := preparationRequestFor(t, st, sitID, "audit-owner", model.PhaseAssessment, now)
	if _, err := p.Prepare(context.Background(), req); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	var count int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM audit_log WHERE kind = ?`, "situation.preparation.cycle_begun").Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit rows = %d, want 1", count)
	}
}

// TestProductionPreparerSkipsAuditWhenAuditorIsNil proves a nil auditor (the
// default, and every other fixture in this file) disables emission rather
// than panicking — Prepare must work identically whether or not audit is
// wired.
func TestProductionPreparerSkipsAuditWhenAuditorIsNil(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Now().UTC()
	_, sitID := seedDeliveredSituation(t, st, "noaudit", "service=checkout-noaudit", now)

	exec := &ctxCapturingExecutor{}
	prepCfg := config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 60}
	p := testProductionPreparer(st, exec, prepCfg) // auditor left nil

	req := preparationRequestFor(t, st, sitID, "noaudit-owner", model.PhaseAssessment, now)
	if _, err := p.Prepare(context.Background(), req); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
}

// TestNewPreparationRuntimeWiresAuditorIntoPreparer proves the auditor
// parameter newPreparationRuntime accepts reaches the returned
// EvidencePreparer's own auditor field — the wiring buildPreparationRuntime
// relies on in production.
func TestNewPreparationRuntimeWiresAuditorIntoPreparer(t *testing.T) {
	st := newTestFoundationStore(t)
	auditor := audit.New(st.DB())
	_, preparer, err := newPreparationRuntime(st, &config.Config{}, "test-owner", nil, nil, nil, nil, nil, nil, nil, auditor, slog.Default())
	if err != nil {
		t.Fatalf("newPreparationRuntime: %v", err)
	}
	pp, ok := preparer.(*productionPreparer)
	if !ok {
		t.Fatalf("preparer = %T, want *productionPreparer", preparer)
	}
	if pp.auditor != auditor {
		t.Fatal("preparer.auditor does not match the auditor passed to newPreparationRuntime")
	}
}

// ----------------------------------------------------------------------
// capabilityDescriptorsFromConfig: enablement boundary
// ----------------------------------------------------------------------

func TestCapabilityDescriptorsFromConfigAlwaysIncludesStoreReadOnly(t *testing.T) {
	descs := capabilityDescriptorsFromConfig(&config.Config{})
	if len(descs) != 1 || descs[0].Capability != model.CapabilityStoreRead {
		t.Fatalf("descs = %+v, want exactly [store_read] for an all-disabled config", descs)
	}
}

func TestCapabilityDescriptorsFromConfigAddsEachEnabledConnector(t *testing.T) {
	cfg := &config.Config{}
	cfg.Prometheus.BaseURL = "http://prom.internal"
	cfg.Logs.Loki.BaseURL = "http://loki.internal"
	cfg.Zabbix.API.BaseURL = "http://zbx.internal"
	cfg.Sentry.Issues.Enabled = true

	descs := capabilityDescriptorsFromConfig(cfg)

	got := make(map[model.Capability]bool, len(descs))
	for _, d := range descs {
		got[d.Capability] = true
	}
	want := []model.Capability{
		model.CapabilityStoreRead, model.CapabilityPrometheusQuery, model.CapabilityLokiQuery,
		model.CapabilitySentryIssues, model.CapabilityZabbixMetricRange, model.CapabilityZabbixProblemHist,
	}
	for _, c := range want {
		if !got[c] {
			t.Fatalf("descs = %+v, missing enabled capability %s", descs, c)
		}
	}
	if len(descs) != len(want) {
		t.Fatalf("descs = %+v, want exactly %v (no extras)", descs, want)
	}
}

// ----------------------------------------------------------------------
// sentryProjectEnvFromScope: label-priority lookup
// ----------------------------------------------------------------------

func TestSentryProjectEnvFromScopePrefersServiceThenFallsThroughPriorityOrder(t *testing.T) {
	project, env, ok := sentryProjectEnvFromScope(model.Scope{Labels: map[string]string{
		"service": "checkout", "project": "should-not-win", "environment": "prod",
	}})
	if !ok || project != "checkout" || env != "prod" {
		t.Fatalf("project=%q env=%q ok=%v, want checkout/prod/true", project, env, ok)
	}
}

func TestSentryProjectEnvFromScopeFallsBackToJobAndEnv(t *testing.T) {
	project, env, ok := sentryProjectEnvFromScope(model.Scope{Labels: map[string]string{
		"job": "worker", "env": "staging",
	}})
	if !ok || project != "worker" || env != "staging" {
		t.Fatalf("project=%q env=%q ok=%v, want worker/staging/true", project, env, ok)
	}
}

func TestSentryProjectEnvFromScopeNoProjectLabelIsNotOK(t *testing.T) {
	_, _, ok := sentryProjectEnvFromScope(model.Scope{Labels: map[string]string{"environment": "prod"}})
	if ok {
		t.Fatal("ok = true with no project/service/app/job label present, want false")
	}
}

// ----------------------------------------------------------------------
// preparationConfigDigest: stable, input-sensitive hash
// ----------------------------------------------------------------------

func TestPreparationConfigDigestStableForIdenticalInput(t *testing.T) {
	descs := []observation.CapabilityDescriptor{{Capability: model.CapabilityStoreRead, DefaultWindow: time.Hour, DefaultLimit: 20}}
	cfg := config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 300}
	a := preparationConfigDigest(descs, cfg)
	b := preparationConfigDigest(descs, cfg)
	if a != b {
		t.Fatalf("digest not stable: %s != %s", a, b)
	}
}

func TestPreparationConfigDigestChangesWithCadenceKnobs(t *testing.T) {
	descs := []observation.CapabilityDescriptor{{Capability: model.CapabilityStoreRead, DefaultWindow: time.Hour, DefaultLimit: 20}}
	a := preparationConfigDigest(descs, config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 300})
	b := preparationConfigDigest(descs, config.SituationPreparationConfig{MaxSourceCallsPerCycle: 5, MaxWallSeconds: 20, RefreshSeconds: 600})
	if a == b {
		t.Fatal("digest unchanged after refresh_seconds changed, want a distinct digest")
	}
}

// ----------------------------------------------------------------------
// executorsFromClients: nil-client capabilities are simply omitted
// ----------------------------------------------------------------------

func TestExecutorsFromClientsOmitsUnconfiguredCapabilitiesAndAlwaysIncludesLocalReads(t *testing.T) {
	st := newTestFoundationStore(t)
	execs := executorsFromClients(st, nil, nil, nil, nil, func() time.Time { return time.Now().UTC() })

	if _, ok := execs[model.CapabilityStoreRead]; !ok {
		t.Fatal("store_read executor missing even though it needs no external client")
	}
	if _, ok := execs[model.CapabilityChangeEvents]; !ok {
		t.Fatal("change_events executor missing even though it needs no external client")
	}
	for _, c := range []model.Capability{model.CapabilityPrometheusQuery, model.CapabilityLokiQuery, model.CapabilitySentryIssues, model.CapabilityZabbixMetricRange, model.CapabilityZabbixProblemHist} {
		if _, ok := execs[c]; ok {
			t.Fatalf("executor registered for %s with a nil client, want it omitted", c)
		}
	}
}

// ----------------------------------------------------------------------
// newPreparationRuntime: construction guard
// ----------------------------------------------------------------------

func TestNewPreparationRuntimeRejectsEmptyOwner(t *testing.T) {
	st := newTestFoundationStore(t)
	_, _, err := newPreparationRuntime(st, &config.Config{}, "  ", nil, nil, nil, nil, nil, nil, nil, nil, slog.Default())
	if err == nil {
		t.Fatal("expected an error for an empty/whitespace owner")
	}
}

// ----------------------------------------------------------------------
// preparationSweep: bounded, idempotent scheduled work
// ----------------------------------------------------------------------

func TestPreparationSweepDrainRunsUntilARoundHandlesZero(t *testing.T) {
	remaining := []int{3, 2, 0}
	calls := 0
	sweep := newPreparationSweep("test_sweep", time.Hour, func(context.Context, time.Time) (int, error) {
		n := remaining[calls]
		calls++
		return n, nil
	}, nil, nil)

	handled, err := sweep.Drain(context.Background())
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if handled != 5 {
		t.Fatalf("handled = %d, want 5 (3+2+0)", handled)
	}
	if calls != 3 {
		t.Fatalf("run calls = %d, want 3 (stops at the first zero round)", calls)
	}
}

func TestPreparationSweepDrainPropagatesRunError(t *testing.T) {
	wantErr := context.DeadlineExceeded
	sweep := newPreparationSweep("test_sweep", time.Hour, func(context.Context, time.Time) (int, error) {
		return 1, wantErr
	}, nil, nil)

	if _, err := sweep.Drain(context.Background()); err != wantErr { //nolint:errorlint // exact sentinel identity is the thing under test
		t.Fatalf("Drain err = %v, want %v", err, wantErr)
	}
}

func TestPreparationSweepStartRunsOnWakeAndStopsCleanly(t *testing.T) {
	handled := make(chan struct{}, 1)
	sweep := newPreparationSweep("test_sweep", time.Hour, func(context.Context, time.Time) (int, error) {
		select {
		case handled <- struct{}{}:
		default:
		}
		return 0, nil
	}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sweep.Start(ctx)

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("sweep never ran its first round after Start")
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := sweep.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// ----------------------------------------------------------------------
// preparationRuntime: orchestration over a real, empty store
// ----------------------------------------------------------------------

func TestPreparationRuntimeRecoverOnEmptyStoreIsANoOp(t *testing.T) {
	st := newTestFoundationStore(t)
	rt, _, err := newPreparationRuntime(st, &config.Config{}, "test-owner", nil, nil, nil, nil, nil, nil, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newPreparationRuntime: %v", err)
	}
	if err := rt.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
}

func TestPreparationRuntimeDrainOnEmptyStoreIsANoOp(t *testing.T) {
	st := newTestFoundationStore(t)
	rt, _, err := newPreparationRuntime(st, &config.Config{}, "test-owner", nil, nil, nil, nil, nil, nil, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newPreparationRuntime: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := rt.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
}
