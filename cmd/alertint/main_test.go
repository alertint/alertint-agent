// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/llm"
	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	notifystdout "github.com/alertint/alertint-agent/internal/notify/stdout"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

func TestRun_VersionFlagPrintsVersionAndExitsCleanly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run --version: %v (stderr=%q)", err, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got == "" {
		t.Fatal("--version produced empty output")
	}
}

func TestRun_RejectsUnknownLogLevel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--log-level", "loud"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown log level")
	}
}

// TestBuildLogger_Precedence verifies CLI flag > config > built-in default for
// both level and format, and that auto resolves to json on a non-TTY writer
// (a bytes.Buffer). The returned strings are what the startup line reports.
func TestBuildLogger_Precedence(t *testing.T) {
	cases := []struct {
		name                                       string
		flagLevel, flagFormat, cfgLevel, cfgFormat string
		wantLevel, wantFormat                      string
	}{
		{"defaults when all empty", "", "", "", "", "info", "json"},
		{"config applied over default", "", "", "debug", "json", "debug", "json"},
		{"flag overrides config", "warn", "json", "debug", "console", "warn", "json"},
		{"config format auto resolves to json off-tty", "", "", "", "auto", "info", "json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, level, format, err := buildLogger(tc.flagLevel, tc.flagFormat, tc.cfgLevel, tc.cfgFormat, &buf)
			if err != nil {
				t.Fatalf("buildLogger: %v", err)
			}
			if level != tc.wantLevel {
				t.Errorf("level = %q, want %q", level, tc.wantLevel)
			}
			if format != tc.wantFormat {
				t.Errorf("format = %q, want %q", format, tc.wantFormat)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Situation runtime cutover
// --------------------------------------------------------------------------

// buildRuntimeForTest assembles the exact serve topology (minus HTTP
// listeners) against a temporary store, so the wiring itself is assertable.
func buildRuntimeForTest(t *testing.T, mutate func(*config.Config)) *serveRuntime {
	t.Helper()
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "alertint.db")
	if mutate != nil {
		mutate(&cfg)
	}
	st, err := store.Open(ctx, cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	auditor := audit.New(st.DB())
	logger := slog.New(slog.DiscardHandler)
	cor := correlator.New(correlator.Config{}, st, correlator.NopIncidentSink{}, logger)
	// The skill is constructed exactly as runServe constructs it: no notifier.
	// The stub LLM client stands in for the real provider (serve always wires
	// one); a failing call exercises the honest "L1 blocked" path.
	skill := acutetriage.New(acutetriage.Config{}, st, stubLLM{}, auditor, nil, logger)
	rt, err := buildSituationRuntime(&cfg, st, auditor, cor, situationDeps{Skill: skill}, logger)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// stubLLM stands in for the configured provider in wiring tests. It never
// succeeds: these tests assert the deterministic paths, which must hold with
// no usable model at all.
type stubLLM struct{}

func (stubLLM) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	return llm.Completion{}, errors.New("stub llm: unavailable")
}

func TestServeHasNoLegacyIncidentSlackWriter(t *testing.T) {
	rt := buildRuntimeForTest(t, nil)
	if rt.acuteNotifierWired {
		t.Fatal("acute triage still has a notifier; L1 would publish to Slack directly")
	}
	// The check is not vacuous: a skill built WITH a notifier reports one.
	withNotifier := acutetriage.New(acutetriage.Config{}, rt.store, stubLLM{}, nil, notifystdout.New(io.Discard, nil, false), slog.New(slog.DiscardHandler))
	if !withNotifier.NotifierWired() {
		t.Fatal("NotifierWired reports no notifier on a skill that has one")
	}
	if _, ok := rt.incidentSink.(correlator.NopIncidentSink); !ok {
		t.Fatalf("correlator incident sink = %T, want the no-op sink", rt.incidentSink)
	}
	// The resolution notifier, occurrence notifier, and direct rejudger have
	// no seam left at all: *correlator.Correlator no longer exposes one.
	var c any = rt.correlator
	if _, ok := c.(interface{ SetResolutionNotifier(any) }); ok {
		t.Fatal("correlator still exposes a resolution-notifier seam")
	}
	if _, ok := c.(interface{ SetOccurrenceNotifier(any) }); ok {
		t.Fatal("correlator still exposes an occurrence-notifier seam")
	}
	if _, ok := c.(interface{ SetRejudger(any) }); ok {
		t.Fatal("correlator still exposes a direct-rejudger seam")
	}
}

func TestServeWiresExactlyOneSlackAuthority(t *testing.T) {
	t.Setenv("ALERTINT_SLACK_BOT_TOKEN", "xoxb-test-token")
	rt := buildRuntimeForTest(t, func(cfg *config.Config) {
		cfg.Notify.Slack.Enabled = true
		cfg.Notify.Slack.Channel = "#alerts"
		cfg.Notify.Slack.BotTokenEnv = "ALERTINT_SLACK_BOT_TOKEN"
	})
	// The runtime under test is built without a Slack client (situationDeps
	// leaves it nil), so it records no authority — proving the count comes
	// from what was wired, not from config alone.
	if len(rt.slackAuthorities) != 0 {
		t.Fatalf("slack authorities=%v without a wired client", rt.slackAuthorities)
	}

	cfg := config.Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "alertint.db")
	cfg.Notify.Slack.Enabled = true
	cfg.Notify.Slack.Channel = "#alerts"
	st, err := store.Open(context.Background(), cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cor := correlator.New(correlator.Config{}, st, correlator.NopIncidentSink{}, slog.New(slog.DiscardHandler))
	wired, err := buildSituationRuntime(&cfg, st, audit.New(st.DB()), cor,
		situationDeps{SlackClient: notifyslack.NewHTTPAPIClient("xoxb-test")}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if len(wired.slackAuthorities) != 1 || wired.slackAuthorities[0] != slackAuthoritySituationNotifications {
		t.Fatalf("slack authorities=%v, want exactly the situation notification worker", wired.slackAuthorities)
	}
}

func TestServeStartsTheFullSituationWorkerGraph(t *testing.T) {
	rt := buildRuntimeForTest(t, nil)
	if rt.workers.Dispatch == nil || rt.workers.Inputs == nil || rt.workers.Controller == nil || rt.workers.Notifications == nil {
		t.Fatalf("worker graph is incomplete: %+v", rt.workers)
	}
	if rt.commands == nil {
		t.Fatal("serve wires no SituationCommands; the Situation MCP tool group would not register")
	}
	if rt.reconstructor == nil {
		t.Fatal("serve wires no startup reconstruction")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.workers.Start(ctx)
	rt.workers.Wake()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := rt.workers.Stop(stopCtx); err != nil {
		t.Fatalf("workers did not drain: %v", err)
	}
}

func TestReconstructionSchedulesActiveIncidentsWithoutPublishing(t *testing.T) {
	ctx := context.Background()
	rt := buildRuntimeForTest(t, nil)
	now := time.Now().UTC().Add(-time.Hour)
	ts := now.Format(time.RFC3339Nano)
	for _, id := range []string{"legacy-a", "legacy-b"} {
		if _, err := rt.store.DB().ExecContext(ctx, `
			INSERT INTO incidents(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
			VALUES (?, 'service=api', 'analyzed', ?, ?, ?, 1, ?, ?)`, id, ts, ts, ts, ts, ts); err != nil {
			t.Fatal(err)
		}
	}

	if err := rt.runReconstruction(ctx, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	sits, err := rt.store.ListSituations(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(sits) != 1 {
		t.Fatalf("situations=%d, want one per exact group", len(sits))
	}
	if sits[0].PublicHandle != nil {
		t.Fatalf("reconstruction published handle %q", *sits[0].PublicHandle)
	}
	var intents int
	if err := rt.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 0 {
		t.Fatalf("upgrade pokes=%d, want none", intents)
	}
}

// failingInputStore is a real situation.InputStore whose claim call fails
// while `broken` is set — the shape of a transient SQLITE_BUSY on the very
// first statement of a worker round.
type failingInputStore struct {
	broken bool
	claims int
}

func (f *failingInputStore) ClaimSituationInputs(_ context.Context, _ string, _ time.Time, _ time.Duration, _ int) ([]situation.InputClaim, error) {
	f.claims++
	if f.broken {
		return nil, errors.New("database is locked")
	}
	return nil, nil
}

func (f *failingInputStore) ApplySituationInput(context.Context, situation.InputClaim) error {
	return nil
}

func (f *failingInputStore) RetrySituationInput(context.Context, situation.InputClaim, string, time.Time, bool) error {
	return nil
}

// TestStoreWriteHealthRecoversThroughALaterRealRound drives the whole
// readiness path through a real worker: a real failing round degrades it, the
// gate then blocks real rounds, and a later real round recovers it. Nothing
// here calls Observe directly — the point is that the recovery PATH exists,
// not that the mechanism can be poked.
func TestStoreWriteHealthRecoversThroughALaterRealRound(t *testing.T) {
	ctx := context.Background()
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelInfo}))

	writable := false
	h := newStoreWriteHealth("/tmp/alertint.db", func(context.Context) error {
		if writable {
			return nil
		}
		return errors.New("attempt to write a readonly database")
	}, logger)
	h.recheckAfter = 0 // probe on every gate consultation in the test
	woken := 0
	h.SetWake(func() { woken++ })

	backing := &failingInputStore{broken: true}
	worker := situation.NewInputWorker(backing, situation.WorkerConfig{
		Owner: "worker-1", Ready: h.Ready, OnRound: h.Observe,
	}, func() time.Time { return time.Now().UTC() }, logger)

	// A real round fails against unwritable storage: readiness degrades.
	if _, err := worker.RunOnce(ctx); err == nil {
		t.Fatal("expected the failing round to surface its error")
	}
	if h.Ready(ctx) {
		t.Fatal("readiness stayed ready after a real failing round")
	}
	if err := h.Check().Probe(ctx); err == nil {
		t.Fatal("health probe reported ok while storage is unwritable")
	}

	// While degraded the gate blocks real rounds: the store is not touched.
	claimsWhenDegraded := backing.claims
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("gated round returned %v, want a clean no-op", err)
	}
	if backing.claims != claimsWhenDegraded {
		t.Fatalf("a gated round still reached storage: claims %d -> %d", claimsWhenDegraded, backing.claims)
	}
	if got := strings.Count(logged.String(), "sqlite write failed"); got != 1 {
		t.Fatalf("logged %d ERROR lines, want exactly one per state change", got)
	}

	// Storage recovers. The next real round must run again — with no restart,
	// and without anything calling Observe on its behalf.
	writable = true
	backing.broken = false
	applied, err := worker.RunOnce(ctx)
	if err != nil || applied != 0 {
		t.Fatalf("recovered round applied=%d err=%v", applied, err)
	}
	if backing.claims <= claimsWhenDegraded {
		t.Fatalf("the round body never ran after recovery: claims %d -> %d", claimsWhenDegraded, backing.claims)
	}
	if !h.Ready(ctx) {
		t.Fatal("readiness did not recover after storage became writable")
	}
	if err := h.Check().Probe(ctx); err != nil {
		t.Fatalf("health probe = %v after recovery, want ok", err)
	}
	if woken == 0 {
		t.Fatal("durable workers were never woken on recovery")
	}
}

// TestStoreWriteHealthIgnoresRoutineContention proves ordinary multi-worker
// outcomes never gate the runtime off.
func TestStoreWriteHealthIgnoresRoutineContention(t *testing.T) {
	ctx := context.Background()
	h := newStoreWriteHealth("/tmp/alertint.db", func(context.Context) error { return nil }, slog.New(slog.DiscardHandler))
	for _, err := range []error{
		store.ErrSituationLeaseLost,
		store.ErrSituationVersionConflict,
		store.ErrAlertDispatchLeaseLost,
		store.ErrNotificationNotPending,
		store.ErrNotFound,
		context.Canceled,
		fmt.Errorf("situation: release situation s-1: %w", store.ErrSituationLeaseLost),
	} {
		h.Observe(0, err)
		if !h.Ready(ctx) {
			t.Fatalf("routine outcome %v degraded storage readiness", err)
		}
	}
	// The check is not vacuous: a genuine storage error does degrade it, and
	// only a successful re-probe brings it back.
	failing := newStoreWriteHealth("/tmp/alertint.db", func(context.Context) error {
		return errors.New("disk I/O error")
	}, slog.New(slog.DiscardHandler))
	failing.recheckAfter = 0
	failing.Observe(0, errors.New("disk I/O error"))
	if failing.Ready(ctx) {
		t.Fatal("a genuine storage failure did not degrade readiness")
	}
}

// TestCutoverRuntimeTurnsADeliveryIntoASituationPoke walks the whole cut-over
// graph once — accepted delivery, correlation dispatch, Situation input,
// reconciliation — and asserts the outcome is a durable Situation
// notification intent, produced with no LLM call and no legacy Incident card.
func TestCutoverRuntimeTurnsADeliveryIntoASituationPoke(t *testing.T) {
	ctx := context.Background()
	rt := buildRuntimeForTest(t, nil)
	now := time.Now().UTC()

	if _, err := rt.store.AcceptDeliveries(ctx, []store.DeliveryInput{{
		ID: "delivery-1",
		Alert: store.Alert{
			ID: "alert-1", Fingerprint: "fp-1", Status: "firing",
			Labels:      map[string]string{"severity": "critical", "alertname": "DiskFull", "service": "api"},
			Annotations: map[string]string{}, StartsAt: now, ReceivedAt: now,
		},
		Source: "alertmanager", SourceEpisodeKey: "alertmanager:fp-1:" + now.Format(time.RFC3339Nano),
		SourceStartedAt: &now, StartedAtBasis: situationmodel.SourceTimeBasisSourcePayload,
		ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "service=api", PayloadDigest: "sha256:delivery-1",
	}}); err != nil {
		t.Fatal(err)
	}

	if err := rt.workers.Dispatch.RunOnce(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if applied, err := rt.workers.Inputs.RunOnce(ctx); err != nil || applied != 1 {
		t.Fatalf("inputs applied=%d err=%v", applied, err)
	}
	if handled, err := rt.workers.Controller.RunOnce(ctx); err != nil || handled != 1 {
		t.Fatalf("controller handled=%d err=%v", handled, err)
	}

	sits, err := rt.store.ListSituations(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sits) != 1 {
		t.Fatalf("situations=%d, want exactly one for the exact group", len(sits))
	}
	if sits[0].Attention != situationmodel.AttentionUrgent {
		t.Fatalf("attention=%q, want the deterministic critical floor without any model call", sits[0].Attention)
	}
	if sits[0].PublicHandle == nil {
		t.Fatal("a published Situation has no public handle to address it by")
	}
	if !sits[0].NextAssessmentAt.After(now) {
		t.Fatalf("next assessment=%s, want a future update promise", sits[0].NextAssessmentAt)
	}

	intents, err := rt.store.SituationNotifications(ctx, sits[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 {
		t.Fatalf("intents=%d, want exactly one root create", len(intents))
	}
	if intents[0].Kind != situationmodel.NotificationSituationRootCreate || !intents[0].MainChannelPoke {
		t.Fatalf("intent=%+v", intents[0])
	}
	if intents[0].ClientMessageID == "" {
		t.Fatal("intent carries no deterministic client message id; a retry could duplicate the post")
	}
}

// TestServeWiresObservationExecutorsForConfiguredConnectors proves the
// cut-over runtime gathers evidence from the connectors this installation
// actually runs, and stays honestly unavailable for the ones it does not.
func TestServeWiresObservationExecutorsForConfiguredConnectors(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "alertint.db")
	st, err := store.Open(ctx, cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// A zero-integration installation still reduces its own delivery ledger.
	bare := buildObservationSources(&cfg, st, nil, nil, nil, nil)
	if bare.Situations == nil {
		t.Fatal("the local store_read reducer is not wired; a zero-integration install would gather nothing")
	}
	for _, name := range bare.Unavailable() {
		if name == "store_read" {
			t.Fatal("store_read reported unavailable on an install that has a store")
		}
	}

	// A configured Zabbix installation gets the problem timeline and metric
	// range reducers Task 6's support was built for.
	enabled := true
	cfg.Zabbix.API.Enabled = &enabled
	cfg.Zabbix.API.BaseURL = "https://zabbix.example.com"
	cfg.Zabbix.API.APITokenEnv = "ALERTINT_ZABBIX_TOKEN"
	t.Setenv("ALERTINT_ZABBIX_TOKEN", "zbx-token")
	zbx, err := newZabbixClient(&cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if zbx == nil {
		t.Fatal("zabbix api is enabled but no client was built")
	}
	wired := buildObservationSources(&cfg, st, nil, nil, nil, zbx)
	if wired.Zabbix == nil {
		t.Fatal("zabbix is configured but its observation reducers are not wired")
	}
	for _, name := range wired.Unavailable() {
		if strings.HasPrefix(name, "zabbix") {
			t.Fatalf("%q reported unavailable while zabbix is configured", name)
		}
	}

	// A disabled connector must never be wired as a typed-nil client, which
	// would look available and then fail every call.
	if wired.Prometheus != nil || wired.Logs != nil || wired.Sentry != nil {
		t.Fatalf("a disabled connector was wired: prom=%v logs=%v sentry=%v",
			wired.Prometheus != nil, wired.Logs != nil, wired.Sentry != nil)
	}
}
