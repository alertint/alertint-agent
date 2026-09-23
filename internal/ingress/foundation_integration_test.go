// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Task 9, Step 4: end-to-end durability scenarios this task's plan asks
// for, driven from the real inbound HTTP boundary (POST /webhook/
// alertmanager) against a real file-backed Store — never a hand-inserted
// situations row. Scenarios 1 and 2 combine into the primary workflow test
// TestFoundationReceiverRestartToSituation, retained per the plan as a
// permanent smoke test; scenarios 5, 6, 8, and 9 each get their own test.
// Scenarios 3, 4, and 7 live in internal/correlator/
// foundation_crash_recovery_test.go, closer to the dispatch/input-worker
// crash boundary they exercise.
// ----------------------------------------------------------------------

// foundationGroupPayload builds a one-alert Alertmanager v4 envelope for the
// given group/fingerprint — enough for the receiver's durable-acceptance
// path to derive a stable ReceiverGroupingIdentity.
func foundationGroupPayload(group, alertname, fingerprint string, at time.Time) AlertmanagerPayload {
	return AlertmanagerPayload{
		Version:     "4",
		Status:      "firing",
		GroupLabels: map[string]string{"group": group},
		Alerts: []AlertmanagerAlert{{
			Status:      "firing",
			Labels:      map[string]string{"alertname": alertname, "group": group},
			Annotations: map[string]string{},
			StartsAt:    at,
			Fingerprint: fingerprint,
		}},
	}
}

// foundationResolvedPayload builds a one-alert "resolved" Alertmanager v4
// envelope for the SAME fingerprint foundationGroupPayload used — the
// follow-up delivery TestFoundationReconstructionInvokesNoOutwardSurface
// needs to actually reach Correlator.applyResolvedDeliveryPlan's
// OnIncidentResolved branch, not just a fresh firing delivery that never
// exercises it.
func foundationResolvedPayload(group, alertname, fingerprint string, startsAt, endsAt time.Time) AlertmanagerPayload {
	return AlertmanagerPayload{
		Version:     "4",
		Status:      "resolved",
		GroupLabels: map[string]string{"group": group},
		Alerts: []AlertmanagerAlert{{
			Status:      "resolved",
			Labels:      map[string]string{"alertname": alertname, "group": group},
			Annotations: map[string]string{},
			StartsAt:    startsAt,
			EndsAt:      endsAt,
			Fingerprint: fingerprint,
		}},
	}
}

// openFoundationHost wires a real file-backed Store behind a real
// ingress.Server (one Alertmanager receiver, real Auditor) and returns an
// httptest.Server plus the Store and its on-disk path, so a test can POST
// over real HTTP and later close/reopen the SAME file to simulate a
// restart. wake, if non-nil, is called once per durably accepted envelope.
func openFoundationHost(t *testing.T, wake DeliveryWake) (*httptest.Server, *store.Store, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "foundation.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	host, err := New(Options{
		Store:     st,
		Auditor:   audit.New(st.DB()),
		Receivers: []Receiver{NewAlertReceiver(st, testToken, wake, nil)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	return srv, st, path
}

// postAndExpect204 POSTs payload and requires the durable-acceptance 204 —
// every Step 4 scenario in this file that reaches this helper is proving
// something downstream of a successful accept, never a rejection path.
func postAndExpect204(t *testing.T, srv *httptest.Server, payload AlertmanagerPayload) {
	t.Helper()
	resp := postPayload(t, srv, mustMarshal(t, payload), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", resp.StatusCode, mustReadBody(t, resp))
	}
}

// ----------------------------------------------------------------------
// Scenarios 1 + 2: receiver POST commits delivery and dispatch; close
// immediately before dispatch, reopen, reconstruct, and observe one
// Incident plus one Situation. Named per this task's plan so the release
// plan can retain it as a permanent smoke test.
// ----------------------------------------------------------------------

func TestFoundationReceiverRestartToSituation(t *testing.T) {
	ctx := context.Background()
	var wakes int
	srv, st, path := openFoundationHost(t, func() { wakes++ })

	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	postAndExpect204(t, srv, foundationGroupPayload("checkout", "HighLatency", "fp-restart", at))
	if wakes != 1 {
		t.Fatalf("wake calls = %d, want 1", wakes)
	}

	// Scenario 1: the POST alone commits an immutable delivery plus a
	// pending dispatch — nothing else has run yet.
	if got := countRows(t, st, `SELECT COUNT(*) FROM alert_deliveries`); got != 1 {
		t.Fatalf("alert_deliveries = %d, want 1", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status = 'pending'`); got != 1 {
		t.Fatalf("pending alert_delivery_dispatches = %d, want 1", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM incidents`); got != 0 {
		t.Fatalf("incidents before any dispatch worker ran = %d, want 0", got)
	}

	// Scenario 2: crash — close the store and the HTTP host before the
	// dispatch worker (never started in this test) claims anything.
	srv.Close()
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Restart against the same on-disk file.
	st2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st2, nil, nil)
	dispatch := correlator.NewDispatchWorker(st2, cor, correlator.WorkerConfig{Owner: "restart:dispatch"}, nil)
	inputs := situation.NewInputWorker(st2, situation.WorkerConfig{Owner: "restart:input"}, nil)
	r := situation.NewReconstructor(st2, func() time.Time { return at.Add(time.Minute) }).WithReplay(dispatch, inputs)

	report, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if report.ReplayedDeliveries != 1 {
		t.Fatalf("replayed deliveries = %d, want 1", report.ReplayedDeliveries)
	}
	if report.ReplayedInputs != 1 {
		t.Fatalf("replayed inputs = %d, want 1", report.ReplayedInputs)
	}
	if report.RepresentedGroups != 0 || report.RepresentedIncidents != 0 {
		t.Fatalf("report = %+v, want the fallback represent phase to find nothing (the queue drain already owns this Incident)", report)
	}

	if got := countRows(t, st2, `SELECT COUNT(*) FROM incidents`); got != 1 {
		t.Fatalf("incidents after restart = %d, want exactly 1", got)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM situations`); got != 1 {
		t.Fatalf("situations after restart = %d, want exactly 1", got)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM situation_incidents`); got != 1 {
		t.Fatalf("situation_incidents after restart = %d, want exactly 1", got)
	}
}

// ----------------------------------------------------------------------
// Scenario 5: replay the same Alertmanager POST before and after restart
// and observe one delivery-driven version increment.
// ----------------------------------------------------------------------

func TestFoundationReplayedPostAcrossRestartOneVersionIncrement(t *testing.T) {
	ctx := context.Background()
	srv, st, path := openFoundationHost(t, nil)

	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	payload := foundationGroupPayload("payments", "HighErrorRate", "fp-replay", at)

	postAndExpect204(t, srv, payload)

	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, nil, nil)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: "pre-restart:dispatch"}, nil)
	inputs := situation.NewInputWorker(st, situation.WorkerConfig{Owner: "pre-restart:input"}, nil)
	if _, err := dispatch.Drain(ctx); err != nil {
		t.Fatalf("pre-restart dispatch drain: %v", err)
	}
	if _, err := inputs.Drain(ctx); err != nil {
		t.Fatalf("pre-restart input drain: %v", err)
	}
	if got := countRows(t, st, `SELECT input_version FROM situations LIMIT 1`); got != 1 {
		t.Fatalf("input_version before restart = %d, want 1", got)
	}

	// Restart.
	srv.Close()
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	st2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	host2, err := New(Options{Store: st2, Auditor: audit.New(st2.DB()), Receivers: []Receiver{NewAlertReceiver(st2, testToken, nil, nil)}})
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}
	srv2 := httptest.NewServer(host2.Handler())
	t.Cleanup(srv2.Close)

	// Replay the byte-identical Alertmanager POST — same fingerprint, same
	// startsAt, same group — after the restart. The delivery digest is
	// deterministic (internal/ingress.payloadDigest), so this must resolve
	// to the SAME delivery id and commit no new dispatch.
	postAndExpect204(t, srv2, payload)

	cor2 := correlator.New(correlator.Config{WindowSeconds: 60}, st2, nil, nil)
	dispatch2 := correlator.NewDispatchWorker(st2, cor2, correlator.WorkerConfig{Owner: "post-restart:dispatch"}, nil)
	inputs2 := situation.NewInputWorker(st2, situation.WorkerConfig{Owner: "post-restart:input"}, nil)
	nDispatch, err := dispatch2.Drain(ctx)
	if err != nil {
		t.Fatalf("post-restart dispatch drain: %v", err)
	}
	if nDispatch != 0 {
		t.Fatalf("post-restart dispatch drained %d, want 0 (the replayed POST commits no new dispatch)", nDispatch)
	}
	if _, err := inputs2.Drain(ctx); err != nil {
		t.Fatalf("post-restart input drain: %v", err)
	}

	if got := countRows(t, st2, `SELECT COUNT(*) FROM alert_deliveries`); got != 1 {
		t.Fatalf("alert_deliveries after replay = %d, want exactly 1 (deduped by delivery id)", got)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM situations`); got != 1 {
		t.Fatalf("situations after replay = %d, want exactly 1", got)
	}
	if got := countRows(t, st2, `SELECT input_version FROM situations LIMIT 1`); got != 1 {
		t.Fatalf("input_version after replay across restart = %d, want 1 (one delivery-driven increment total, not two)", got)
	}
}

// ----------------------------------------------------------------------
// Scenario 6: POST two same-group members concurrently and observe one
// nonterminal Situation.
// ----------------------------------------------------------------------

func TestFoundationConcurrentSameGroupPostsOneNonterminalSituation(t *testing.T) {
	ctx := context.Background()
	srv, st, _ := openFoundationHost(t, nil)
	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	p1 := foundationGroupPayload("concurrent-group", "MemberOne", "fp-concurrent-1", at)
	p2 := foundationGroupPayload("concurrent-group", "MemberTwo", "fp-concurrent-2", at)

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp := postPayload(t, srv, mustMarshal(t, p1), nil)
		statuses[0] = resp.StatusCode
		_ = resp.Body.Close()
	}()
	go func() {
		defer wg.Done()
		resp := postPayload(t, srv, mustMarshal(t, p2), nil)
		statuses[1] = resp.StatusCode
		_ = resp.Body.Close()
	}()
	wg.Wait()
	for i, code := range statuses {
		if code != http.StatusNoContent {
			t.Fatalf("post %d status = %d, want 204", i, code)
		}
	}

	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, nil, nil)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{Owner: "concurrent:dispatch"}, nil)
	inputs := situation.NewInputWorker(st, situation.WorkerConfig{Owner: "concurrent:input"}, nil)
	if _, err := dispatch.Drain(ctx); err != nil {
		t.Fatalf("drain dispatch: %v", err)
	}
	if _, err := inputs.Drain(ctx); err != nil {
		t.Fatalf("drain inputs: %v", err)
	}

	if got := countRows(t, st, `SELECT COUNT(*) FROM alert_deliveries`); got != 2 {
		t.Fatalf("alert_deliveries = %d, want 2 (both members committed)", got)
	}
	// Both members share one exact group and one fixed correlation window,
	// so the Correlator itself (not the Situation layer) already merges
	// them into one Incident — attachment order depends on which of the
	// two concurrent POSTs' dispatch the drain applies first, so this
	// asserts the count, not which delivery "won" first.
	if got := countRows(t, st, `SELECT COUNT(*) FROM incidents`); got != 1 {
		t.Fatalf("incidents = %d, want exactly 1 (one exact group, one collecting window)", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM incident_alert_deliveries`); got != 2 {
		t.Fatalf("incident_alert_deliveries = %d, want 2 (both concurrently-posted members attached to the one incident)", got)
	}

	// The exact-group invariant this scenario exists to prove: at most
	// (here, exactly) one nonterminal Situation for the group both
	// concurrent members share, regardless of how their two POSTs
	// interleaved at the HTTP layer.
	var groupKey string
	if err := st.DB().QueryRowContext(ctx, `SELECT group_key FROM situations LIMIT 1`).Scan(&groupKey); err != nil {
		t.Fatalf("read situation group_key: %v", err)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM situations WHERE lifecycle IN ('active','recovery_pending') AND group_key = ?`, groupKey); got != 1 {
		t.Fatalf("nonterminal situations for group %q = %d, want exactly 1", groupKey, got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM situations`); got != 1 {
		t.Fatalf("total situations = %d, want exactly 1 (both members landed in the same exact group)", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM situation_incidents WHERE situation_id = (SELECT id FROM situations LIMIT 1)`); got != 1 {
		t.Fatalf("situation membership = %d, want 1 (the one incident both members were correlated into)", got)
	}
}

// ----------------------------------------------------------------------
// Scenario 8: inject a Store acceptance failure and prove HTTP 503 with
// zero committed rows.
// ----------------------------------------------------------------------

func TestFoundationStoreAcceptanceFailureReturns503WithZeroCommittedRows(t *testing.T) {
	ctx := context.Background()
	srv, st, path := openFoundationHost(t, nil)
	defer srv.Close()

	// Inject a real Store acceptance failure — not a stub Receiver — by
	// closing the underlying database connection out from under the real
	// alertReceiver AcceptDeliveries call is about to make.
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	resp := postPayload(t, srv, mustMarshal(t, foundationGroupPayload("durability-fail", "WillFail", "fp-fail", at)), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body := mustReadBody(t, resp)
	if !strings.Contains(body, "delivery could not be persisted; retry later") {
		t.Errorf("body = %q, want the fixed public durability message", body)
	}
	if strings.Contains(strings.ToLower(body), "database is closed") || strings.Contains(strings.ToLower(body), "sql:") {
		t.Errorf("body = %q, must not leak the underlying driver error", body)
	}

	// Zero committed rows: verified from a SEPARATE connection to the same
	// on-disk file, not the (now closed) connection that just failed.
	second, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if got := countRows(t, second, `SELECT COUNT(*) FROM alert_deliveries`); got != 0 {
		t.Fatalf("alert_deliveries after a failed acceptance = %d, want 0", got)
	}
	if got := countRows(t, second, `SELECT COUNT(*) FROM alert_delivery_dispatches`); got != 0 {
		t.Fatalf("alert_delivery_dispatches after a failed acceptance = %d, want 0", got)
	}
	if got := countRows(t, second, `SELECT COUNT(*) FROM audit_log`); got != 0 {
		t.Fatalf("audit_log after a failed acceptance = %d, want 0", got)
	}
}

// ----------------------------------------------------------------------
// Scenario 9: assert no Situation Slack/notifier, connector, LLM, or audit
// fake is invoked by reconstruction.
//
// There is structurally no LLM or connector call reachable from this
// path at all: Reconstructor.Run's dispatch.Drain only ever calls
// Correlator.ApplyDelivery, never starts the Correlator's own ticker loop
// (cor.Start), and the acute-triage skill — the only code in this
// codebase that ever calls the LLM — is wired as the ticker-driven
// window-expiry sink, not anything ApplyDelivery reaches directly. What
// IS reachable from ApplyDelivery, and so needs an explicit fake to prove
// silent, is the Correlator's own outward surface: its IncidentSink,
// ResolutionNotifier, OccurrenceNotifier, and Auditor.
//
// A lone fresh firing delivery reaches NONE of those four — resolution,
// occurrence, and audit calls only trigger on resolved/recurrence/retry-
// attach paths a single firing delivery never exercises, which would make
// a bare zero-calls assertion vacuous (it would pass identically whether
// or not reconstruction ever wired a notifier early). So this fixture
// queues TWO follow-ups that stay pending across the crash: a resolved
// delivery for the first group's "ready" Incident, which routes through
// Correlator.applyResolvedDeliveryPlan and its
// "result.Resolved && c.resolutionNotifier != nil" check before calling
// OnIncidentResolved; and a firing delivery for a second group's judged
// Incident, which routes through applyRecurrenceDeliveryPlan and its
// occurrence-notifier and incident.occurrence_attached auditor calls.
// Reconstruction drains both, so this really does reach the outward
// surface: the test asserts the first Incident actually resolved and the
// second actually gained an occurrence (proving both branches were hit),
// separately from asserting the fakes saw zero calls.
//
// There is no structural guard inside Reconstructor/DispatchWorker that
// suppresses notifications during a reconstruction pass — the SAME
// Correlator/DispatchWorker instance drains dispatches during
// reconstruction and during ordinary live operation afterward. The only
// thing that keeps reconstruction silent in production is cmd/alertint's
// wiring order (see cmd/alertint/main.go's foundationSequence):
// SetAuditor/SetResolutionNotifier/SetOccurrenceNotifier are called only
// from startCorrelator, strictly AFTER Reconstruct() returns — the fix
// for the exact ordering bug internal/situation/reconstruct_test.go's
// TestNotifiersWiredBeforeReconstructionWouldLeakOutward (Task 8) proves
// would otherwise leak. This test reproduces that same safe ordering
// (wire only the IncidentSink immediately — matching cmd/alertint, and
// harmless since it is not reachable from this fixture — then wire
// Auditor/ResolutionNotifier/OccurrenceNotifier only after Run returns) so
// its zero-calls assertion is a real consequence of that discipline, not
// an artifact of a fixture that could never reach the branch regardless
// of wiring order. This complements, not duplicates,
// internal/situation/reconstruct_test.go's own pair of tests (Task 8) at
// the correlator-internals level; this one is driven from the real
// receiver HTTP boundary, through a crash and restart.
// ----------------------------------------------------------------------

type foundationOutwardSpy struct {
	mu    sync.Mutex
	calls int
}

func (s *foundationOutwardSpy) OnIncidentReady(context.Context, store.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return nil
}
func (s *foundationOutwardSpy) OnIncidentResolved(context.Context, store.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return nil
}
func (s *foundationOutwardSpy) OnOccurrenceAttached(context.Context, notify.RecurrenceEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return nil
}
func (s *foundationOutwardSpy) Append(context.Context, string, string, any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return nil
}

func (s *foundationOutwardSpy) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestFoundationReconstructionInvokesNoOutwardSurface(t *testing.T) {
	ctx := context.Background()
	srv, st, path := openFoundationHost(t, nil)

	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	postAndExpect204(t, srv, foundationGroupPayload("silent-reconstruction", "Quiet", "fp-silent", at))

	// Correlate and settle the firing delivery to "ready" BEFORE the crash,
	// with a plain (no notifier) Correlator — ordinary pre-crash server
	// operation, not the property under test. Without this, the resolved
	// follow-up below would land on a still-"collecting" Incident and
	// never reach the resolved-Incident notify branch at all.
	preCrashCor := correlator.New(correlator.Config{WindowSeconds: 60}, st, nil, nil)
	preCrashDispatch := correlator.NewDispatchWorker(st, preCrashCor, correlator.WorkerConfig{Owner: "precrash:dispatch"}, nil)
	if _, err := preCrashDispatch.Drain(ctx); err != nil {
		t.Fatalf("pre-crash dispatch drain: %v", err)
	}
	var incidentID string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM incidents LIMIT 1`).Scan(&incidentID); err != nil {
		t.Fatalf("read incident id: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}

	// A second group seeds the OTHER outward branch: a judged Incident whose
	// queued firing follow-up recurrence-collapses DURING reconstruction —
	// the path that appends the incident.occurrence_attached audit event and
	// calls the occurrence notifier (applyRecurrenceDeliveryPlan). Without
	// it, the Auditor half of the zero-calls assertion would be vacuous: no
	// fixture branch could reach an audit site regardless of when the
	// Auditor was wired. This whole block runs BEFORE either follow-up is
	// posted — its drain applies every dispatch pending at that moment, so
	// the two follow-ups must only be queued after it.
	postAndExpect204(t, srv, foundationGroupPayload("silent-recurrence", "Noisy", "fp-noisy-1", at))
	if _, err := preCrashDispatch.Drain(ctx); err != nil {
		t.Fatalf("pre-crash dispatch drain (second group): %v", err)
	}
	var judgedID string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM incidents WHERE id <> ?`, incidentID).Scan(&judgedID); err != nil {
		t.Fatalf("read second incident id: %v", err)
	}
	// Judge it directly (status + last_judged_at are all the recurrence
	// planner reads) so the follow-up below is a genuine recurrence
	// candidate, not a join into a still-collecting window. Wall-clock
	// time, because the recurrence horizon compares against the follow-up
	// delivery's real HTTP receipt time.
	judgedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().ExecContext(ctx, `UPDATE incidents SET status='analyzed', last_judged_at=?, updated_at=? WHERE id=?`, judgedAt, judgedAt, judgedID); err != nil {
		t.Fatalf("judge second incident: %v", err)
	}

	// Both follow-ups stay queued (pending dispatches) across the crash:
	// reconstruction, not any live worker, is what must drain them.
	//
	// The resolved follow-up reuses the FIRST group's fingerprint. Once
	// that Incident is "ready" (not "collecting"), applying a resolved
	// delivery for its only member routes through
	// Correlator.applyResolvedDeliveryPlan, which fully resolves the
	// Incident and explicitly checks
	// result.Resolved && c.resolutionNotifier != nil before calling
	// OnIncidentResolved — the notifier surface a Task-8-style ordering
	// bug would leak from.
	postAndExpect204(t, srv, foundationResolvedPayload("silent-reconstruction", "Quiet", "fp-silent", at, at.Add(time.Minute)))
	postAndExpect204(t, srv, foundationGroupPayload("silent-recurrence", "Noisy", "fp-noisy-2", at.Add(time.Minute)))

	srv.Close()
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	st2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	// The pre-crash POSTs above already appended their own "alert.received"
	// audit rows through the real receiver/Auditor path — that is normal
	// receiver acknowledgment, not reconstruction, so this test compares
	// the count reconstruction itself adds, not the table's raw total.
	auditBefore := countRows(t, st2, `SELECT COUNT(*) FROM audit_log`)

	spy := &foundationOutwardSpy{}
	// Only the IncidentSink is wired from construction, matching
	// cmd/alertint's real ordering exactly (see the comment block above) —
	// harmless here since this fixture never reaches its call site.
	// Auditor, ResolutionNotifier, and OccurrenceNotifier are deliberately
	// NOT wired yet: cmd/alertint only wires those from startCorrelator,
	// strictly after Reconstruct() returns, because this fixture's queued
	// follow-ups DO reach all three call sites during the reconstruction
	// drain.
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st2, spy, nil)

	dispatch := correlator.NewDispatchWorker(st2, cor, correlator.WorkerConfig{Owner: "silent:dispatch"}, nil)
	inputs := situation.NewInputWorker(st2, situation.WorkerConfig{Owner: "silent:input"}, nil)
	r := situation.NewReconstructor(st2, func() time.Time { return at.Add(time.Hour) }).WithReplay(dispatch, inputs)

	report, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if report.ReplayedDeliveries != 2 {
		t.Fatalf("replayed deliveries = %d, want 2 (the queued resolved follow-up and the queued recurrence follow-up; the initial firing deliveries were already applied pre-crash)", report.ReplayedDeliveries)
	}
	if report.ReplayedInputs < 1 {
		t.Fatalf("replayed inputs = %d, want at least 1", report.ReplayedInputs)
	}

	// Prove the fixture actually reached the branch this test exists to
	// guard: the Incident really did resolve during reconstruction — only
	// the NOTIFICATION must have been suppressed, not the resolution
	// itself. Without this check, a bug that skipped resolution entirely
	// would also read as "zero outward calls" and pass for the wrong
	// reason. Confirmed empirically too: wiring SetResolutionNotifier
	// BEFORE r.Run above (the unsafe order Task 8 fixed) makes this exact
	// fixture deliver exactly one OnIncidentResolved call — proof this
	// fixture is live, not inert.
	var incidentStatus string
	if err := st2.DB().QueryRowContext(ctx, `SELECT status FROM incidents WHERE id = ?`, incidentID).Scan(&incidentStatus); err != nil {
		t.Fatalf("read incident status: %v", err)
	}
	if incidentStatus != "resolved" {
		t.Fatalf("incident status after reconstruction = %s, want resolved (otherwise this test is vacuous)", incidentStatus)
	}

	// Same proof for the second branch: the queued firing follow-up really
	// did collapse into the judged Incident as an occurrence during
	// reconstruction — only the audit append and the notification must have
	// been suppressed, never the durable attach itself.
	if got := countRows(t, st2, `SELECT COUNT(*) FROM incident_occurrences WHERE incident_id = ?`, judgedID); got != 1 {
		t.Fatalf("occurrences on judged incident after reconstruction = %d, want 1 (otherwise the audit half of this test is vacuous)", got)
	}

	if got := spy.total(); got != 0 {
		t.Fatalf("outward calls during reconstruction (IncidentSink only — Auditor/ResolutionNotifier/OccurrenceNotifier not wired yet) = %d, want 0", got)
	}

	// NOW wire the deferred outward surface, exactly where cmd/alertint's
	// startCorrelator does: strictly after reconstruction, never before.
	cor.SetAuditor(spy)
	cor.SetResolutionNotifier(spy)
	cor.SetOccurrenceNotifier(spy)
	if got := spy.total(); got != 0 {
		t.Fatalf("wiring the deferred outward surface after reconstruction must not itself trigger a call: got %d", got)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM audit_log`); got != auditBefore {
		t.Fatalf("audit_log rows: %d before reconstruction, %d after — reconstruction itself must never audit", auditBefore, got)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM situations`); got != 2 {
		t.Fatalf("situations = %d, want exactly 2 (one per fixture group)", got)
	}
}

// countRows runs a literal (never concatenated) COUNT/scalar query and
// returns the result. Shared by every Step 4 scenario in this file.
func countRows(t *testing.T, st *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}
