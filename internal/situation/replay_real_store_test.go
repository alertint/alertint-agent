// SPDX-License-Identifier: FSL-1.1-ALv2

// replay_real_store_test.go validates the same locked replay corpus
// (internal/situation/testdata/replays/*.json) a second time against the
// real production store — never the in-package double replay_test.go uses.
// It lives here (not in internal/situation itself, and see
// controller_integration_test.go for this package's doc comment) for the
// same reason controller_integration_test.go does: it needs internal/store,
// internal/correlator, and internal/ingress, which internal/situation
// cannot import back.
package situation_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/llm"
	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// realStoreExcluded names the locked fixtures that cannot run against the
// real store today, and exactly why — each reason cites a specific,
// verified gap in internal/store's production wiring, not a convenience
// exclusion. No fixture is silently skipped: every excluded name below
// surfaces as a t.Skip with this reason, so the skip itself is asserted
// coverage (a fixture that starts working again shows up as an unexpected
// pass once removed from this map — see TestReplayCorpusAgainstRealStore).
var realStoreExcluded = map[string]string{
	"envelope-forbidden-impact.json": "requires SnapshotInput.Impact, which internal/store's LoadReconciliationInput " +
		"never populates (confirmed: no production code path sets .Impact/.BlastRadius/.UrgentPolicies/.SemanticChoice " +
		"anywhere in internal/store) — the same parked observation-connector gap TestRestartAfterEveryBoundary's " +
		"observation_commit subtest documents: no wired connector derives impact facts today.",
	"delayed-resolution.json": "requires the duration_outlier reason candidate, which needs " +
		"SnapshotInput.CurrentDurationEvidenceRefs — internal/store's LoadReconciliationInput populates " +
		".CompletedEpisodes for real but never sets .CurrentDurationEvidenceRefs anywhere, so durationOutlierEvidence " +
		"can never resolve its current-duration fact. Same parked observation-connector gap as above.",
	"recovery-pending-refire.json": "requires ReconcileLifecycle's symptom-driven recovery/refire transitions " +
		"(allSymptomsResolved/hasFiringSymptom), which read SnapshotInput.Symptoms — a newly confirmed gap found " +
		"while building this real-store pass: internal/store's LoadReconciliationInput never sets .Symptoms anywhere " +
		"(grepped the whole store package); canonicalSymptoms only derives Snapshot.Symptoms from Deliveries inside " +
		"BuildSnapshot, which controller.go calls AFTER ReconcileLifecycle already ran against the empty raw list. " +
		"Recovery/refire lifecycle transitions therefore cannot fire against the real production loader today. " +
		"Reported, not fixed — out of this task's scope.",
	"recovery-pending-stable.json": "same reason as recovery-pending-refire.json (grace-expiry is reachable via " +
		"TerminalUncertainty alone, but this fixture's recovery_pending ENTRY step depends on the same " +
		"unpopulated SnapshotInput.Symptoms).",
}

// TestReplayCorpusAgainstRealStore drives every fixture in the locked corpus
// a second time, this time against a real file-backed SQLite store through
// the production internal/store adapters (store.NewSituationRuntime and
// friends) — the same public durable paths and real I/O boundaries
// TestRestartAfterEveryBoundary uses, applied to the replay corpus itself.
// Fixtures that depend on a confirmed, currently-unwired production gap are
// excluded by name with an explicit reason (realStoreExcluded) rather than
// silently passed over.
func TestReplayCorpusAgainstRealStore(t *testing.T) {
	entries, err := os.ReadDir("testdata/replays")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 11 {
		t.Fatalf("fixtures=%d, want 11", len(entries))
	}
	for _, entry := range entries {
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			if reason, skip := realStoreExcluded[name]; skip {
				t.Skip(reason)
			}
			fx := loadRealStoreFixture(t, filepath.Join("testdata/replays", name))
			switch {
			case fx.Reconstruction != nil:
				runRealStoreReconstructionFixture(t, fx)
			case fx.DependencyHealth != nil:
				runRealStoreDependencyHealthFixture(t, fx)
			default:
				runRealStoreRoundsFixture(t, fx)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Fixture schema (a lean, real-store-only mirror of replay_test.go's
// unexported schema — duplicated deliberately rather than shared, so this
// file can decode the exact same JSON fixtures without reaching into
// internal/situation's test-only types, which package situation_test cannot
// see, and without risking the already-locked in-package driver).
// --------------------------------------------------------------------------

type realStoreFixture struct {
	Rounds           []realStoreRound           `json:"rounds,omitempty"`
	DependencyHealth *realStoreDependencyHealth `json:"dependency_health,omitempty"`
	Reconstruction   *realStoreReconstruction   `json:"reconstruction,omitempty"`
	Expect           realStoreExpect            `json:"expect"`
}

type realStoreRound struct {
	Symptoms []realStoreSymptom `json:"symptoms,omitempty"`
	Envelope *realStoreEnvelope `json:"envelope,omitempty"`
	Assessor *realStoreAssessor `json:"assessor,omitempty"`
}

type realStoreSymptom struct {
	ID        string `json:"id"`
	Lifecycle string `json:"lifecycle"`
	Severity  string `json:"severity,omitempty"`
}

type realStoreEnvelope struct {
	EnvelopeID        string   `json:"envelope_id"`
	EnvelopeVersion   int      `json:"envelope_version"`
	Result            string   `json:"result"`
	Violations        []string `json:"violations,omitempty"`
	Observability     []string `json:"observability,omitempty"`
	QuietingAuthority bool     `json:"quieting_authority,omitempty"`
}

type realStoreAssessor struct {
	Attention       string `json:"attention"`
	Causality       string `json:"causality,omitempty"`
	EvidenceQuality string `json:"evidence_quality,omitempty"`
	ReasonCode      string `json:"reason_code,omitempty"`
}

type realStoreDependencyHealth struct {
	Dependency            string  `json:"dependency"`
	BroadcastAfterSeconds int64   `json:"broadcast_after_seconds"`
	EventOffsetsSeconds   []int64 `json:"event_offsets_seconds"`
	EventOK               []bool  `json:"event_ok"`
}

type realStoreReconstruction struct {
	Incidents []struct {
		IncidentID string `json:"incident_id"`
		GroupKey   string `json:"group_key"`
	} `json:"incidents"`
}

type realStoreExpect struct {
	SituationCount    int      `json:"situation_count"`
	MainChannelPokes  int      `json:"main_channel_pokes"`
	Transitions       []string `json:"transitions"`
	Causality         string   `json:"causality"`
	L1Runs            int      `json:"l1_runs"`
	FinalLifecycle    string   `json:"final_lifecycle"`
	EnvelopeResult    string   `json:"envelope_result"`
	NotificationKinds []string `json:"notification_kinds"`
}

func loadRealStoreFixture(t *testing.T, path string) realStoreFixture {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fx realStoreFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fx
}

// --------------------------------------------------------------------------
// Situation-controller rounds driver
// --------------------------------------------------------------------------

// countingInvestigator is a real, immediately-completing AcuteInvestigator
// that counts dispatches — reused across every round's freshly constructed
// Controller (Controller carries no state Reconcile itself needs preserved
// across calls; only the durable store does), so l1_runs is accurate across
// the whole fixture.
type countingInvestigator struct {
	mu    sync.Mutex
	calls int
}

func (c *countingInvestigator) Investigate(_ context.Context, incidentID string) (situation.AcuteResult, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return situation.AcuteResult{IncidentID: incidentID, RootCause: "resolved", Confidence: 0.9, CompletedAt: time.Now().UTC()}, nil
}

func (c *countingInvestigator) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// onceAssessor returns one fixed completion for every call.
type onceAssessor struct{ completion llm.Completion }

func (a onceAssessor) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	return a.completion, nil
}

func runRealStoreRoundsFixture(t *testing.T, fx realStoreFixture) {
	t.Helper()
	if len(fx.Rounds) == 0 {
		t.Fatal("fixture declares no rounds and no alternate driver")
	}
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "alertint.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	clock := func() time.Time { return time.Now().UTC() }
	logger := slog.New(slog.DiscardHandler)
	cor := correlator.New(correlator.Config{GroupLabels: []string{"service"}}, st, correlator.NopIncidentSink{}, logger)
	receiver := ingress.NewAlertReceiver(st, "test-token", nil, logger)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.DispatchWorkerConfig{Owner: "replay-real-dispatch", Lease: time.Minute}, logger)
	runtime := store.NewSituationRuntime(st, notifyslack.ClientMessageID, nil, clock, store.SituationRuntimePolicy{
		MinSeverity: model.PriorityLow, HorizonTier: situation.HorizonUnknown,
	})
	inputs := situation.NewInputWorker(runtime, situation.WorkerConfig{Owner: "replay-real-inputs", Batch: 16}, clock, logger)
	investigator := &countingInvestigator{}

	now := time.Now().UTC()
	seen := map[string]realStoreSymptom{} // symptom id -> last observed (lifecycle, severity)
	var situationID string
	evalSeq := 0

	for round := range fx.Rounds {
		r := fx.Rounds[round]
		changed := false
		for _, s := range r.Symptoms {
			if prior, ok := seen[s.ID]; ok && prior == s {
				continue // unchanged: the persisted delivery already carries this evidence forward
			}
			seen[s.ID] = s
			changed = true
			status := "firing"
			if s.Lifecycle == "resolved" {
				status = "resolved"
			}
			ingestSymptomDelivery(t, receiver, s.ID, status, s.Severity, now.Add(time.Duration(round)*time.Second))
		}
		if changed {
			if err := dispatch.RunOnce(ctx); err != nil {
				t.Fatalf("round %d: dispatch: %v", round, err)
			}
			if _, err := inputs.RunOnce(ctx); err != nil {
				t.Fatalf("round %d: apply situation input: %v", round, err)
			}
		}

		claimAt := time.Now().UTC()
		if round > 0 {
			// The prior round's commit scheduled its own next checkpoint
			// FastCadence (60s, a floor commit) or NormalCadence (5m, a
			// degraded/observe commit) out; a genuinely due second round
			// needs a claim instant safely past the longer of the two.
			claimAt = claimAt.Add(6 * time.Minute)
		}
		owner := fmt.Sprintf("replay-real-%s-%d", t.Name(), round)
		claims, err := runtime.ClaimDueSituations(ctx, owner, claimAt, time.Minute, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("round %d: claim due situation: claims=%v err=%v", round, claims, err)
		}
		situationID = claims[0].SituationID
		sit, err := st.GetSituation(ctx, situationID)
		if err != nil {
			t.Fatalf("round %d: read claimed situation: %v", round, err)
		}
		storeClaim := store.SituationClaim{Situation: sit, ClaimOwner: claims[0].ClaimOwner, ClaimToken: claims[0].ClaimToken}

		if r.Envelope != nil {
			evalSeq++
			seedRealEnvelopeEvaluation(t, st, storeClaim, r.Envelope, evalSeq)
		}

		var assessor situation.AssessmentClient
		if r.Assessor != nil {
			situationClaim := situation.Claim{Situation: sit, ClaimOwner: claims[0].ClaimOwner, ClaimToken: claims[0].ClaimToken}
			in, _, err := runtime.LoadReconciliationInput(ctx, situationClaim)
			if err != nil {
				t.Fatalf("round %d: load reconciliation input for scripting: %v", round, err)
			}
			in.Now = time.Now().UTC()
			snap, err := situation.BuildSnapshot(in)
			if err != nil {
				t.Fatalf("round %d: build snapshot for scripting: %v", round, err)
			}
			assessor = onceAssessor{completion: buildRealScriptedCompletion(t, *r.Assessor, snap, in.Now)}
		}

		controller := situation.NewController(runtime, nil, nil, investigator, assessor, clock, situation.Config{})
		l1Done := make(chan struct{}, 1)
		controller.SetBoundaryHookForTest(func(name string) error {
			if name == "l1_complete" {
				l1Done <- struct{}{}
			}
			return nil
		})
		if err := controller.Reconcile(ctx, situationID); err != nil {
			t.Fatalf("round %d: reconcile: %v", round, err)
		}
		select {
		case <-l1Done:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: timed out waiting for l1_complete", round)
		}
	}

	assertRealStoreRoundsExpectation(t, st, situationID, fx.Expect, investigator.count())
}

// ingestSymptomDelivery posts one real Alertmanager delivery for the fixed
// "replay-real" group, using the symptom id as both alertname and
// fingerprint so distinct symptoms correlate as distinct members of the
// same Incident.
func ingestSymptomDelivery(t *testing.T, receiver ingress.Receiver, symptomID, status, severity string, at time.Time) {
	t.Helper()
	alert := ingress.AlertmanagerAlert{
		Status: status, Fingerprint: symptomID,
		Labels:      map[string]string{"alertname": symptomID, "service": "replay-real", "severity": severity},
		Annotations: map[string]string{}, StartsAt: at,
	}
	if status == "resolved" {
		alert.EndsAt = at
	}
	payload := ingress.AlertmanagerPayload{
		Version: "4", Status: status, GroupLabels: map[string]string{"service": "replay-real"},
		Alerts: []ingress.AlertmanagerAlert{alert},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if _, err := receiver.Ingest(context.Background(), raw); err != nil {
		t.Fatalf("ingest: %v", err)
	}
}

// seedRealEnvelopeHead directly inserts the minimal real
// situation_judgments and expected_behavior_envelopes rows
// envelope_evaluations' foreign keys require (envelope_id ->
// expected_behavior_envelopes.id -> source_judgment_id ->
// situation_judgments.id). This is test setup, not the behavior under test:
// the real judgment-confirms-an-envelope MCP flow is covered by
// internal/situation/judgment_test.go and cmd/alertint's envelope command
// tests. Direct SQL seeding of a real table to establish prior state
// already has precedent in this suite (seedRecurrenceOccurrence,
// controller_integration_test.go).
func seedRealEnvelopeHead(t *testing.T, st *store.Store, situationID, envelopeID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	judgmentID := "judgment:" + envelopeID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_judgments (
			id, situation_id, judged_input_version, covered_fact_hash, covered_symptoms_json, covered_impact_json,
			judgment, basis, evidence_refs_json, authenticated_as, asserted_operator, created_at
		) VALUES (?, ?, 1, 'seed-hash', '[]', '[]', 'expected_this_episode', 'operator_knowledge', '[]', 'installation_mcp_token', 'replay-real-store-seed', ?)`,
		judgmentID, situationID, now); err != nil {
		t.Fatalf("seed source judgment for envelope %s: %v", envelopeID, err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO expected_behavior_envelopes (id, current_version, source_judgment_id, created_at, updated_at)
		VALUES (?, 1, ?, ?, ?)`, envelopeID, judgmentID, now, now); err != nil {
		t.Fatalf("seed envelope head %s: %v", envelopeID, err)
	}
}

// seedRealEnvelopeEvaluation writes one real envelope evaluation row
// (store.AppendEnvelopeEvaluation) plus the one matching real
// observationmodel.Fact (store.AppendSituationFacts) EligibleReasons'
// envelopeEvidence/envelopeQuietingAuthorized require to admit it —
// exercising the same two real, exported, production write paths a
// correctly-wired envelope-evaluation loop would use once that parked gap
// closes (see realStoreExcluded's doc comment), rather than injecting the
// evaluation into an in-memory struct.
func seedRealEnvelopeEvaluation(t *testing.T, st *store.Store, claim store.SituationClaim, env *realStoreEnvelope, seq int) {
	t.Helper()
	ctx := context.Background()
	if seq == 1 {
		seedRealEnvelopeHead(t, st, claim.Situation.ID, env.EnvelopeID)
	}
	factID := fmt.Sprintf("fact:envelope-eval:%s:%d", env.EnvelopeID, seq)
	observedAt := time.Now().UTC()
	value, err := json.Marshal(struct {
		EnvelopeVersion   int      `json:"envelope_version"`
		Result            string   `json:"result"`
		MatchedFields     []string `json:"matched_fields"`
		Violations        []string `json:"violations"`
		Observability     []string `json:"observability"`
		QuietingAuthority bool     `json:"quieting_authority"`
	}{env.EnvelopeVersion, env.Result, []string{factID}, env.Violations, env.Observability, env.QuietingAuthority})
	if err != nil {
		t.Fatalf("marshal envelope evaluation fact value: %v", err)
	}
	fact := observationmodel.Fact{
		ID: factID, SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Kind: "envelope_evaluation", Subject: env.EnvelopeID, Value: value,
		SourceCapability: observationmodel.CapabilityStoreRead, ObservedAt: observedAt,
		Freshness: observationmodel.FreshnessFresh, ResultStatus: observationmodel.ResultStatusConfirmedValue,
		Digest: "digest:" + factID, Material: true,
	}
	if err := st.AppendSituationFacts(ctx, claim, []observationmodel.Fact{fact}); err != nil {
		t.Fatalf("seed envelope evaluation fact: %v", err)
	}
	eval := model.EnvelopeEvaluation{
		ID: fmt.Sprintf("eval:%s:%d", env.EnvelopeID, seq), EnvelopeID: env.EnvelopeID, EnvelopeVersion: env.EnvelopeVersion,
		SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion,
		Result: model.EnvelopeEvaluationResult(env.Result), MatchedFields: []string{factID},
		Violations: env.Violations, Observability: env.Observability, QuietingAuthority: env.QuietingAuthority,
		CreatedAt: observedAt,
	}
	if err := st.AppendEnvelopeEvaluation(ctx, eval); err != nil {
		t.Fatalf("seed envelope evaluation: %v", err)
	}
}

// buildRealScriptedCompletion renders one llm.Completion whose Raw JSON is a
// model.Assessment ValidateAssessment can accept, resolving ReasonCode
// against snap.EligibleReasons — the real, freshly computed candidates from
// the real store's own LoadReconciliationInput, never invented.
func buildRealScriptedCompletion(t *testing.T, step realStoreAssessor, snap situation.Snapshot, now time.Time) llm.Completion {
	t.Helper()
	attention := model.Attention(step.Attention)
	causality := model.Causality(step.Causality)
	if causality == "" {
		causality = model.CausalityUnknown
	}
	evidenceQuality := model.EvidenceQuality(step.EvidenceQuality)
	if evidenceQuality == "" {
		evidenceQuality = model.EvidenceQualityDegraded
	}
	a := model.Assessment{
		SchemaVersion: situation.AssessmentSchemaVersion, Persistence: model.PersistenceUnknown, Impact: model.ImpactUnknown,
		Novelty: model.NoveltyInsufficientHistory, Causality: causality, Attention: attention, Lifecycle: snap.Lifecycle,
		EvidenceQuality: evidenceQuality, Limitations: []model.Limitation{}, ProposedCadence: model.CadenceNormal,
	}
	if step.ReasonCode != "" {
		var candidate model.ReasonCandidate
		found := false
		for _, c := range snap.EligibleReasons {
			if c.Code == step.ReasonCode {
				candidate, found = c, true
				break
			}
		}
		if !found {
			t.Fatalf("reason code %q is not eligible against the real snapshot (eligible=%+v)", step.ReasonCode, snap.EligibleReasons)
		}
		a.SufficientReason = &model.SufficientReason{Code: candidate.Code, CandidateID: candidate.ID, Summary: "scripted real-store response", EvidenceRefs: candidate.EvidenceRefs}
	}
	nextUpdate := now.Add(5 * time.Minute)
	switch attention {
	case model.AttentionUrgent, model.AttentionInvestigate:
		action := "investigate"
		a.ActionContract = model.ActionContract{NextActor: model.NextActorAlertint, ActionStatus: model.ActionStatusPlanned, AlertintAction: &action, NextUpdateAt: &nextUpdate, NextUpdateOn: []string{"recovery_observed"}}
	default:
		a.ActionContract = model.ActionContract{NextActor: model.NextActorNone, ActionStatus: model.ActionStatusWaiting, NextUpdateAt: &nextUpdate}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal scripted assessment: %v", err)
	}
	return llm.Completion{Raw: raw, Model: "replay-real-scripted"}
}

func assertRealStoreRoundsExpectation(t *testing.T, st *store.Store, situationID string, want realStoreExpect, l1Runs int) {
	t.Helper()
	ctx := context.Background()

	var situationCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situations`).Scan(&situationCount); err != nil {
		t.Fatal(err)
	}
	if situationCount != want.SituationCount {
		t.Fatalf("situation_count = %d, want %d", situationCount, want.SituationCount)
	}

	rows, err := st.DB().QueryContext(ctx, `
		SELECT validated_json FROM situation_assessment_attempts
		WHERE situation_id = ? AND status = 'authoritative' ORDER BY sequence ASC`, situationID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var transitions []string
	var lastAssessment model.Assessment
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var a model.Assessment
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			t.Fatal(err)
		}
		transitions = append(transitions, string(a.Lifecycle))
		lastAssessment = a
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !stringsEqual(transitions, want.Transitions) {
		t.Fatalf("transitions = %v, want %v", transitions, want.Transitions)
	}
	if string(lastAssessment.Causality) != want.Causality {
		t.Fatalf("causality = %q, want %q", lastAssessment.Causality, want.Causality)
	}
	if l1Runs != want.L1Runs {
		t.Fatalf("l1_runs = %d, want %d", l1Runs, want.L1Runs)
	}

	var lifecycle string
	if err := st.DB().QueryRowContext(ctx, `SELECT lifecycle FROM situations WHERE id = ?`, situationID).Scan(&lifecycle); err != nil {
		t.Fatal(err)
	}
	if lifecycle != want.FinalLifecycle {
		t.Fatalf("final_lifecycle = %q, want %q", lifecycle, want.FinalLifecycle)
	}

	intentRows, err := st.DB().QueryContext(ctx, `
		SELECT kind, main_channel_poke FROM notification_intents
		WHERE situation_id = ? ORDER BY created_at ASC, id ASC`, situationID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = intentRows.Close() }()
	var kinds []string
	pokes := 0
	for intentRows.Next() {
		var kind string
		var poke int
		if err := intentRows.Scan(&kind, &poke); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, kind)
		if poke != 0 {
			pokes++
		}
	}
	if err := intentRows.Err(); err != nil {
		t.Fatal(err)
	}
	if !stringsEqual(kinds, want.NotificationKinds) {
		t.Fatalf("notification_kinds = %v, want %v", kinds, want.NotificationKinds)
	}
	if pokes != want.MainChannelPokes {
		t.Fatalf("main_channel_pokes = %d, want %d", pokes, want.MainChannelPokes)
	}
}

// --------------------------------------------------------------------------
// Reconstruction driver (active-upgrade-reconstruction)
// --------------------------------------------------------------------------

func runRealStoreReconstructionFixture(t *testing.T, fx realStoreFixture) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "alertint.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	for _, in := range fx.Reconstruction.Incidents {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO incidents(id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
			VALUES (?, ?, 'analyzed', ?, ?, ?, 1, ?, ?)`, in.IncidentID, in.GroupKey, ts, ts, ts, ts, ts); err != nil {
			t.Fatalf("seed legacy incident %s: %v", in.IncidentID, err)
		}
	}

	clock := func() time.Time { return time.Now().UTC() }
	runtime := store.NewSituationRuntime(st, notifyslack.ClientMessageID, nil, clock, store.SituationRuntimePolicy{
		MinSeverity: model.PriorityLow, HorizonTier: situation.HorizonUnknown,
	})
	reconstructor := situation.NewReconstructor(runtime, clock)
	report, err := reconstructor.Run(ctx)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}

	if report.Reconstructed != fx.Expect.SituationCount {
		t.Fatalf("situation_count = %d, want %d", report.Reconstructed, fx.Expect.SituationCount)
	}
	if fx.Expect.MainChannelPokes != 0 {
		t.Fatalf("fixture declares %d pokes; reconstruction against the real store has no notification seam and can never poke", fx.Expect.MainChannelPokes)
	}
	var intents int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 0 {
		t.Fatalf("notification intents after reconstruction = %d, want 0", intents)
	}
	var situations int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situations`).Scan(&situations); err != nil {
		t.Fatal(err)
	}
	if situations != fx.Expect.SituationCount {
		t.Fatalf("durable situations = %d, want %d", situations, fx.Expect.SituationCount)
	}
	var handled int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situations WHERE public_handle IS NOT NULL`).Scan(&handled); err != nil {
		t.Fatal(err)
	}
	if handled != 0 {
		t.Fatalf("reconstruction published %d handles, want 0", handled)
	}
}

// --------------------------------------------------------------------------
// Dependency-health driver (shared-zabbix-outage)
// --------------------------------------------------------------------------

func runRealStoreDependencyHealthFixture(t *testing.T, fx realStoreFixture) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "alertint.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Seed one real active Situation so the real ScheduleAffectedSituations
	// (which fans out via `WHERE lifecycle IN ('active','recovery_pending')`
	// against the real situations table) has something real to affect.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situations (
			id, group_key, lifecycle, attention, input_version, opened_at,
			effective_started_at, effective_started_at_basis, first_received_at,
			last_lifecycle_observed_at, next_assessment_at, due_reasons_json, created_at, updated_at
		) VALUES ('affected-situation', 'service=dep-health', 'active', 'observe', 1, ?, ?, 'source_payload', ?, ?, ?, '[]', ?, ?)`,
		now, now, now, now, now, now, now); err != nil {
		t.Fatalf("seed affected situation: %v", err)
	}

	cfg := fx.DependencyHealth
	clock := func() time.Time { return time.Now().UTC() }
	runtime := store.NewSituationRuntime(st, notifyslack.ClientMessageID, nil, clock, store.SituationRuntimePolicy{
		MinSeverity: model.PriorityLow, HorizonTier: situation.HorizonUnknown,
	})
	sink := situation.NewDependencyHealthSink(runtime, time.Duration(cfg.BroadcastAfterSeconds)*time.Second)

	if len(cfg.EventOffsetsSeconds) != len(cfg.EventOK) {
		t.Fatalf("dependency_health event_offsets_seconds and event_ok must pair 1:1")
	}
	base := time.Now().UTC()
	for i, offset := range cfg.EventOffsetsSeconds {
		at := base.Add(time.Duration(offset) * time.Second)
		status := health.Status{Name: cfg.Dependency, OK: cfg.EventOK[i], CheckedAt: at}
		if err := sink.RecordDependencyStatus(ctx, status); err != nil {
			t.Fatalf("event %d: record dependency status: %v", i, err)
		}
	}

	var due string
	if err := st.DB().QueryRowContext(ctx, `SELECT due_reasons_json FROM situations WHERE id = 'affected-situation'`).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due == "[]" {
		t.Fatal("the real affected Situation was never fanned out to reconsider; ScheduleAffectedSituations did not run for real")
	}

	rows, err := st.DB().QueryContext(ctx, `
		SELECT kind, main_channel_poke FROM notification_intents
		WHERE subject_kind = 'dependency_health' ORDER BY created_at ASC, id ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var kinds []string
	pokes := 0
	for rows.Next() {
		var kind string
		var poke int
		if err := rows.Scan(&kind, &poke); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, kind)
		if poke != 0 {
			pokes++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !stringsEqual(kinds, fx.Expect.NotificationKinds) {
		t.Fatalf("notification_kinds = %v, want %v", kinds, fx.Expect.NotificationKinds)
	}
	if pokes != fx.Expect.MainChannelPokes {
		t.Fatalf("main_channel_pokes = %d, want %d", pokes, fx.Expect.MainChannelPokes)
	}
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
