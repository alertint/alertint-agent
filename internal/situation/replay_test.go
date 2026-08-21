// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/llm"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// TestReplayCorpus locks the approved sanitized replay corpus: eleven fixed
// scenarios, each driving the real deterministic reducers (BuildSnapshot,
// EligibleReasons, ValidateAssessment, ReconcileLifecycle,
// PlanNotificationIntents) and the real Controller/Reconstructor/
// DependencyHealthSink through their public APIs, against an in-package
// durable-store double — the same pattern controller_test.go, workers_test.go,
// and reconstruct_test.go already use. Only the SQL persistence leaf is
// doubled; every reducer and policy decision is the genuine production
// function. A missing or added fixture fails loudly (len check) rather than
// silently narrowing the locked corpus.
func TestReplayCorpus(t *testing.T) {
	entries, err := os.ReadDir("testdata/replays")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 11 {
		t.Fatalf("fixtures=%d, want 11", len(entries))
	}
	for _, entry := range entries {
		t.Run(entry.Name(), func(t *testing.T) {
			RunReplayFixture(t, filepath.Join("testdata/replays", entry.Name()))
		})
	}
}

// RunReplayFixture loads one replay fixture and asserts its declared
// ReplayExpectation. It dispatches on which of the fixture's three mutually
// exclusive drivers is populated: an ordered sequence of Situation
// reconciliation rounds (the common case), a startup reconstruction pass, or
// a shared dependency-health outage.
func RunReplayFixture(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture replayFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	switch {
	case fixture.Reconstruction != nil:
		runReconstructionFixture(t, fixture)
	case fixture.DependencyHealth != nil:
		runDependencyHealthFixture(t, fixture)
	default:
		runSituationRoundsFixture(t, fixture)
	}
}

// --------------------------------------------------------------------------
// Fixture schema
// --------------------------------------------------------------------------

const (
	replaySituationID = "replay-situation"
	replayIncidentID  = "replay-incident"
)

var replayStartAt = time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)

type replayFixture struct {
	Description      string                  `json:"description"`
	Rounds           []replayRound           `json:"rounds,omitempty"`
	DependencyHealth *replayDependencyHealth `json:"dependency_health,omitempty"`
	Reconstruction   *replayReconstruction   `json:"reconstruction,omitempty"`
	Expect           ReplayExpectation       `json:"expect"`
}

// replayRound is one Situation input version's material evidence — the
// "connector/profile inputs" a wired observation source would otherwise have
// produced — plus the deterministic clock advance before it runs and an
// optional scripted L2 response for it.
type replayRound struct {
	AdvanceSeconds      int64               `json:"advance_seconds"`
	Symptoms            []replaySymptom     `json:"symptoms,omitempty"`
	Judgments           []replayJudgment    `json:"judgments,omitempty"`
	Envelope            *replayEnvelope     `json:"envelope,omitempty"`
	Impact              []replayImpact      `json:"impact,omitempty"`
	DurationClass       string              `json:"duration_class,omitempty"`
	Assessor            *replayAssessorStep `json:"assessor,omitempty"`
	HoldL1UntilAsserted bool                `json:"hold_l1_until_asserted,omitempty"`
	// CompletedEpisodeMinutes, when set, seeds duration_outlier's comparable
	// history (five or more prior episode durations, in minutes) so the
	// harness can auto-derive matching current_duration/completed_episode
	// evidence facts from the real elapsed time this round observes.
	CompletedEpisodeMinutes []int `json:"completed_episode_minutes,omitempty"`
}

type replaySymptom struct {
	ID        string `json:"id"`
	Lifecycle string `json:"lifecycle"` // "firing" | "resolved"
	Severity  string `json:"severity,omitempty"`
}

type replayJudgment struct {
	Judgment         string `json:"judgment"`
	Basis            string `json:"basis"`
	AssertedOperator string `json:"asserted_operator"`
}

type replayEnvelope struct {
	EnvelopeID        string   `json:"envelope_id"`
	EnvelopeVersion   int      `json:"envelope_version"`
	Result            string   `json:"result"` // "match" | "violation" | "authority_removed" | "not_applicable"
	Violations        []string `json:"violations,omitempty"`
	Observability     []string `json:"observability,omitempty"`
	QuietingAuthority bool     `json:"quieting_authority,omitempty"`
}

type replayImpact struct {
	Kind      string `json:"kind"`
	Severity  string `json:"severity"`
	Confirmed bool   `json:"confirmed"`
}

// replayAssessorStep scripts one L2 completion. ReasonCode, when set, is
// resolved live against the round's own freshly built Snapshot.EligibleReasons
// (never hand-authored: a candidate id is a content-bound digest, so the
// fixture names only the durable reason CODE and the harness looks up the
// real candidate).
type replayAssessorStep struct {
	Attention       string `json:"attention"`
	Causality       string `json:"causality,omitempty"`
	EvidenceQuality string `json:"evidence_quality,omitempty"`
	ReasonCode      string `json:"reason_code,omitempty"`
}

type replayDependencyHealth struct {
	Dependency            string   `json:"dependency"`
	AffectedSituations    []string `json:"affected_situations"`
	BroadcastAfterSeconds int64    `json:"broadcast_after_seconds"`
	// EventOffsetsSeconds/EventOK pair one health.Status observation per
	// entry: the offset from the fixture start and whether it reported OK.
	EventOffsetsSeconds []int64 `json:"event_offsets_seconds"`
	EventOK             []bool  `json:"event_ok"`
}

type replayReconstruction struct {
	Incidents []replayUpgradeIncident `json:"incidents"`
}

type replayUpgradeIncident struct {
	IncidentID string `json:"incident_id"`
	GroupKey   string `json:"group_key"`
}

// --------------------------------------------------------------------------
// Situation-controller rounds driver
// --------------------------------------------------------------------------

func runSituationRoundsFixture(t *testing.T, fixture replayFixture) {
	t.Helper()
	if len(fixture.Rounds) == 0 {
		t.Fatal("fixture declares no rounds and no alternate driver")
	}

	clockNow := replayStartAt
	clock := func() time.Time { return clockNow }

	store := newReplayStore()
	investigator := &replayInvestigator{}
	l1Done := make(chan string, 64)
	hook := func(name string) error {
		if name == "l1_complete" {
			l1Done <- name
		}
		return nil
	}

	ctrl := NewController(store, nil, nil, investigator, nil, clock, Config{})
	ctrl.SetBoundaryHookForTest(hook)

	symptoms := map[string]Symptom{}
	situationRow := model.Situation{
		ID: replaySituationID, GroupKey: "replay-group", Lifecycle: model.LifecycleActive, Attention: model.AttentionObserve,
		EffectiveStartedAt: clockNow, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
		FirstReceivedAt: clockNow, LastLifecycleObservedAt: clockNow,
		CreatedAt: clockNow, UpdatedAt: clockNow, DueReasons: []model.DueReason{model.DueIncidentCreated},
	}

	for i, round := range fixture.Rounds {
		clockNow = clockNow.Add(time.Duration(round.AdvanceSeconds) * time.Second)
		inputVersion := i + 1

		for _, s := range round.Symptoms {
			sym := Symptom{ID: s.ID, Lifecycle: model.DeliveryStatus(s.Lifecycle), Severity: s.Severity}
			symptoms[sym.ID] = sym
		}
		orderedSymptoms := orderedSymptomList(symptoms)

		var envelope *model.EnvelopeEvaluation
		var envelopeRefs []string
		if round.Envelope != nil {
			envelope = &model.EnvelopeEvaluation{
				EnvelopeID: round.Envelope.EnvelopeID, EnvelopeVersion: round.Envelope.EnvelopeVersion,
				Result:     model.EnvelopeEvaluationResult(round.Envelope.Result),
				Violations: round.Envelope.Violations, Observability: round.Envelope.Observability,
				QuietingAuthority: round.Envelope.QuietingAuthority,
			}
			envelopeRefs = []string{"fact:envelope_evaluation:" + round.Envelope.EnvelopeID}
		}

		var impact []ImpactFact
		for _, im := range round.Impact {
			impact = append(impact, ImpactFact{Kind: im.Kind, Severity: im.Severity, Confirmed: im.Confirmed, EvidenceRefs: []string{"fact:impact:" + im.Kind}})
		}

		situationRow.InputVersion = inputVersion
		situationRow.AttemptCount = 0
		situationRow.LastLifecycleObservedAt = clockNow

		// duration_outlier evidence: replicate BuildSnapshot's own elapsed
		// derivation (now - effective start, floored at zero) exactly, so
		// the auto-derived current_duration fact's value matches what the
		// real snapshot computes.
		var completedEpisodes []CompletedEpisode
		var currentDurationRefs []string
		durationClass := round.DurationClass
		elapsedSeconds := int64(clockNow.Sub(situationRow.EffectiveStartedAt) / time.Second)
		if elapsedSeconds < 0 {
			elapsedSeconds = 0
		}
		if len(round.CompletedEpisodeMinutes) > 0 {
			currentDurationRefs = []string{"fact:current_duration"}
			for i, minutes := range round.CompletedEpisodeMinutes {
				id := fmt.Sprintf("episode-%d", i)
				completedEpisodes = append(completedEpisodes, CompletedEpisode{
					ID: id, DurationSeconds: int64(minutes) * 60, Comparable: true, EvidenceRefs: []string{"fact:completed_episode:" + id},
				})
			}
			if durationClass == "" {
				durationClass = classifyDuration(time.Duration(elapsedSeconds) * time.Second)
			}
		}

		in := SnapshotInput{
			Situation: situationRow, Symptoms: orderedSymptoms, Envelope: envelope, EnvelopeEvidenceRefs: envelopeRefs,
			Impact: impact, DurationClass: durationClass,
			CompletedEpisodes: completedEpisodes, CurrentDurationEvidenceRefs: currentDurationRefs,
			Facts: buildReplayFacts(inputVersion, orderedSymptoms, envelope, envelopeRefs, impact, completedEpisodes, currentDurationRefs, elapsedSeconds, durationClass),
		}
		for _, j := range round.Judgments {
			in.Judgments = append(in.Judgments, model.Judgment{
				ID: fmt.Sprintf("judgment-%d", inputVersion), SituationID: replaySituationID, JudgedInputVersion: inputVersion,
				Judgment: model.JudgmentKind(j.Judgment), Basis: model.JudgmentBasis(j.Basis),
				AssertedOperator: j.AssertedOperator, AuthenticatedAs: "installation_mcp_token", CreatedAt: clockNow,
			})
		}

		store.mu.Lock()
		store.claim = Claim{Situation: situationRow, ClaimOwner: "replay-worker", ClaimToken: int64(inputVersion)}
		store.input = in
		store.incidentID = replayIncidentID
		store.mu.Unlock()

		// Pre-build the identical snapshot the controller will build
		// internally, purely to resolve a scripted assessor's reason code
		// against the real, current eligible candidates — never to invent one.
		preSnap, err := BuildSnapshot(withNow(in, clockNow))
		if err != nil {
			t.Fatalf("round %d: pre-build snapshot: %v", inputVersion, err)
		}

		var assessor *scriptedAssessor
		if round.Assessor != nil {
			completion, err := buildScriptedCompletion(*round.Assessor, preSnap, clockNow)
			if err != nil {
				t.Fatalf("round %d: build scripted assessor response: %v", inputVersion, err)
			}
			assessor = &scriptedAssessor{completion: completion}
			ctrl.assessor = assessor
		} else {
			ctrl.assessor = nil
		}

		var hold chan struct{}
		if round.HoldL1UntilAsserted {
			hold = investigator.armHold()
		}

		// A terminal lifecycle transition (grace expiry, entering
		// recovery_pending, closed_unknown) short-circuits Reconcile before
		// the B+ gate ever runs, so this round dispatches no L1 at all —
		// exactly the same ReconcileLifecycle call Reconcile itself makes,
		// so the harness knows deterministically whether to expect a
		// completion signal rather than guessing from stale gate state.
		outcome := ReconcileLifecycle(situationRow, orderedSymptoms, nil, clockNow, replayRecoveryGrace)
		l1WillDispatch := !(outcome.Changed && outcome.Terminal)

		if err := ctrl.Reconcile(context.Background(), replaySituationID); err != nil {
			t.Fatalf("round %d: reconcile: %v", inputVersion, err)
		}

		if round.HoldL1UntilAsserted {
			assertHeldPoke(t, store, inputVersion)
			close(hold)
			investigator.disarm()
		}
		if l1WillDispatch {
			waitForL1Settle(t, l1Done)
		}

		store.mu.Lock()
		situationRow = store.claim.Situation
		store.mu.Unlock()
	}

	assertReplayExpectation(t, fixture.Expect, store, investigator.count())
}

// withNow returns a copy of in with Now set — the same mutation
// Controller.Reconcile itself performs right after loading input, so the
// harness's own pre-build snapshot matches what Reconcile will build.
func withNow(in SnapshotInput, now time.Time) SnapshotInput {
	in.Now = now
	return in
}

func orderedSymptomList(symptoms map[string]Symptom) []Symptom {
	ids := make([]string, 0, len(symptoms))
	for id := range symptoms {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Symptom, 0, len(ids))
	for _, id := range ids {
		sym := symptoms[id]
		sym.EvidenceRefs = []string{"fact:symptom_state:" + id}
		out = append(out, sym)
	}
	return out
}

// buildReplayFacts derives the deterministic observation facts that back
// every candidate EligibleReasons might admit this round, mirroring
// internal/store's deriveSymptomStateFacts for symptoms and the same
// evidence-fact shapes internal/situation's own reasons_test.go fixtures use
// for envelope/impact evidence. Every fact carries this exact round's input
// version, so it evidences only this round's material fact set — never a
// stale one.
func buildReplayFacts(inputVersion int, symptoms []Symptom, envelope *model.EnvelopeEvaluation, envelopeRefs []string, impact []ImpactFact, completedEpisodes []CompletedEpisode, currentDurationRefs []string, elapsedSeconds int64, durationClass string) []observationmodel.Fact {
	observedAt := replayStartAt.Add(time.Duration(inputVersion) * time.Second)
	var out []observationmodel.Fact
	for _, sym := range symptoms {
		value, _ := json.Marshal(struct {
			Lifecycle model.DeliveryStatus `json:"lifecycle"`
			Severity  string               `json:"severity"`
		}{sym.Lifecycle, sym.Severity})
		out = append(out, replayFact("fact:symptom_state:"+sym.ID, "symptom_state", sym.ID, value, inputVersion, observedAt, nil))
	}
	if envelope != nil && len(envelopeRefs) > 0 {
		value, _ := json.Marshal(struct {
			EnvelopeVersion   int                            `json:"envelope_version"`
			Result            model.EnvelopeEvaluationResult `json:"result"`
			MatchedFields     []string                       `json:"matched_fields"`
			Violations        []string                       `json:"violations"`
			Observability     []string                       `json:"observability"`
			QuietingAuthority bool                           `json:"quieting_authority"`
		}{envelope.EnvelopeVersion, envelope.Result, canonicalStrings(nil), canonicalStrings(envelope.Violations), canonicalStrings(envelope.Observability), envelope.QuietingAuthority})
		out = append(out, replayFact(envelopeRefs[0], "envelope_evaluation", envelope.EnvelopeID, value, inputVersion, observedAt, nil))
	}
	for _, im := range impact {
		value, _ := json.Marshal(struct {
			Kind      string `json:"kind"`
			Severity  string `json:"severity"`
			Confirmed bool   `json:"confirmed"`
		}{im.Kind, im.Severity, im.Confirmed})
		out = append(out, replayFact("fact:impact:"+im.Kind, "impact", im.Kind, value, inputVersion, observedAt, nil))
	}
	if len(currentDurationRefs) > 0 {
		value, _ := json.Marshal(struct {
			ElapsedSeconds int64  `json:"elapsed_seconds"`
			DurationClass  string `json:"duration_class"`
		}{elapsedSeconds, durationClass})
		out = append(out, replayFact(currentDurationRefs[0], "current_duration", replaySituationID, value, inputVersion, observedAt, nil))
	}
	for _, episode := range completedEpisodes {
		value, _ := json.Marshal(struct {
			DurationSeconds int64 `json:"duration_seconds"`
			Comparable      bool  `json:"comparable"`
		}{episode.DurationSeconds, episode.Comparable})
		out = append(out, replayFact(episode.EvidenceRefs[0], "completed_episode", episode.ID, value, inputVersion, observedAt, nil))
	}
	return out
}

func replayFact(id, kind, subject string, value json.RawMessage, inputVersion int, observedAt time.Time, refs []string) observationmodel.Fact {
	return observationmodel.Fact{
		ID: id, SituationID: replaySituationID, InputVersion: inputVersion, Kind: kind, Subject: subject,
		Value: value, SourceCapability: observationmodel.CapabilityStoreRead, ObservedAt: observedAt.UTC(),
		Freshness: observationmodel.FreshnessFresh, ResultStatus: observationmodel.ResultStatusConfirmedValue,
		Digest: "digest:" + id, EvidenceRefs: refs, Material: true,
	}
}

// buildScriptedCompletion renders one llm.Completion whose Raw JSON is a
// model.Assessment that ValidateAssessment can accept. ReasonCode, when set,
// is resolved against snap.EligibleReasons — the real, freshly computed
// candidates — never invented.
func buildScriptedCompletion(step replayAssessorStep, snap Snapshot, now time.Time) (llm.Completion, error) {
	attention := model.Attention(step.Attention)
	causality := model.Causality(step.Causality)
	if causality == "" {
		causality = model.CausalityUnknown
	}
	evidenceQuality := model.EvidenceQuality(step.EvidenceQuality)
	if evidenceQuality == "" {
		evidenceQuality = model.EvidenceQualityDegraded
	}
	assessment := model.Assessment{
		SchemaVersion: AssessmentSchemaVersion, Persistence: model.PersistenceUnknown, Impact: model.ImpactUnknown,
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
			return llm.Completion{}, fmt.Errorf("reason code %q is not eligible against this round's snapshot (eligible=%v)", step.ReasonCode, snap.EligibleReasons)
		}
		assessment.SufficientReason = &model.SufficientReason{Code: candidate.Code, CandidateID: candidate.ID, Summary: "scripted L2 response", EvidenceRefs: candidate.EvidenceRefs}
	}
	nextUpdate := now.Add(5 * time.Minute)
	switch attention {
	case model.AttentionUrgent:
		action := "investigate"
		assessment.ActionContract = model.ActionContract{NextActor: model.NextActorAlertint, ActionStatus: model.ActionStatusPlanned, AlertintAction: &action, NextUpdateAt: &nextUpdate, NextUpdateOn: []string{"recovery_observed"}}
	case model.AttentionInvestigate:
		action := "investigate"
		assessment.ActionContract = model.ActionContract{NextActor: model.NextActorAlertint, ActionStatus: model.ActionStatusPlanned, AlertintAction: &action, NextUpdateAt: &nextUpdate, NextUpdateOn: []string{"recovery_observed"}}
	default:
		assessment.ActionContract = model.ActionContract{NextActor: model.NextActorNone, ActionStatus: model.ActionStatusWaiting, NextUpdateAt: &nextUpdate}
	}
	raw, err := json.Marshal(assessment)
	if err != nil {
		return llm.Completion{}, err
	}
	return llm.Completion{Raw: raw}, nil
}

// assertHeldPoke asserts a main-channel poke already exists for the
// Situation while L1 is still (deliberately) held running — proving
// publication never waits on L1 completion.
func assertHeldPoke(t *testing.T, store *replayStore, round int) {
	t.Helper()
	store.mu.Lock()
	status := store.analysis[replayIncidentID].Status
	poked := false
	for _, in := range store.intents {
		if in.MainChannelPoke {
			poked = true
		}
	}
	store.mu.Unlock()
	if status != L1StatusRunning {
		t.Fatalf("round %d: l1 status = %s, want running while its poke is asserted", round, status)
	}
	if !poked {
		t.Fatalf("round %d: no main-channel poke exists yet, want one before l1 completes", round)
	}
}

// waitForL1Settle drains the l1_complete signal exactly when this round
// dispatched L1 (AnalysisState moved off "not_requested"/"planned"), so
// every round starts from a settled B+ gate — deterministic, no arbitrary
// sleeps, no reliance on goroutine scheduling order.
func waitForL1Settle(t *testing.T, l1Done chan string) {
	t.Helper()
	select {
	case <-l1Done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for l1 completion signal")
	}
}

// replayRecoveryGrace mirrors Config{}.normalized().RecoveryGrace — the
// default webhook grace every replay-corpus Controller uses (Config{} sets
// no RecoveryGrace override) — so the harness's own ReconcileLifecycle
// pre-check agrees with what Controller.Reconcile computes internally.
var replayRecoveryGrace = (RecoveryGraceConfig{}).RecoveryGrace()

func assertReplayExpectation(t *testing.T, want ReplayExpectation, store *replayStore, l1Runs int) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()

	if got := 1; got != want.SituationCount {
		t.Fatalf("situation_count = %d, want %d", got, want.SituationCount)
	}
	pokes := 0
	kinds := make([]string, 0, len(store.intents))
	for _, in := range store.intents {
		kinds = append(kinds, string(in.Kind))
		if in.MainChannelPoke {
			pokes++
		}
	}
	if pokes != want.MainChannelPokes {
		t.Fatalf("main_channel_pokes = %d, want %d", pokes, want.MainChannelPokes)
	}
	gotTransitions := make([]string, 0, len(store.transitions))
	for _, tr := range store.transitions {
		gotTransitions = append(gotTransitions, string(tr.Lifecycle))
	}
	if !stringsEqual(gotTransitions, want.Transitions) {
		t.Fatalf("transitions = %v, want %v", gotTransitions, want.Transitions)
	}
	gotCausality := ""
	if len(store.transitions) > 0 {
		last := store.transitions[len(store.transitions)-1]
		if last.Assessment != nil {
			gotCausality = string(last.Assessment.Causality)
		}
	}
	if gotCausality != want.Causality {
		t.Fatalf("causality = %q, want %q", gotCausality, want.Causality)
	}
	if l1Runs != want.L1Runs {
		t.Fatalf("l1_runs = %d, want %d", l1Runs, want.L1Runs)
	}
	finalLifecycle := store.claim.Situation.Lifecycle
	if finalLifecycle != want.FinalLifecycle {
		t.Fatalf("final_lifecycle = %q, want %q", finalLifecycle, want.FinalLifecycle)
	}
	if got := string(store.lastEnvelopeResult); got != want.EnvelopeResult {
		t.Fatalf("envelope_result = %q, want %q", got, want.EnvelopeResult)
	}
	if !stringsEqual(kinds, want.NotificationKinds) {
		t.Fatalf("notification_kinds = %v, want %v", kinds, want.NotificationKinds)
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

// --------------------------------------------------------------------------
// replayStore: a durable-store double implementing situation.Store, used
// only by this package's own replay corpus (mirrors fakeStore in
// controller_test.go, extended to actually plan notification intents via
// the real, exported PlanNotificationIntents — the same function
// store.SituationRuntime.CommitAuthoritative calls in production).
// --------------------------------------------------------------------------

type replayStore struct {
	mu sync.Mutex

	claim      Claim
	input      SnapshotInput
	incidentID string

	analysis map[string]AnalysisState
	trusted  TrustedAssessment
	prior    *model.Assessment

	transitions        []model.Transition
	intents            []model.NotificationIntent
	hasRoot            bool
	lastPokeAt         *time.Time
	lastEnvelopeResult model.EnvelopeEvaluationResult
}

func newReplayStore() *replayStore {
	return &replayStore{analysis: map[string]AnalysisState{}}
}

func (s *replayStore) ClaimedSituation(_ context.Context, situationID string) (Claim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if situationID != s.claim.Situation.ID {
		return Claim{}, errors.New("replay store: unknown situation")
	}
	return s.claim, nil
}

func (s *replayStore) LoadReconciliationInput(_ context.Context, _ Claim) (SnapshotInput, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.input.Envelope != nil {
		s.lastEnvelopeResult = s.input.Envelope.Result
	}
	return s.input, s.incidentID, nil
}

func (s *replayStore) AnalysisState(_ context.Context, incidentID string) (AnalysisState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.analysis[incidentID], nil
}

func (s *replayStore) SetAnalysisState(_ context.Context, state AnalysisState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analysis[state.IncidentID] = state
	return nil
}

func (s *replayStore) LastTrustedAssessment(_ context.Context, _ Claim) (TrustedAssessment, *model.Assessment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trusted, s.prior, nil
}

func (s *replayStore) AppendAssessmentAttempt(_ context.Context, _ Claim, _ AssessmentAttempt) error {
	return nil
}

func (s *replayStore) CommitAuthoritative(_ context.Context, claim Claim, attempt AssessmentAttempt, tr model.Transition) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.transitions = append(s.transitions, tr)
	s.trusted = TrustedAssessment{Sequence: attempt.Sequence, FactHash: attempt.FactHash, Trustworthy: tr.Assessment != nil && tr.Assessment.EvidenceQuality == model.EvidenceQualityComplete}
	s.prior = tr.Assessment

	claim.Situation.Lifecycle = tr.Lifecycle
	claim.Situation.Attention = tr.Attention
	// Mirror store.CommitSituationTransition's exact per-lifecycle field
	// derivation (internal/store/situations.go): the committed Transition
	// carries no GraceUntil/RecoveryObservedAt/TerminalAt of its own — the
	// real store derives them from tr.Lifecycle and
	// tr.ActionContract.NextUpdateAt, which is what this fake must do too so
	// a later round's own ReconcileLifecycle check (grace expiry, refire)
	// sees the same durable state a real restart would.
	switch tr.Lifecycle {
	case model.LifecycleActive:
		claim.Situation.RecoveryObservedAt = nil
		claim.Situation.GraceUntil = nil
	case model.LifecycleRecoveryPending:
		if claim.Situation.RecoveryObservedAt == nil {
			observed := tr.CreatedAt.UTC()
			claim.Situation.RecoveryObservedAt = &observed
		}
		if tr.ActionContract.NextUpdateAt != nil {
			until := tr.ActionContract.NextUpdateAt.UTC()
			claim.Situation.GraceUntil = &until
		}
	case model.LifecycleRecovered, model.LifecycleClosedUnknown:
		terminal := tr.CreatedAt.UTC()
		claim.Situation.TerminalAt = &terminal
		claim.Situation.RecoveryObservedAt = nil
		claim.Situation.GraceUntil = nil
		if tr.Lifecycle == model.LifecycleClosedUnknown {
			reason := model.TerminalReason(tr.Reason)
			claim.Situation.TerminalReason = &reason
		}
	}
	s.claim = claim

	var priorTr *model.Transition
	if len(s.transitions) > 1 {
		p := s.transitions[len(s.transitions)-2]
		priorTr = &p
	}
	planned := PlanNotificationIntents(PublishInput{
		Transition: tr, PriorTransition: priorTr, Root: RootCoordinates{Exists: s.hasRoot},
		MinSeverity: model.PriorityLow, RecoveryPending: tr.Lifecycle == model.LifecycleRecoveryPending,
		LastMainChannelPokeAt: s.lastPokeAt, Now: tr.CreatedAt,
	})
	for _, in := range planned {
		if in.Kind == model.NotificationSituationRootCreate {
			s.hasRoot = true
		}
		if in.MainChannelPoke {
			at := tr.CreatedAt
			s.lastPokeAt = &at
		}
		s.intents = append(s.intents, in)
	}
	return nil
}

func (s *replayStore) Reschedule(_ context.Context, _ Claim, _ time.Time) error     { return nil }
func (s *replayStore) Park(_ context.Context, _ Claim, _ time.Time, _ string) error { return nil }
func (s *replayStore) MarkDue(_ context.Context, _ string, _ model.DueReason, _ time.Time) error {
	return nil
}

// replayInvestigator is a counting AcuteInvestigator that can be armed to
// block one call until explicitly released — used by the critical-floor
// fixture to prove publication never waits on L1.
type replayInvestigator struct {
	mu      sync.Mutex
	calls   int
	holding chan struct{}
}

func (r *replayInvestigator) Investigate(_ context.Context, incidentID string) (AcuteResult, error) {
	r.mu.Lock()
	r.calls++
	hold := r.holding
	r.mu.Unlock()
	if hold != nil {
		<-hold
	}
	return AcuteResult{IncidentID: incidentID, RootCause: "resolved", Confidence: 0.9, CompletedAt: time.Now().UTC()}, nil
}

func (r *replayInvestigator) armHold() chan struct{} {
	ch := make(chan struct{})
	r.mu.Lock()
	r.holding = ch
	r.mu.Unlock()
	return ch
}

func (r *replayInvestigator) disarm() {
	r.mu.Lock()
	r.holding = nil
	r.mu.Unlock()
}

func (r *replayInvestigator) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// scriptedAssessor returns one queued completion for every call — this
// package's replay corpus only ever scripts one L2 response per round.
type scriptedAssessor struct{ completion llm.Completion }

func (s *scriptedAssessor) Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error) {
	return s.completion, nil
}

// --------------------------------------------------------------------------
// Reconstruction driver (active-upgrade-reconstruction)
// --------------------------------------------------------------------------

// runReconstructionFixture drives the real Reconstructor against the
// package's own fakeReconstructStore double (reconstruct_test.go), asserting
// that startup reconstruction populates one nonterminal Situation per exact
// group without publishing anything.
func runReconstructionFixture(t *testing.T, fixture replayFixture) {
	t.Helper()
	incidents := make([]UpgradeIncident, 0, len(fixture.Reconstruction.Incidents))
	for _, in := range fixture.Reconstruction.Incidents {
		incidents = append(incidents, upgradeIncident(in.IncidentID, in.GroupKey))
	}
	store := newFakeReconstructStore(incidents...)
	r := NewReconstructor(store, fixedClock(replayStartAt.Format(time.RFC3339)))
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}

	want := fixture.Expect
	if report.Reconstructed != want.SituationCount {
		t.Fatalf("situation_count = %d, want %d", report.Reconstructed, want.SituationCount)
	}
	if want.MainChannelPokes != 0 {
		t.Fatalf("fixture declares %d pokes; reconstruction has no notification seam and can never poke", want.MainChannelPokes)
	}
	if len(want.Transitions) != 0 || len(want.NotificationKinds) != 0 || want.L1Runs != 0 {
		t.Fatalf("reconstruction produces no transitions, l1 runs, or notifications; expect=%+v", want)
	}
	if want.FinalLifecycle != model.LifecycleActive {
		t.Fatalf("final_lifecycle = %q, want active (ReconstructSituation always seeds active)", want.FinalLifecycle)
	}
}

// --------------------------------------------------------------------------
// Dependency-health driver (shared-zabbix-outage)
// --------------------------------------------------------------------------

// runDependencyHealthFixture drives the real DependencyHealthSink against
// the package's own fakeDependencyHealthStore double
// (dependency_health_test.go), replaying a sequence of health.Status
// observations for one shared dependency and asserting the exactly-once
// health root/update it produces plus how many active Situations it fanned
// the outage out to.
func runDependencyHealthFixture(t *testing.T, fixture replayFixture) {
	t.Helper()
	cfg := fixture.DependencyHealth
	store := newFakeDependencyHealthStore()
	broadcastAfter := time.Duration(cfg.BroadcastAfterSeconds) * time.Second
	sink := NewDependencyHealthSink(store, broadcastAfter)

	if len(cfg.EventOffsetsSeconds) != len(cfg.EventOK) {
		t.Fatalf("dependency_health event_offsets_seconds and event_ok must pair 1:1")
	}
	for i, offset := range cfg.EventOffsetsSeconds {
		at := replayStartAt.Add(time.Duration(offset) * time.Second)
		if err := sink.RecordDependencyStatus(context.Background(), depStatus(cfg.Dependency, cfg.EventOK[i], at)); err != nil {
			t.Fatalf("event %d: record dependency status: %v", i, err)
		}
	}
	// The real DependencyHealthSink fans every active Situation out to
	// reconsider (ScheduleAffectedSituations) exactly once per genuine
	// healthy<->degraded transition — the store itself resolves which
	// Situations that reaches; this sink never learns their identities.
	// SituationCount in dependency-health mode therefore counts fan-out
	// transitions, not a Situation list — the fixture's own
	// affected_situations names the scenario for a human reader.
	want := fixture.Expect
	if got := len(store.scheduledCalls); got != want.SituationCount {
		t.Fatalf("situation_count (fan-out transitions) = %d, want %d", got, want.SituationCount)
	}
	pokes, kinds := 0, make([]string, 0, len(store.createdIntents))
	for _, in := range store.createdIntents {
		kinds = append(kinds, string(in.Kind))
		if in.MainChannelPoke {
			pokes++
		}
	}
	if pokes != want.MainChannelPokes {
		t.Fatalf("main_channel_pokes = %d, want %d", pokes, want.MainChannelPokes)
	}
	if !stringsEqual(kinds, want.NotificationKinds) {
		t.Fatalf("notification_kinds = %v, want %v", kinds, want.NotificationKinds)
	}
	if len(want.Transitions) != 0 || want.L1Runs != 0 {
		t.Fatalf("dependency health drives no Situation reconciliation; expect=%+v", want)
	}
}

func depStatus(name string, ok bool, at time.Time) health.Status {
	return health.Status{Name: name, OK: ok, CheckedAt: at}
}
