// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 3 Task 5: fixtures for the fenced history commit. Every helper is
// prefixed `sh` (situation history) so it never collides with the store
// package's existing Plan 1/2 test helpers.
// ----------------------------------------------------------------------

// shRunningTriageContract is a valid nonterminal Operator contract in which
// AlertINT is currently running Acute Triage.
func shRunningTriageContract(next time.Time) situationmodel.ActionContract {
	action := situationmodel.AlertINTActionRunAcuteTriage
	status := situationmodel.AlertINTStatusRunning
	return situationmodel.ActionContract{
		NextActor:      situationmodel.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   timePtrValue(next),
		NextUpdateOn:   []situationmodel.NextUpdateOn{situationmodel.NextUpdateOnTriageOutcome},
	}
}

// shOperatorContract hands the next move to a human while AlertINT's own
// Acute Triage work continues — a material Operator-contract change against
// shRunningTriageContract.
func shOperatorContract(next time.Time) situationmodel.ActionContract {
	op := situationmodel.OperatorActionInvestigateSituation
	action := situationmodel.AlertINTActionRunAcuteTriage
	status := situationmodel.AlertINTStatusRunning
	return situationmodel.ActionContract{
		NextActor:              situationmodel.NextActorOperator,
		AlertINTAction:         &action,
		AlertINTStatus:         &status,
		OperatorActionRequired: &op,
		NextUpdateAt:           timePtrValue(next),
		NextUpdateOn:           []situationmodel.NextUpdateOn{situationmodel.NextUpdateOnMaterialInput},
	}
}

func shConclusion() situationmodel.AssessmentConclusion {
	return situationmodel.AssessmentConclusion{
		Persistence:             situationmodel.PersistenceSustained,
		Impact:                  situationmodel.ImpactSuspected,
		Novelty:                 situationmodel.NoveltyNew,
		Causality:               situationmodel.CausalityCorrelated,
		EvidenceQuality:         situationmodel.EvidenceQualityComplete,
		LimitationCodes:         []string{},
		SufficientReasonCode:    "critical_anchor",
		SufficientReasonSummary: "Confirmed active critical source severity.",
	}
}

func shAssessment(contract situationmodel.ActionContract, concl situationmodel.AssessmentConclusion,
	lifecycle situationmodel.Lifecycle, attention situationmodel.Attention) situationmodel.Assessment {
	a := situationmodel.Assessment{
		SchemaVersion:   situationmodel.AssessmentSchemaVersion,
		Persistence:     concl.Persistence,
		Impact:          concl.Impact,
		Novelty:         concl.Novelty,
		Causality:       concl.Causality,
		Attention:       attention,
		Lifecycle:       lifecycle,
		EvidenceQuality: concl.EvidenceQuality,
		ActionContract:  contract,
		Limitations:     []situationmodel.Limitation{},
		Cadence:         situationmodel.CadenceFast,
	}
	if lifecycle.Terminal() {
		a.Cadence = situationmodel.Cadence("")
	}
	if concl.SufficientReasonCode != "" {
		a.SufficientReason = &situationmodel.SufficientReason{
			Code:         concl.SufficientReasonCode,
			CandidateID:  "candidate-" + concl.SufficientReasonCode,
			Summary:      concl.SufficientReasonSummary,
			EvidenceRefs: []string{"fact-anchor"},
		}
	}
	return a
}

// shCycle is one prepared reconciliation: the ControllerCommit Plan 2 would
// hand CommitController, plus the derived history Plan 3 attaches to it.
type shCycle struct {
	Commit  situation.ControllerCommit
	Change  situation.AuthoritativeChange
	Publish situation.PublicationInput
}

// shPrepare builds one realistic reconciliation for claim: a fresh
// authoritative attempt, the matching Assessment/contract, and the history
// BuildHistoryCommit derives from them.
func shPrepare(t *testing.T, claim situation.Claim, contract situationmodel.ActionContract,
	lifecycle situationmodel.Lifecycle, attention situationmodel.Attention, now time.Time) shCycle {
	t.Helper()
	sit := claim.Situation
	sit.Lifecycle = lifecycle
	sit.Attention = attention

	concl := shConclusion()
	assessment := shAssessment(contract, concl, lifecycle, attention)
	commit := basicControllerCommit(sit.ID, sit.InputVersion, now)
	commit.Assessment = assessment
	commit.Attempt.Validated = mustMarshalJSON(t, assessment)
	commit.Lifecycle = lifecycle
	commit.Attention = attention
	commit.MaterialFactHash = "sha256:material-" + sit.ID
	commit.ConsumedDueReasons = claim.Situation.DueReasons

	projection := situationmodel.ProjectionFacts{
		EffectiveStartedAt:      sit.EffectiveStartedAt,
		EffectiveStartedAtBasis: sit.EffectiveStartedAtBasis,
		Assessment:              &concl,
	}
	if lifecycle.Terminal() {
		projection.TerminalAt = timePtrValue(now)
		sit.TerminalAt = timePtrValue(now)
		commit.TerminalAt = timePtrValue(now)
		if lifecycle == situationmodel.LifecycleClosedUnknown {
			reason := situationmodel.TerminalReasonObservationDeadline
			projection.TerminalReason = &reason
			sit.TerminalReason = &reason
			commit.TerminalReason = &reason
		}
	}

	change := situation.AuthoritativeChange{
		Situation:        sit,
		AssessmentID:     &commit.Attempt.ID,
		Assessment:       assessment,
		Derivation:       situationmodel.DerivationDeterministic,
		Projection:       projection,
		MaterialFactHash: commit.MaterialFactHash,
		EvidenceRefs:     []string{"fact-a"},
		Now:              now,
	}
	publish := situation.PublicationInput{
		Situation:      sit,
		SlackFloor:     situationmodel.InterruptionLow,
		RepageCooldown: 15 * time.Minute,
		Now:            now,
	}
	if !lifecycle.Terminal() {
		publish.ContractDeadlineAt = contract.NextUpdateAt
	}
	return shCycle{Commit: commit, Change: change, Publish: publish}
}

// shDerive runs Task 4's composition and attaches the result to the commit.
func shDerive(t *testing.T, c shCycle) situation.ControllerCommit {
	t.Helper()
	history, err := situation.BuildHistoryCommit(c.Change, c.Publish)
	if err != nil {
		t.Fatalf("BuildHistoryCommit: %v", err)
	}
	commit := c.Commit
	commit.History = &history
	return commit
}

// shSeedPendingArtifact inserts one applied, journal_state='pending'
// situation_input_outbox row owned by situationID, and returns the
// OperatorArtifactInput the controller would hand BuildTransitions for it.
func shSeedPendingArtifact(t *testing.T, st *Store, situationID, incidentID, groupKey, inputID, kind string,
	appliedInputVersion int, occurredAt time.Time) situation.OperatorArtifactInput {
	t.Helper()
	ctx := context.Background()
	artifact := situation.OperatorArtifactInput{
		InputID:             inputID,
		Kind:                kind,
		AppliedInputVersion: appliedInputVersion,
		OccurredAt:          occurredAt.UTC(),
		AttributedActor:     "operator@example.com",
		Headline:            "Operator note recorded",
		Detail:              "Rollback started.",
	}
	var annotationID, verdictID any
	switch kind {
	case "operator_annotation_recorded":
		id, err := insertAnnotationRow(ctx, st, incidentID)
		if err != nil {
			t.Fatalf("insert annotation row: %v", err)
		}
		annotationID = id
		artifact.AnnotationID = shStringPtr(strconv.FormatInt(id, 10))
	case "captured_verdict_recorded":
		id, err := insertVerdictRow(ctx, st, incidentID, appliedInputVersion)
		if err != nil {
			t.Fatalf("insert verdict row: %v", err)
		}
		verdictID = id
		artifact.VerdictID = shStringPtr(strconv.FormatInt(id, 10))
	default:
		t.Fatalf("unsupported artifact kind %q", kind)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (
			id, idempotency_key, incident_id, kind, group_key, occurred_at, status,
			applied_situation_id, applied_at, applied_input_version,
			annotation_id, verdict_id, journal_state
		) VALUES (?, ?, ?, ?, ?, ?, 'applied', ?, ?, ?, ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, kind, groupKey, canonicalTime(occurredAt),
		situationID, canonicalTime(occurredAt), appliedInputVersion, annotationID, verdictID); err != nil {
		t.Fatalf("seed pending artifact %s: %v", inputID, err)
	}
	return artifact
}

func shStringPtr(s string) *string { return &s }

// ----------------------------------------------------------------------
// Assertion helpers reading the durable history back.
// ----------------------------------------------------------------------

func shTransitionSequences(t *testing.T, st *Store, situationID string) []int {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(),
		`SELECT sequence FROM situation_transitions WHERE situation_id = ? ORDER BY sequence`, situationID)
	if err != nil {
		t.Fatalf("read transition sequences: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := []int{}
	for rows.Next() {
		var seq int
		if err := rows.Scan(&seq); err != nil {
			t.Fatalf("scan transition sequence: %v", err)
		}
		out = append(out, seq)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate transition sequences: %v", err)
	}
	return out
}

func shCountRows(t *testing.T, st *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

func shCurrentPointer(t *testing.T, st *Store, situationID string) (string, int) {
	t.Helper()
	var id nullStringForTest
	var seq int
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT current_transition_id, current_transition_sequence FROM situations WHERE id = ?`,
		situationID).Scan(&id, &seq); err != nil {
		t.Fatalf("read current transition pointer: %v", err)
	}
	return id.String, seq
}

// nullStringForTest keeps the pointer read above readable without pulling
// database/sql into every assertion.
type nullStringForTest struct {
	String string
	Valid  bool
}

func (n *nullStringForTest) Scan(v any) error {
	if v == nil {
		n.String, n.Valid = "", false
		return nil
	}
	switch s := v.(type) {
	case string:
		n.String, n.Valid = s, true
	case []byte:
		n.String, n.Valid = string(s), true
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	return nil
}

// ----------------------------------------------------------------------
// Step 1: atomicity.
// ----------------------------------------------------------------------

// TestControllerCommitHistoryPersistsEveryDurableRecordInOneTransaction is
// the whole-commit success case: one transaction updates Plan 2's
// projection AND inserts every Transition in contiguous sequence order, one
// Episode-summary version per Transition, one transition-stream row per
// Transition, every planned intent, and the advanced current pointer.
func TestControllerCommitHistoryPersistsEveryDurableRecordInOneTransaction(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-history-ok", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	commit := shDerive(t, cycle)
	if len(commit.History.Transitions) != 1 {
		t.Fatalf("derived transitions = %d, want 1", len(commit.History.Transitions))
	}
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	tr := commit.History.Transitions[0]
	if got := shTransitionSequences(t, st, sitID); len(got) != 1 || got[0] != 1 {
		t.Fatalf("transition sequences = %v, want [1]", got)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_transition_stream WHERE situation_id = ?`, sitID); n != 1 {
		t.Fatalf("transition stream rows = %d, want 1", n)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ?`, sitID); n != len(commit.History.Intents) {
		t.Fatalf("notification intents = %d, want %d", n, len(commit.History.Intents))
	}
	var version, sourceSeq int
	var summaryJSON string
	if err := st.db.QueryRowContext(ctx,
		`SELECT version, source_transition_sequence, summary_json FROM situation_episode_summaries WHERE situation_id = ?`,
		sitID).Scan(&version, &sourceSeq, &summaryJSON); err != nil {
		t.Fatalf("read episode summary: %v", err)
	}
	if version != 1 || sourceSeq != tr.Sequence {
		t.Fatalf("episode summary (version, source_sequence) = (%d,%d), want (1,%d)", version, sourceSeq, tr.Sequence)
	}
	wantSummary, err := json.Marshal(commit.History.Summary)
	if err != nil {
		t.Fatalf("marshal expected summary: %v", err)
	}
	if summaryJSON != string(wantSummary) {
		t.Fatalf("persisted summary_json = %s, want %s", summaryJSON, wantSummary)
	}
	if id, seq := shCurrentPointer(t, st, sitID); id != tr.ID || seq != tr.Sequence {
		t.Fatalf("current transition pointer = (%q,%d), want (%q,%d)", id, seq, tr.ID, tr.Sequence)
	}
	// The immutable journal entry for this Transition landed too, and knows
	// it may not be delivered before the root exists.
	thread := shIntentOfClass(t, commit.History.Intents, "thread_append")
	storedThread, err := st.GetNotificationIntent(ctx, thread.ID)
	if err != nil {
		t.Fatalf("GetNotificationIntent(thread_append): %v", err)
	}
	if !storedThread.RequiresRoot || storedThread.MainChannelPoke {
		t.Fatalf("thread_append intent = %+v, want requires_root and no poke", storedThread)
	}
	if storedThread.TransitionSequence == nil || *storedThread.TransitionSequence != tr.Sequence {
		t.Fatalf("thread_append transition sequence = %v, want %d", storedThread.TransitionSequence, tr.Sequence)
	}
	// Plan 2's own projection still landed in the same transaction.
	var currentAssessmentID string
	if err := st.db.QueryRowContext(ctx, `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID).
		Scan(&currentAssessmentID); err != nil {
		t.Fatalf("read current assessment id: %v", err)
	}
	if currentAssessmentID != commit.Attempt.ID {
		t.Fatalf("current_assessment_id = %q, want %q", currentAssessmentID, commit.Attempt.ID)
	}
}

// TestControllerCommitHistoryJournalsEveryPendingArtifactInOneCommit pins
// R1: two artifacts applied between two controller cycles are journaled in
// one commit, in (applied_input_version, occurred_at, id) order, before the
// controller-state Transition, each carrying its own Transition ID.
func TestControllerCommitHistoryJournalsEveryPendingArtifactInOneCommit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	group := "group-history-artifacts"
	sitID := newSituationForGroup(t, st, group, now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	first := shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-art-1",
		"operator_annotation_recorded", claim.Situation.InputVersion, now.Add(-2*time.Minute))
	second := shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-art-2",
		"captured_verdict_recorded", claim.Situation.InputVersion, now.Add(-time.Minute))

	cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	cycle.Change.OperatorArtifacts = []situation.OperatorArtifactInput{first, second}
	commit := shDerive(t, cycle)
	if len(commit.History.Transitions) != 3 {
		t.Fatalf("derived transitions = %d, want 3 (two artifacts then the controller state)", len(commit.History.Transitions))
	}
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	if got := shTransitionSequences(t, st, sitID); len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("transition sequences = %v, want [1 2 3]", got)
	}
	for i, artifact := range []situation.OperatorArtifactInput{first, second} {
		var state string
		var journaledTransitionID string
		if err := st.db.QueryRowContext(ctx,
			`SELECT journal_state, journaled_transition_id FROM situation_input_outbox WHERE id = ?`,
			artifact.InputID).Scan(&state, &journaledTransitionID); err != nil {
			t.Fatalf("read artifact %s: %v", artifact.InputID, err)
		}
		if state != "journaled" {
			t.Fatalf("artifact %s journal_state = %q, want journaled", artifact.InputID, state)
		}
		if want := commit.History.Transitions[i].ID; journaledTransitionID != want {
			t.Fatalf("artifact %s journaled_transition_id = %q, want %q", artifact.InputID, journaledTransitionID, want)
		}
	}
	// One Episode-summary version per Transition: three folds from nothing.
	var version int
	if err := st.db.QueryRowContext(ctx,
		`SELECT version FROM situation_episode_summaries WHERE situation_id = ?`, sitID).Scan(&version); err != nil {
		t.Fatalf("read episode summary version: %v", err)
	}
	if version != 3 {
		t.Fatalf("episode summary version = %d, want 3 (one fold per Transition)", version)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_transition_stream WHERE situation_id = ?`, sitID); n != 3 {
		t.Fatalf("transition stream rows = %d, want 3", n)
	}
}

// TestControllerCommitHistoryFailedWriteLeavesNoPartialState injects a
// failure after each durable history write step and proves the whole
// transaction rolls back: no orphan Transition, no orphan summary, stream
// row, or intent, no journaled artifact, and no advanced current pointer.
func TestControllerCommitHistoryFailedWriteLeavesNoPartialState(t *testing.T) {
	for _, step := range historyCommitSteps {
		t.Run(step, func(t *testing.T) {
			st := newTestStore(t)
			ctx := context.Background()
			now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
			group := "group-history-fail-" + step
			sitID := newSituationForGroup(t, st, group, now)
			claim := claimSituation(t, st, sitID, "controller-a", now)
			artifact := shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-fail-"+step,
				"operator_annotation_recorded", claim.Situation.InputVersion, now.Add(-time.Minute))

			cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
				situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
			cycle.Change.OperatorArtifacts = []situation.OperatorArtifactInput{artifact}
			commit := shDerive(t, cycle)

			injected := errors.New("injected failure at " + step)
			historyCommitFailpoint = func(at string) error {
				if at == step {
					return injected
				}
				return nil
			}
			t.Cleanup(func() { historyCommitFailpoint = nil })

			if err := st.CommitController(ctx, claim, commit); !errors.Is(err, injected) {
				t.Fatalf("CommitController with a failure at %q = %v, want the injected error", step, err)
			}
			historyCommitFailpoint = nil

			if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("transitions after rollback = %d, want 0", n)
			}
			if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_episode_summaries WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("episode summaries after rollback = %d, want 0", n)
			}
			if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_transition_stream WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("stream rows after rollback = %d, want 0", n)
			}
			if n := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("intents after rollback = %d, want 0", n)
			}
			if n := shCountRows(t, st,
				`SELECT COUNT(*) FROM situation_input_outbox WHERE id = ? AND journal_state = 'pending'`,
				artifact.InputID); n != 1 {
				t.Fatalf("artifact journal_state after rollback: pending rows = %d, want 1", n)
			}
			if id, seq := shCurrentPointer(t, st, sitID); id != "" || seq != 0 {
				t.Fatalf("current transition pointer after rollback = (%q,%d), want (\"\",0)", id, seq)
			}
			// Plan 2's own projection must have rolled back too.
			var currentAssessmentID nullStringForTest
			if err := st.db.QueryRowContext(ctx, `SELECT current_assessment_id FROM situations WHERE id = ?`, sitID).
				Scan(&currentAssessmentID); err != nil {
				t.Fatalf("read current assessment id: %v", err)
			}
			if currentAssessmentID.Valid {
				t.Fatalf("current_assessment_id after rollback = %q, want NULL", currentAssessmentID.String)
			}
			if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_assessment_attempts WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("assessment attempts after rollback = %d, want 0", n)
			}
		})
	}
}

// ----------------------------------------------------------------------
// Step 2: fencing and concurrency.
// ----------------------------------------------------------------------

// TestControllerCommitFenceRejectsHistoryOnStaleClaim proves a stale lease
// owner, claim token, or input version rejects the WHOLE commit — history
// included — never just Plan 2's own fields.
func TestControllerCommitFenceRejectsHistoryOnStaleClaim(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*situation.Claim)
		wantErr error
	}{
		{"owner", func(c *situation.Claim) { c.ClaimOwner = "someone-else" }, situationmodel.ErrSituationLeaseLost},
		{"token", func(c *situation.Claim) { c.ClaimToken++ }, situationmodel.ErrSituationLeaseLost},
		{"input_version", func(c *situation.Claim) { c.Situation.InputVersion++ }, ErrSituationVersionConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			ctx := context.Background()
			now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
			sitID := newSituationForGroup(t, st, "group-history-fence-"+tc.name, now)
			claim := claimSituation(t, st, sitID, "controller-a", now)

			cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
				situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
			commit := shDerive(t, cycle)

			stale := claim
			tc.mutate(&stale)
			if err := st.CommitController(ctx, stale, commit); !errors.Is(err, tc.wantErr) {
				t.Fatalf("CommitController with a stale %s = %v, want %v", tc.name, err, tc.wantErr)
			}
			if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("transitions after a fenced rejection = %d, want 0", n)
			}
			if n := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("intents after a fenced rejection = %d, want 0", n)
			}
			if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_episode_summaries WHERE situation_id = ?`, sitID); n != 0 {
				t.Fatalf("episode summaries after a fenced rejection = %d, want 0", n)
			}
		})
	}
}

// TestControllerCommitConcurrentRacePicksOneContiguousWinner races two valid
// commits for one Situation: exactly one lands, sequences stay contiguous,
// and no Transition or intent is duplicated.
func TestControllerCommitConcurrentRacePicksOneContiguousWinner(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-history-race", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	commitA := shDerive(t, cycle)
	commitB := shDerive(t, cycle)
	commitB.Attempt.ID = commitA.Attempt.ID // same derivation, same cycle, same claim.

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, c := range []situation.ControllerCommit{commitA, commitB} {
		wg.Add(1)
		go func(idx int, commit situation.ControllerCommit) {
			defer wg.Done()
			errs[idx] = st.CommitController(ctx, claim, commit)
		}(i, c)
	}
	wg.Wait()

	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, situationmodel.ErrSituationLeaseLost):
		default:
			t.Fatalf("racing commit failed with an unexpected error: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("winning commits = %d, want exactly 1 (errors: %v)", won, errs)
	}
	if got := shTransitionSequences(t, st, sitID); len(got) != 1 || got[0] != 1 {
		t.Fatalf("transition sequences after the race = %v, want [1]", got)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ?`, sitID); n != len(commitA.History.Intents) {
		t.Fatalf("intents after the race = %d, want %d", n, len(commitA.History.Intents))
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_transition_stream WHERE situation_id = ?`, sitID); n != 1 {
		t.Fatalf("stream rows after the race = %d, want 1", n)
	}
}

// TestControllerCommitHistoryVerbatimReplayFailsClosed pins Plan 2's replay
// boundary 9 for history: replaying a landed commit with the same (now
// stale) claim fails closed and changes nothing.
func TestControllerCommitHistoryVerbatimReplayFailsClosed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-history-replay", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	commit := shDerive(t, cycle)
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("first CommitController: %v", err)
	}
	before := shTransitionSequences(t, st, sitID)
	intentsBefore := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ?`, sitID)

	if err := st.CommitController(ctx, claim, commit); !errors.Is(err, situationmodel.ErrSituationLeaseLost) {
		t.Fatalf("verbatim replay = %v, want ErrSituationLeaseLost", err)
	}
	after := shTransitionSequences(t, st, sitID)
	if len(after) != len(before) {
		t.Fatalf("transitions after replay = %v, want unchanged %v", after, before)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ?`, sitID); n != intentsBefore {
		t.Fatalf("intents after replay = %d, want unchanged %d", n, intentsBefore)
	}
}

// TestControllerCommitHistorySupersedesPendingRootSync proves a second
// commit's root projection atomically supersedes the first commit's still
// pending one — migration 0018's "at most one pending, unsuperseded
// root_sync per Situation" index would otherwise reject the whole commit.
func TestControllerCommitHistorySupersedesPendingRootSync(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	group := "group-history-supersede"
	sitID := newSituationForGroup(t, st, group, now)

	claim := claimSituation(t, st, sitID, "controller-a", now)
	first := shDerive(t, shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now))
	if err := st.CommitController(ctx, claim, first); err != nil {
		t.Fatalf("first CommitController: %v", err)
	}
	firstRoot := shIntentOfClass(t, first.History.Intents, "root_sync")

	// Second cycle: same input version, a materially changed contract.
	later := now.Add(time.Minute)
	shMakeDue(t, st, sitID, now.Add(-time.Minute))
	claim2 := claimSituation(t, st, sitID, "controller-a", later)
	cycle2 := shPrepare(t, claim2, shOperatorContract(later.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, later)
	cycle2.Change.PriorTransition = &first.History.Transitions[0]
	cycle2.Change.PriorSummary = first.History.Summary
	cycle2.Publish.PriorTransition = &first.History.Transitions[0]
	cycle2.Publish.RootPublished = true
	commit2 := shDerive(t, cycle2)
	if err := st.CommitController(ctx, claim2, commit2); err != nil {
		t.Fatalf("second CommitController: %v", err)
	}

	var status, supersessionReason, replacement string
	if err := st.db.QueryRowContext(ctx,
		`SELECT status, COALESCE(supersession_reason,''), COALESCE(replacement_intent_id,'') FROM notification_intents WHERE id = ?`,
		firstRoot.ID).Scan(&status, &supersessionReason, &replacement); err != nil {
		t.Fatalf("read first root intent: %v", err)
	}
	if status != "superseded" {
		t.Fatalf("first root_sync status = %q, want superseded", status)
	}
	secondRoot := shIntentOfClass(t, commit2.History.Intents, "root_sync")
	if replacement != secondRoot.ID {
		t.Fatalf("first root_sync replacement_intent_id = %q, want %q", replacement, secondRoot.ID)
	}
	if supersessionReason == "" {
		t.Fatal("a superseded root_sync must record why")
	}
	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM notification_intents WHERE situation_id = ? AND effect_class = 'root_sync' AND status = 'pending'`,
		sitID); n != 1 {
		t.Fatalf("pending root_sync intents = %d, want exactly 1", n)
	}
}

// shMakeDue re-arms situationID's deterministic checkpoint so
// ClaimDueSituations selects it again — the second cycle of a two-cycle
// test, without waiting out a real cadence.
func shMakeDue(t *testing.T, st *Store, situationID string, at time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(),
		`UPDATE situations SET next_assessment_at = ? WHERE id = ?`, canonicalTime(at), situationID); err != nil {
		t.Fatalf("re-arm situation %s: %v", situationID, err)
	}
}

func shIntentOfClass(t *testing.T, intents []situationmodel.NotificationIntent, class situationmodel.EffectClass) situationmodel.NotificationIntent {
	t.Helper()
	for _, i := range intents {
		if i.EffectClass == class {
			return i
		}
	}
	t.Fatalf("no %s intent among %d planned", class, len(intents))
	return situationmodel.NotificationIntent{}
}

// TestControllerCommitHistoryRejectsNonContinuingTransitionSequence proves
// the third fence Step 2 names: history derived against a prior Transition
// that is no longer the Situation's current one is rejected whole, rather
// than punching a gap into an immutable ledger.
func TestControllerCommitHistoryRejectsNonContinuingTransitionSequence(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-history-sequence-gap", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	commit := shDerive(t, cycle)
	// Pretend the controller derived against a prior Transition at
	// sequence 4 while the Situation has none at all.
	for i := range commit.History.Transitions {
		commit.History.Transitions[i].Sequence += 4
	}
	commit.History.Summary.SourceTransitionSequence += 4

	if err := st.CommitController(ctx, claim, commit); !errors.Is(err, ErrSituationHistoryConflict) {
		t.Fatalf("CommitController with a non-continuing sequence = %v, want ErrSituationHistoryConflict", err)
	}
	if n := shCountRows(t, st, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, sitID); n != 0 {
		t.Fatalf("transitions after a sequence-conflict rejection = %d, want 0", n)
	}
}

// ----------------------------------------------------------------------
// Step 5: the coherent load the controller derives history from.
// ----------------------------------------------------------------------

// TestLoadReconciliationInputReadsPriorHistoryAndPendingArtifacts proves the
// controller's coherent load returns the prior Transition, the current
// Episode summary, and only the applied-and-unjournaled artifacts, in R1's
// (applied_input_version, occurred_at, id) order.
func TestLoadReconciliationInputReadsPriorHistoryAndPendingArtifacts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	group := "group-load-history"
	sitID := newSituationForGroup(t, st, group, now)

	claim := claimSituation(t, st, sitID, "controller-a", now)
	first := shDerive(t, shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now))
	if err := st.CommitController(ctx, claim, first); err != nil {
		t.Fatalf("first CommitController: %v", err)
	}

	// Two artifacts pending, deliberately seeded out of order.
	shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-zz",
		"captured_verdict_recorded", claim.Situation.InputVersion, now.Add(-time.Minute))
	shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-aa",
		"operator_annotation_recorded", claim.Situation.InputVersion, now.Add(-2*time.Minute))

	shMakeDue(t, st, sitID, now.Add(-time.Minute))
	claim2 := claimSituation(t, st, sitID, "controller-a", now.Add(time.Minute))
	in, err := st.LoadReconciliationInput(ctx, claim2, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	if in.PriorTransition == nil || in.PriorTransition.ID != first.History.Transitions[0].ID {
		t.Fatalf("prior transition = %+v, want the committed %q", in.PriorTransition, first.History.Transitions[0].ID)
	}
	if in.CurrentSummary == nil || in.CurrentSummary.Version != 1 {
		t.Fatalf("current summary = %+v, want version 1", in.CurrentSummary)
	}
	if in.RootPublished {
		t.Fatal("root_published must stay false until Slack coordinates are durable")
	}
	if in.LatestRootSyncVersion == nil || *in.LatestRootSyncVersion != 1 {
		t.Fatalf("latest root sync version = %v, want 1", in.LatestRootSyncVersion)
	}
	if in.LastDeliveredRootDeadlineAt != nil || in.LastMainChannelPokeAt != nil {
		t.Fatalf("nothing has been delivered yet, got (%v,%v)", in.LastDeliveredRootDeadlineAt, in.LastMainChannelPokeAt)
	}
	if len(in.PendingArtifacts) != 2 {
		t.Fatalf("pending artifacts = %d, want 2", len(in.PendingArtifacts))
	}
	if in.PendingArtifacts[0].InputID != "input-aa" || in.PendingArtifacts[1].InputID != "input-zz" {
		t.Fatalf("pending artifact order = %q,%q, want input-aa then input-zz (occurred_at order)",
			in.PendingArtifacts[0].InputID, in.PendingArtifacts[1].InputID)
	}
	if in.PendingArtifacts[0].AnnotationID == nil || in.PendingArtifacts[0].Headline == "" {
		t.Fatalf("annotation artifact lost its durable content: %+v", in.PendingArtifacts[0])
	}
	if in.PendingArtifacts[1].VerdictID == nil || in.PendingArtifacts[1].AttributedActor == "" {
		t.Fatalf("verdict artifact lost its durable content: %+v", in.PendingArtifacts[1])
	}
}

// TestLoadReconciliationInputSkipsJournaledAndOwnerTerminalArtifacts pins R2
// at the load boundary: an artifact recorded against an already-terminal
// owner is never offered for journaling, and neither is one a previous
// commit already consumed.
func TestLoadReconciliationInputSkipsJournaledAndOwnerTerminalArtifacts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	group := "group-load-r2"
	sitID := newSituationForGroup(t, st, group, now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	pending := shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-live",
		"operator_annotation_recorded", claim.Situation.InputVersion, now.Add(-time.Minute))
	late := shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-late",
		"operator_annotation_recorded", claim.Situation.InputVersion, now)
	if _, err := st.db.ExecContext(ctx,
		`UPDATE situation_input_outbox SET journal_state = 'owner_terminal' WHERE id = ?`, late.InputID); err != nil {
		t.Fatalf("mark artifact owner_terminal: %v", err)
	}

	cycle := shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now)
	cycle.Change.OperatorArtifacts = []situation.OperatorArtifactInput{pending}
	if err := st.CommitController(ctx, claim, shDerive(t, cycle)); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	shMakeDue(t, st, sitID, now.Add(-time.Minute))
	claim2 := claimSituation(t, st, sitID, "controller-a", now.Add(time.Minute))
	in, err := st.LoadReconciliationInput(ctx, claim2, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("LoadReconciliationInput: %v", err)
	}
	if len(in.PendingArtifacts) != 0 {
		t.Fatalf("pending artifacts = %+v, want none (one journaled, one owner_terminal)", in.PendingArtifacts)
	}
	var lateState string
	var lateTransition nullStringForTest
	if err := st.db.QueryRowContext(ctx,
		`SELECT journal_state, journaled_transition_id FROM situation_input_outbox WHERE id = ?`,
		late.InputID).Scan(&lateState, &lateTransition); err != nil {
		t.Fatalf("read late artifact: %v", err)
	}
	if lateState != "owner_terminal" || lateTransition.Valid {
		t.Fatalf("late artifact = (%q,%v), want owner_terminal with no Transition", lateState, lateTransition)
	}
}

// TestControllerCommitHistoryLeavesEveryEffectRecoverable is the "crash
// after commit" half of the crash boundary: once the fenced transaction
// lands, every outward effect it created is still pending and claimable by
// a restarted worker — nothing was consumed by the commit itself.
func TestControllerCommitHistoryLeavesEveryEffectRecoverable(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	sitID := newSituationForGroup(t, st, "group-history-recoverable", now)
	claim := claimSituation(t, st, sitID, "controller-a", now)

	commit := shDerive(t, shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now))
	if err := st.CommitController(ctx, claim, commit); err != nil {
		t.Fatalf("CommitController: %v", err)
	}

	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM situation_transition_stream WHERE situation_id = ? AND status = 'pending' AND lease_owner IS NULL`,
		sitID); n != len(commit.History.Transitions) {
		t.Fatalf("recoverable stream rows = %d, want %d", n, len(commit.History.Transitions))
	}
	pendingIntents := 0
	for _, intent := range commit.History.Intents {
		if intent.Status == situationmodel.IntentPending {
			pendingIntents++
		}
	}
	if n := shCountRows(t, st,
		`SELECT COUNT(*) FROM notification_intents WHERE situation_id = ? AND status = 'pending' AND claim_owner IS NULL AND attempt_count = 0`,
		sitID); n != pendingIntents {
		t.Fatalf("recoverable pending intents = %d, want %d", n, pendingIntents)
	}
	// The Situation's own lease is released, so the next claim is free to
	// pick the work up again.
	var leaseOwner nullStringForTest
	if err := st.db.QueryRowContext(ctx, `SELECT lease_owner FROM situations WHERE id = ?`, sitID).Scan(&leaseOwner); err != nil {
		t.Fatalf("read lease owner: %v", err)
	}
	if leaseOwner.Valid {
		t.Fatalf("lease owner after commit = %q, want released", leaseOwner.String)
	}
}

// TestControllerCommitHistoryTerminalCycleJournalsArtifactThenCloses is R1's
// terminal ordering against the real schema: an artifact still pending when
// the Situation closes is journaled in the same transaction, before the
// terminal Transition, and the terminal Episode summary lands with it.
func TestControllerCommitHistoryTerminalCycleJournalsArtifactThenCloses(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	group := "group-history-terminal"
	sitID := newSituationForGroup(t, st, group, now)

	claim := claimSituation(t, st, sitID, "controller-a", now)
	first := shDerive(t, shPrepare(t, claim, shRunningTriageContract(now.Add(time.Minute)),
		situationmodel.LifecycleActive, situationmodel.AttentionInvestigate, now))
	if err := st.CommitController(ctx, claim, first); err != nil {
		t.Fatalf("first CommitController: %v", err)
	}

	later := now.Add(time.Minute)
	artifact := shSeedPendingArtifact(t, st, sitID, "inc-"+group, group, "input-terminal",
		"operator_annotation_recorded", claim.Situation.InputVersion, now)
	shMakeDue(t, st, sitID, now.Add(-time.Minute))
	claim2 := claimSituation(t, st, sitID, "controller-a", later)

	terminal := shPrepare(t, claim2, situationmodel.ActionContract{NextActor: situationmodel.NextActorNone},
		situationmodel.LifecycleClosedUnknown, situationmodel.AttentionObserve, later)
	terminal.Change.PriorTransition = &first.History.Transitions[0]
	terminal.Change.PriorSummary = first.History.Summary
	terminal.Change.OperatorArtifacts = []situation.OperatorArtifactInput{artifact}
	terminal.Publish.PriorTransition = &first.History.Transitions[0]
	terminal.Publish.RootPublished = true
	commit := shDerive(t, terminal)
	if err := st.CommitController(ctx, claim2, commit); err != nil {
		t.Fatalf("terminal CommitController: %v", err)
	}

	if got := shTransitionSequences(t, st, sitID); len(got) != 3 {
		t.Fatalf("transition sequences = %v, want three (publication, artifact, closure)", got)
	}
	var reasons []string
	rows, err := st.db.QueryContext(ctx,
		`SELECT reason FROM situation_transitions WHERE situation_id = ? ORDER BY sequence`, sitID)
	if err != nil {
		t.Fatalf("read transition reasons: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var reason string
		if err := rows.Scan(&reason); err != nil {
			t.Fatalf("scan transition reason: %v", err)
		}
		reasons = append(reasons, reason)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate transition reasons: %v", err)
	}
	want := []string{"first_authoritative_state", "operator_artifact_recorded", "closed_unknown"}
	for i := range want {
		if i >= len(reasons) || reasons[i] != want[i] {
			t.Fatalf("transition reasons = %v, want %v", reasons, want)
		}
	}
	var state, journaledTransitionID string
	if err := st.db.QueryRowContext(ctx,
		`SELECT journal_state, journaled_transition_id FROM situation_input_outbox WHERE id = ?`,
		artifact.InputID).Scan(&state, &journaledTransitionID); err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if state != "journaled" || journaledTransitionID != commit.History.Transitions[0].ID {
		t.Fatalf("artifact = (%q,%q), want journaled by the artifact Transition %q",
			state, journaledTransitionID, commit.History.Transitions[0].ID)
	}
	view, err := st.GetSituationEpisodeView(ctx, sitID)
	if err != nil {
		t.Fatalf("GetSituationEpisodeView: %v", err)
	}
	if view.Summary.Version != 3 || view.Summary.TerminalAt == nil {
		t.Fatalf("terminal episode summary = %+v, want version 3 with a terminal instant", view.Summary)
	}
	if view.SourceTransition.Reason != "closed_unknown" {
		t.Fatalf("terminal summary source transition reason = %q, want closed_unknown", view.SourceTransition.Reason)
	}
	// A terminal root carries no promised update time.
	root := shIntentOfClass(t, commit.History.Intents, "root_sync")
	stored, err := st.GetNotificationIntent(ctx, root.ID)
	if err != nil {
		t.Fatalf("GetNotificationIntent: %v", err)
	}
	if stored.ContractDeadlineAt != nil {
		t.Fatalf("terminal root_sync contract deadline = %v, want none", stored.ContractDeadlineAt)
	}
}
