// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// historyFactsProjections is one projection per shape the history reads
// must agree on: legacy rows without candidates, every candidate kind, the
// limitation and action facts the folds carry, a briefing with and without
// execution start, and the degenerate JSON shapes Go never writes.
func historyFactsProjections(t *testing.T) []struct {
	journal    situationmodel.JournalKind
	projection string
} {
	t.Helper()
	firing := make([]string, 300)
	for i := range firing {
		firing[i] = fmt.Sprintf("KubePodCrashLooping/payments-%03d", i)
	}
	next := situationmodel.NextStepFacts{Kind: situationmodel.NextStepStatusCheck}
	members := situationmodel.MaterialCandidate{Kind: situationmodel.CandidateMembersChanged,
		Members: &situationmodel.MemberFacts{NowFiring: firing[:1], StillFiring: firing, FiringCount: len(firing), Total: len(firing)}, Next: next}
	finding := &situationmodel.FindingFacts{IncidentID: "inc-1", Hypothesis: "a deploy broke payments", Observations: []string{"5xx rose"}}
	briefing := func(started bool) *situationmodel.OperatorBriefing {
		b := &situationmodel.OperatorBriefing{}
		b.Work.ExecutionStarted = started
		return b
	}
	withCandidates := func(started *bool, cs ...situationmodel.MaterialCandidate) string {
		p := situationmodel.ProjectionFacts{OperatorDelta: &situationmodel.OperatorDelta{Candidates: cs}}
		if started != nil {
			p.Briefing = briefing(*started)
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	yes, no := true, false
	out := []struct {
		journal    situationmodel.JournalKind
		projection string
	}{
		{situationmodel.JournalInvestigationStarted, `{}`},
		{situationmodel.JournalInvestigationStarted, `{"operator_delta":{}}`},
		{situationmodel.JournalInvestigationChanged, `{"operator_delta":{"candidates":null},"briefing":null}`},
		{situationmodel.JournalInvestigationStarted, `{"operator_delta":{"candidates":[]}}`},
		{situationmodel.JournalInvestigationChanged, `{"operator_delta":{"candidates":[null]}}`},
		{situationmodel.JournalInvestigationChanged, `{"briefing":{"work":{}}}`},
		{situationmodel.JournalInvestigationStarted, withCandidates(&yes, members, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateFirstExecutionAssurance, Members: members.Members, Next: next})},
		{situationmodel.JournalInvestigationStarted, withCandidates(&yes, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateFirstExecutionAssurance, Next: next})},
		{situationmodel.JournalInvestigationChanged, withCandidates(&no, members, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateAbilityChanged, Limitation: &situationmodel.LimitationFacts{Code: "prometheus_unavailable"}, Next: next})},
		{situationmodel.JournalInvestigationChanged, withCandidates(nil, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateAbilityChanged, Limitation: &situationmodel.LimitationFacts{Code: "prometheus_unavailable", Cleared: true}, Next: next})},
		{situationmodel.JournalOperatorContractChanged, withCandidates(&yes, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateActionChanged, Action: &situationmodel.ActionFacts{Introduced: true, Action: situationmodel.OperatorAction("restart_workload")}, Next: next})},
		{situationmodel.JournalOperatorContractChanged, withCandidates(&yes, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateActionChanged, Action: &situationmodel.ActionFacts{Revised: true, Action: situationmodel.OperatorAction("rollback_deploy")}, Next: next})},
		{situationmodel.JournalOperatorContractChanged, withCandidates(&yes, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateActionChanged, Action: &situationmodel.ActionFacts{Withdrawn: true}, Next: next})},
		{situationmodel.JournalEvidenceConclusion, withCandidates(&yes, members, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateUsefulFinding, Finding: finding, Next: next})},
		{situationmodel.JournalEvidenceConclusion, withCandidates(&yes, situationmodel.MaterialCandidate{
			Kind: situationmodel.CandidateInconclusiveCompletion, Finding: finding, Next: next})},
		{situationmodel.JournalRecovered, withCandidates(&yes, situationmodel.MaterialCandidate{Kind: situationmodel.CandidateAllClear, Next: next})},
		{situationmodel.JournalRecoveryRefired, withCandidates(&yes, situationmodel.MaterialCandidate{Kind: situationmodel.CandidateRefire, Next: next})},
		{situationmodel.JournalClosedUnknown, withCandidates(&yes, situationmodel.MaterialCandidate{Kind: situationmodel.CandidateTerminalEnd, Next: next})},
	}
	return out
}

// historyFactsView is everything the delivery-history reads take from one
// Transition.
type historyFactsView struct {
	ID, SituationID  string
	Sequence         int
	JournalKind      situationmodel.JournalKind
	Delta            bool
	Candidates       []situationmodel.MaterialCandidate
	Briefing         bool
	ExecutionStarted bool
}

func historyFactsViewOf(tr situationmodel.Transition) historyFactsView {
	v := historyFactsView{ID: tr.ID, SituationID: tr.SituationID, Sequence: tr.Sequence, JournalKind: tr.JournalKind}
	if d := tr.Projection.OperatorDelta; d != nil {
		v.Delta = true
		for _, c := range d.Candidates {
			v.Candidates = append(v.Candidates, situationmodel.MaterialCandidate{Kind: c.Kind, Limitation: c.Limitation, Action: c.Action})
		}
	}
	if b := tr.Projection.Briefing; b != nil {
		v.Briefing, v.ExecutionStarted = true, b.Work.ExecutionStarted
	}
	return v
}

// assertHistoryFactsMatchProjections checks every Transition in db: its
// facts row must exist and give every history read the same answer as its
// full projection.
func assertHistoryFactsMatchProjections(t *testing.T, db *sql.DB, wantRows int) {
	t.Helper()
	ctx := context.Background()
	assertTableCount(t, db, "situation_transitions", wantRows)
	assertTableCount(t, db, "situation_transition_history_facts", wantRows)

	full := allTransitions(t, db)
	facts := make([]situationmodel.Transition, 0, len(full))
	for _, tr := range full {
		got, err := scanHistoryFacts(db.QueryRowContext(ctx, `SELECT `+historyFactColumns+` FROM situation_transition_history_facts WHERE transition_id = ?`, tr.ID))
		if err != nil {
			t.Fatalf("history facts for %s (sequence %d): %v", tr.ID, tr.Sequence, err)
		}
		facts = append(facts, got)
		if want, have := historyFactsViewOf(tr), historyFactsViewOf(got); !reflect.DeepEqual(want, have) {
			t.Errorf("sequence %d: facts differ from projection\nprojection: %+v\nfacts:      %+v", tr.Sequence, want, have)
		}
		if transitionConveysAssurance(tr) != transitionConveysAssurance(got) {
			t.Errorf("sequence %d: transitionConveysAssurance differs", tr.Sequence)
		}
		if purelyTransientAssurance(tr) != purelyTransientAssurance(got) {
			t.Errorf("sequence %d: purelyTransientAssurance differs", tr.Sequence)
		}
	}
	wantCodes, wantAction := foldLimitationsAndAction(full)
	gotCodes, gotAction := foldLimitationsAndAction(facts)
	if !reflect.DeepEqual(wantCodes, gotCodes) || !reflect.DeepEqual(wantAction, gotAction) {
		t.Errorf("fold differs: projection codes=%v action=%v, facts codes=%v action=%v", wantCodes, wantAction, gotCodes, gotAction)
	}
}

// allTransitions reads every Transition in db with its full projection, in
// (situation, sequence) order.
func allTransitions(t *testing.T, db *sql.DB) []situationmodel.Transition {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT `+transitionColumns+` FROM situation_transitions ORDER BY situation_id, sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var all []situationmodel.Transition
	for rows.Next() {
		tr, err := scanTransition(rows)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, tr)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return all
}

// TestHistoryFactsMatchProjectionsAcrossUpgradeAndInsert covers both ways a
// facts row is written: migration 0047's backfill of Transitions that
// already exist, and the insert trigger for every later Transition.
func TestHistoryFactsMatchProjectionsAcrossUpgradeAndInsert(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "history-facts-upgrade.db")
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	fixture := &Store{db: db}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.version > 46 {
			break
		}
		if err := fixture.applyMigration(ctx, migration); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	sitID := seedReconcileSituation(t, fixture, "group-history-facts", now)
	var existing int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_transitions`).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	projections := historyFactsProjections(t)
	sequence := 100
	for _, p := range projections {
		sequence++
		insertHistoryFactsTransition(t, db, sitID, sequence, p.journal, p.projection)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := openTestStoreWithMigrations(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	assertHistoryFactsMatchProjections(t, st.db, existing+len(projections))

	for _, p := range projections {
		sequence++
		insertHistoryFactsTransition(t, st.db, sitID, sequence, p.journal, p.projection)
	}
	assertHistoryFactsMatchProjections(t, st.db, existing+2*len(projections))

	for _, statement := range []string{
		`UPDATE situation_transition_history_facts SET journal_kind = 'none'`,
		`DELETE FROM situation_transition_history_facts`,
	} {
		if _, err := st.db.ExecContext(ctx, statement); err == nil {
			t.Fatalf("history facts must remain immutable: %s", statement)
		}
	}
}

// TestHistoryFactsInsertLooksUpOneTransition guards the insert trigger's
// cost: it selects from the deriving view by transition id, which must stay
// a primary-key lookup rather than a scan of every Transition's projection.
func TestHistoryFactsInsertLooksUpOneTransition(t *testing.T) {
	st := newTestStore(t)
	rows, err := st.db.QueryContext(context.Background(),
		`EXPLAIN QUERY PLAN SELECT facts_json FROM situation_transition_history_facts_source WHERE transition_id = ?`, "tr-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	searched := false
	for _, detail := range plan {
		if strings.HasPrefix(detail, "SCAN t") {
			t.Fatalf("history facts view scans every transition: %q", plan)
		}
		searched = searched || strings.HasPrefix(detail, "SEARCH t ")
	}
	if !searched {
		t.Fatalf("history facts view does not search transitions by id: %q", plan)
	}
}
