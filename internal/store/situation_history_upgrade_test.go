// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Step 1: migration 0017 upgrade tests — a populated Plan 2 (migration 16)
// fixture must gain the new STRICT tables and MaxSchemaVersion 17, pass
// PRAGMA foreign_key_check, and acquire zero fabricated Transition history
// for its pre-existing nonterminal/terminal Situations.
// ----------------------------------------------------------------------

// seedMigration16HistoryFixture builds a database file shaped like the
// schema immediately before this task's 0017 (every embedded migration
// through version 16 only, so situation_transitions/situation_episode_
// summaries/situation_transition_stream do not exist yet and
// situation_input_outbox still has its pre-0017 shape) and seeds one
// nonterminal ("active") and one terminal ("closed_unknown") Situation,
// each owning one Incident and one already-"applied" situation_input_outbox
// row — entirely by direct SQL, since the current ApplySituationInput now
// references 0017-only columns (applied_input_version, journal_state) that
// do not exist at this schema version.
func seedMigration16HistoryFixture(t *testing.T, path string) (nonterminalID, terminalID string) {
	t.Helper()
	ctx := context.Background()

	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		) STRICT;
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	fixture := &Store{db: db}
	for _, m := range migrations {
		if m.version > 16 {
			continue
		}
		if err := fixture.applyMigration(ctx, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}

	now := time.Now().UTC()
	nonterminalID = "sit-history-nonterminal"
	terminalID = "sit-history-terminal"

	insertOperationalIncident(ctx, t, fixture, "inc-history-nonterminal", "group-history-nonterminal")
	if err := insertSituation(ctx, fixture, situationRow{id: nonterminalID, groupKey: "group-history-nonterminal", lifecycle: "active"}); err != nil {
		t.Fatalf("insert nonterminal situation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)
	`, nonterminalID, "inc-history-nonterminal", canonicalTime(now)); err != nil {
		t.Fatalf("attach nonterminal membership: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (
			id, idempotency_key, incident_id, kind, group_key, occurred_at,
			status, applied_situation_id, applied_at
		) VALUES ('input-history-nonterminal', 'idem-history-nonterminal', 'inc-history-nonterminal', 'incident_created', 'group-history-nonterminal', ?, 'applied', ?, ?)
	`, canonicalTime(now), nonterminalID, canonicalTime(now)); err != nil {
		t.Fatalf("insert applied input for nonterminal situation: %v", err)
	}

	insertOperationalIncident(ctx, t, fixture, "inc-history-terminal", "group-history-terminal")
	term := canonicalTime(now.Add(time.Hour))
	if err := insertSituation(ctx, fixture, situationRow{
		id: terminalID, groupKey: "group-history-terminal", lifecycle: "closed_unknown",
		terminalAt: term, terminalReason: "resolution_missing",
	}); err != nil {
		t.Fatalf("insert terminal situation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES (?, ?, ?)
	`, terminalID, "inc-history-terminal", canonicalTime(now)); err != nil {
		t.Fatalf("attach terminal membership: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (
			id, idempotency_key, incident_id, kind, group_key, occurred_at,
			status, applied_situation_id, applied_at
		) VALUES ('input-history-terminal', 'idem-history-terminal', 'inc-history-terminal', 'incident_created', 'group-history-terminal', ?, 'applied', ?, ?)
	`, canonicalTime(now), terminalID, canonicalTime(now)); err != nil {
		t.Fatalf("insert applied input for terminal situation: %v", err)
	}

	return nonterminalID, terminalID
}

// TestSituationHistoryUpgrade_CreatesStrictTablesAndBumpsSchemaVersion is
// the brief's literal Step 1 test: opening a migration-16 database with the
// current Open must apply 0017, create its three new STRICT tables, bump
// MaxSchemaVersion to 17, pass PRAGMA foreign_key_check, and leave the
// fixture's pre-existing nonterminal/terminal Situations with zero
// Transitions.
func TestSituationHistoryUpgrade_CreatesStrictTablesAndBumpsSchemaVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration16-history.db")
	nonterminalID, terminalID := seedMigration16HistoryFixture(t, path)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	var applied int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 17`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 17 applied count = %d, want 1", applied)
	}

	got, err := MaxSchemaVersion()
	if err != nil {
		t.Fatalf("MaxSchemaVersion: %v", err)
	}
	if got != 17 {
		t.Fatalf("MaxSchemaVersion = %d, want 17", got)
	}

	for _, table := range []string{"situation_transitions", "situation_episode_summaries", "situation_transition_stream"} {
		var name string
		if err := st.DB().QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("table %s missing after upgrade: %v", table, err)
		}
	}

	assertNoForeignKeyViolations(ctx, t, st)

	for _, id := range []string{nonterminalID, terminalID} {
		var count int
		if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("situation %s: transitions = %d, want 0 (no fabricated history)", id, count)
		}
	}
}

// TestSituationHistoryUpgrade_ExistingSituationsRemainReadableWithZeroHistory
// proves both a pre-Plan-3 nonterminal and a pre-Plan-3 terminal Situation
// stay fully readable after the upgrade, with a NULL/0 current Transition
// pointer — this migration never invents a Transition to fill that gap.
func TestSituationHistoryUpgrade_ExistingSituationsRemainReadableWithZeroHistory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration16-history-readable.db")
	nonterminalID, terminalID := seedMigration16HistoryFixture(t, path)

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer func() { _ = st.Close() }()

	nonterm, err := st.GetSituation(ctx, nonterminalID)
	if err != nil {
		t.Fatalf("get nonterminal situation: %v", err)
	}
	if nonterm.Lifecycle != situationmodel.LifecycleActive {
		t.Fatalf("nonterminal lifecycle = %s, want active", nonterm.Lifecycle)
	}

	term, err := st.GetSituation(ctx, terminalID)
	if err != nil {
		t.Fatalf("get terminal situation: %v", err)
	}
	if term.Lifecycle != situationmodel.LifecycleClosedUnknown {
		t.Fatalf("terminal lifecycle = %s, want closed_unknown", term.Lifecycle)
	}

	for _, id := range []string{nonterminalID, terminalID} {
		var currentTransitionID sql.NullString
		var currentTransitionSequence int
		if err := st.DB().QueryRowContext(ctx, `SELECT current_transition_id, current_transition_sequence FROM situations WHERE id = ?`, id).
			Scan(&currentTransitionID, &currentTransitionSequence); err != nil {
			t.Fatalf("read current transition pointer for %s: %v", id, err)
		}
		if currentTransitionID.Valid || currentTransitionSequence != 0 {
			t.Fatalf("situation %s current transition pointer = (%v,%d), want (NULL,0)", id, currentTransitionID, currentTransitionSequence)
		}
	}
}

// ----------------------------------------------------------------------
// Step 2: direct constraint/trigger tests for situation_transitions,
// situations' new current-Transition pointer, situation_episode_summaries,
// and situation_transition_stream.
// ----------------------------------------------------------------------

// transitionRow is a minimal, overridable set of columns for inserting a
// row into situation_transitions directly — schema/constraint tests only;
// the folding logic that builds real Transitions is a later task.
type transitionRow struct {
	id                      string
	situationID             string
	sequence                int
	inputVersion            int
	assessmentID            any
	lifecycle               string
	attention               string
	reason                  string
	journalKind             string
	actor                   string
	operatorArtifactInputID any
}

func insertTransition(ctx context.Context, s *Store, r transitionRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	journal := fmt.Sprintf(`{"headline":"t","occurred_at":"%s"}`, now)
	projection := fmt.Sprintf(`{"effective_started_at":"%s","effective_started_at_basis":"source_payload"}`, now)
	contract := `{"next_actor":"none","alertint_action":null,"alertint_status":null,"operator_action_required":null,"next_update_at":null,"next_update_on":[],"wait_reason":null}`
	inputVersion := r.inputVersion
	if inputVersion == 0 {
		inputVersion = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_transitions (
			id, situation_id, sequence, input_version, material_fact_hash,
			assessment_id, lifecycle, attention, action_contract_json,
			reason, journal_kind, journal_json, projection_json,
			operator_artifact_input_id, evidence_refs_json, actor, created_at
		) VALUES (?, ?, ?, ?, 'sha256:mf', ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?)
	`, r.id, r.situationID, r.sequence, inputVersion, r.assessmentID, r.lifecycle, r.attention, contract,
		r.reason, r.journalKind, journal, projection, r.operatorArtifactInputID, r.actor, now)
	return err
}

// insertAuthoritativeAssessmentAttempt seeds a minimal authoritative
// situation_assessment_attempts row (deterministic_controller derivation,
// no provider call) for the same-Situation Transition-assessment guard
// tests below, and returns its id. sequence must be unique per situationID
// (situation_assessment_attempts' own UNIQUE(situation_id,sequence)).
func insertAuthoritativeAssessmentAttempt(ctx context.Context, t *testing.T, s *Store, id, situationID string, sequence int) string {
	t.Helper()
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: id, situationID: situationID, sequence: sequence, inputVer: 1, workAttempt: 1,
		status: "authoritative", derivation: "deterministic_controller", providerStarted: "false", assessmentJSON: "{}",
	}); err != nil {
		t.Fatalf("seed authoritative assessment attempt %s: %v", id, err)
	}
	return id
}

// insertNonAuthoritativeAssessmentAttempt seeds a minimal "stale"
// (non-authoritative) situation_assessment_attempts row and returns its id.
// sequence must be unique per situationID.
func insertNonAuthoritativeAssessmentAttempt(ctx context.Context, t *testing.T, s *Store, id, situationID string, sequence int) string {
	t.Helper()
	if err := insertAssessmentAttempt(ctx, s, assessmentAttemptRow{
		id: id, situationID: situationID, sequence: sequence, inputVer: 1, workAttempt: 1,
		status: "stale", providerStarted: "unknown",
	}); err != nil {
		t.Fatalf("seed non-authoritative assessment attempt %s: %v", id, err)
	}
	return id
}

// TestSituationHistorySchema_TransitionSequenceUniquePerSituation proves the
// (situation_id, sequence) uniqueness constraint.
func TestSituationHistorySchema_TransitionSequenceUniquePerSituation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-tr-uniq", "group-tr-uniq")
	if err := insertSituation(ctx, s, situationRow{id: "sit-tr-uniq", groupKey: "group-tr-uniq", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-1", situationID: "sit-tr-uniq", sequence: 1, lifecycle: "active", attention: "observe",
		reason: "first_authoritative_state", journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("insert first transition: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-2", situationID: "sit-tr-uniq", sequence: 1, lifecycle: "active", attention: "observe",
		reason: "attention_changed", journalKind: "none", actor: "deterministic_controller",
	}); err == nil {
		t.Fatal("expected duplicate (situation_id,sequence) to be rejected")
	}
}

// TestSituationHistorySchema_TransitionIsImmutable proves a Transition row
// can never be updated or deleted once inserted.
func TestSituationHistorySchema_TransitionIsImmutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-tr-immut", "group-tr-immut")
	if err := insertSituation(ctx, s, situationRow{id: "sit-tr-immut", groupKey: "group-tr-immut", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-immut", situationID: "sit-tr-immut", sequence: 1, lifecycle: "active", attention: "observe",
		reason: "first_authoritative_state", journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("insert transition: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE situation_transitions SET attention = 'urgent' WHERE id = 'tr-immut'`); err == nil {
		t.Fatal("expected update of a transition to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM situation_transitions WHERE id = 'tr-immut'`); err == nil {
		t.Fatal("expected delete of a transition to be rejected")
	}
}

// TestSituationHistorySchema_TransitionAssessmentGuardRejectsForeignOrNonAuthoritative
// proves the same-Situation authoritative-Assessment guard: a Transition
// may cite only an authoritative attempt owned by its own Situation.
func TestSituationHistorySchema_TransitionAssessmentGuardRejectsForeignOrNonAuthoritative(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-tr-assess", "group-tr-assess")
	if err := insertSituation(ctx, s, situationRow{id: "sit-tr-assess", groupKey: "group-tr-assess", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertSituation(ctx, s, situationRow{id: "sit-tr-assess-other", groupKey: "group-tr-assess-other", lifecycle: "active"}); err != nil {
		t.Fatalf("insert other situation: %v", err)
	}

	nonAuth := insertNonAuthoritativeAssessmentAttempt(ctx, t, s, "attempt-rejected", "sit-tr-assess", 1)
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-bad-attempt", situationID: "sit-tr-assess", sequence: 1, assessmentID: nonAuth,
		lifecycle: "active", attention: "observe", reason: "first_authoritative_state",
		journalKind: "publication", actor: "deterministic_controller",
	}); err == nil {
		t.Fatal("expected a non-authoritative assessment_id to be rejected")
	}

	authOther := insertAuthoritativeAssessmentAttempt(ctx, t, s, "attempt-other-situation", "sit-tr-assess-other", 1)
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-foreign-attempt", situationID: "sit-tr-assess", sequence: 1, assessmentID: authOther,
		lifecycle: "active", attention: "observe", reason: "first_authoritative_state",
		journalKind: "publication", actor: "deterministic_controller",
	}); err == nil {
		t.Fatal("expected a foreign-situation authoritative assessment_id to be rejected")
	}

	authSame := insertAuthoritativeAssessmentAttempt(ctx, t, s, "attempt-same-situation", "sit-tr-assess", 2)
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-good-attempt", situationID: "sit-tr-assess", sequence: 1, assessmentID: authSame,
		lifecycle: "active", attention: "observe", reason: "first_authoritative_state",
		journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("expected a same-situation authoritative assessment_id to be accepted: %v", err)
	}
}

// TestSituationHistorySchema_CurrentTransitionPointerMustBeSameSituation
// proves situations' current-Transition pointer guard: it may reference
// only a Transition owned by that exact Situation, at the matching
// sequence.
func TestSituationHistorySchema_CurrentTransitionPointerMustBeSameSituation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-ptr", "group-ptr")
	if err := insertSituation(ctx, s, situationRow{id: "sit-ptr-a", groupKey: "group-ptr-a", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation a: %v", err)
	}
	if err := insertSituation(ctx, s, situationRow{id: "sit-ptr-b", groupKey: "group-ptr-b", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation b: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-ptr-a", situationID: "sit-ptr-a", sequence: 1, lifecycle: "active", attention: "observe",
		reason: "first_authoritative_state", journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("insert transition for a: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE situations SET current_transition_id = 'tr-ptr-a', current_transition_sequence = 1 WHERE id = 'sit-ptr-b'`); err == nil {
		t.Fatal("expected pointing sit-ptr-b at sit-ptr-a's transition to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE situations SET current_transition_id = 'tr-ptr-a', current_transition_sequence = 2 WHERE id = 'sit-ptr-a'`); err == nil {
		t.Fatal("expected a mismatched current_transition_sequence to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE situations SET current_transition_id = 'tr-ptr-a', current_transition_sequence = 1 WHERE id = 'sit-ptr-a'`); err != nil {
		t.Fatalf("expected a matching same-situation pointer to be accepted: %v", err)
	}
}

// episodeSummaryRow is a minimal, overridable set of columns for inserting
// a row into situation_episode_summaries directly.
type episodeSummaryRow struct {
	situationID              string
	version                  int
	sourceTransitionSequence int
}

func insertEpisodeSummary(ctx context.Context, s *Store, r episodeSummaryRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_episode_summaries (
			situation_id, version, source_transition_sequence, summary_json, updated_at
		) VALUES (?, ?, ?, '{"title":"t"}', ?)
	`, r.situationID, r.version, r.sourceTransitionSequence, now)
	return err
}

// TestSituationHistorySchema_OneCurrentEpisodeSummaryPerSituation proves the
// PRIMARY KEY(situation_id) invariant: at most one current summary row per
// Situation.
func TestSituationHistorySchema_OneCurrentEpisodeSummaryPerSituation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-ep-one", "group-ep-one")
	if err := insertSituation(ctx, s, situationRow{id: "sit-ep-one", groupKey: "group-ep-one", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-ep-one", situationID: "sit-ep-one", sequence: 1, lifecycle: "active", attention: "observe",
		reason: "first_authoritative_state", journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("insert transition: %v", err)
	}
	if err := insertEpisodeSummary(ctx, s, episodeSummaryRow{situationID: "sit-ep-one", version: 1, sourceTransitionSequence: 1}); err != nil {
		t.Fatalf("insert first episode summary: %v", err)
	}
	if err := insertEpisodeSummary(ctx, s, episodeSummaryRow{situationID: "sit-ep-one", version: 1, sourceTransitionSequence: 1}); err == nil {
		t.Fatal("expected a second situation_episode_summaries row for the same situation to be rejected")
	}
}

// TestSituationHistorySchema_EpisodeSummarySourceSequenceMustReferenceTransition
// proves the composite foreign key: source_transition_sequence must name an
// actual Transition sequence belonging to the same Situation.
func TestSituationHistorySchema_EpisodeSummarySourceSequenceMustReferenceTransition(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-ep-fk", "group-ep-fk")
	if err := insertSituation(ctx, s, situationRow{id: "sit-ep-fk", groupKey: "group-ep-fk", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertEpisodeSummary(ctx, s, episodeSummaryRow{situationID: "sit-ep-fk", version: 1, sourceTransitionSequence: 1}); err == nil {
		t.Fatal("expected an episode summary with no matching transition to be rejected")
	}
}

// TestSituationHistorySchema_EpisodeSummaryVersionAndSourceSequenceMustAdvance
// proves the monotonic fence: version must advance by exactly 1 and
// source_transition_sequence must strictly increase on every fold.
func TestSituationHistorySchema_EpisodeSummaryVersionAndSourceSequenceMustAdvance(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-ep-mono", "group-ep-mono")
	if err := insertSituation(ctx, s, situationRow{id: "sit-ep-mono", groupKey: "group-ep-mono", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	for _, seq := range []int{1, 2} {
		if err := insertTransition(ctx, s, transitionRow{
			id: fmt.Sprintf("tr-ep-mono-%d", seq), situationID: "sit-ep-mono", sequence: seq,
			lifecycle: "active", attention: "observe", reason: "attention_changed",
			journalKind: "none", actor: "deterministic_controller",
		}); err != nil {
			t.Fatalf("insert transition %d: %v", seq, err)
		}
	}
	if err := insertEpisodeSummary(ctx, s, episodeSummaryRow{situationID: "sit-ep-mono", version: 1, sourceTransitionSequence: 1}); err != nil {
		t.Fatalf("insert first episode summary: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE situation_episode_summaries SET version = 3, source_transition_sequence = 2 WHERE situation_id = 'sit-ep-mono'`); err == nil {
		t.Fatal("expected a version skip to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE situation_episode_summaries SET version = 2, source_transition_sequence = 1 WHERE situation_id = 'sit-ep-mono'`); err == nil {
		t.Fatal("expected a non-increasing source_transition_sequence to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE situation_episode_summaries SET version = 2, source_transition_sequence = 2 WHERE situation_id = 'sit-ep-mono'`); err != nil {
		t.Fatalf("expected a legal fold-forward update to succeed: %v", err)
	}
}

// transitionStreamRow is a minimal set of columns for inserting a row into
// situation_transition_stream directly.
type transitionStreamRow struct {
	id           string
	transitionID string
	situationID  string
	sequence     int
}

func insertTransitionStream(ctx context.Context, s *Store, r transitionStreamRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_transition_stream (
			id, transition_id, situation_id, sequence, status, created_at
		) VALUES (?, ?, ?, ?, 'pending', ?)
	`, r.id, r.transitionID, r.situationID, r.sequence, now)
	return err
}

// TestSituationHistorySchema_TransitionStreamOneRowPerTransition proves the
// UNIQUE(transition_id) constraint.
func TestSituationHistorySchema_TransitionStreamOneRowPerTransition(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-stream-uniq", "group-stream-uniq")
	if err := insertSituation(ctx, s, situationRow{id: "sit-stream-uniq", groupKey: "group-stream-uniq", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-stream-uniq", situationID: "sit-stream-uniq", sequence: 1, lifecycle: "active", attention: "observe",
		reason: "first_authoritative_state", journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("insert transition: %v", err)
	}
	if err := insertTransitionStream(ctx, s, transitionStreamRow{id: "stream-1", transitionID: "tr-stream-uniq", situationID: "sit-stream-uniq", sequence: 1}); err != nil {
		t.Fatalf("insert first stream row: %v", err)
	}
	if err := insertTransitionStream(ctx, s, transitionStreamRow{id: "stream-2", transitionID: "tr-stream-uniq", situationID: "sit-stream-uniq", sequence: 1}); err == nil {
		t.Fatal("expected a second stream row for the same transition to be rejected")
	}
}

// TestSituationHistorySchema_TransitionStreamIdentityImmutableButStatusMutable
// proves stream rows reject any change to their identity columns and reject
// delete entirely, while a worker's ordinary lease/status/delivery updates
// succeed.
func TestSituationHistorySchema_TransitionStreamIdentityImmutableButStatusMutable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-stream-immut", "group-stream-immut")
	if err := insertSituation(ctx, s, situationRow{id: "sit-stream-immut", groupKey: "group-stream-immut", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-stream-immut", situationID: "sit-stream-immut", sequence: 1, lifecycle: "active", attention: "observe",
		reason: "first_authoritative_state", journalKind: "publication", actor: "deterministic_controller",
	}); err != nil {
		t.Fatalf("insert transition: %v", err)
	}
	if err := insertTransitionStream(ctx, s, transitionStreamRow{id: "stream-immut", transitionID: "tr-stream-immut", situationID: "sit-stream-immut", sequence: 1}); err != nil {
		t.Fatalf("insert stream row: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `UPDATE situation_transition_stream SET lease_owner = 'worker-1', lease_expires_at = ? WHERE id = 'stream-immut'`, now); err != nil {
		t.Fatalf("expected claiming (lease fields) to be accepted: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE situation_transition_stream SET status = 'delivered', delivered_at = ?, lease_owner = NULL, lease_expires_at = NULL WHERE id = 'stream-immut'
	`, now); err != nil {
		t.Fatalf("expected delivering to be accepted: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE situation_transition_stream SET sequence = 2 WHERE id = 'stream-immut'`); err == nil {
		t.Fatal("expected changing sequence identity to be rejected")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM situation_transition_stream WHERE id = 'stream-immut'`); err == nil {
		t.Fatal("expected delete of a stream row to be rejected")
	}
}

// ----------------------------------------------------------------------
// Step 3: operator-artifact provenance and the R1/R2 journaling cursor on
// the rebuilt situation_input_outbox.
// ----------------------------------------------------------------------

// insertAnnotationRow seeds a minimal incident_annotations row and returns
// its rowid, for use as situation_input_outbox.annotation_id.
func insertAnnotationRow(ctx context.Context, s *Store, incidentID string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_annotations (incident_id, kind, note, created_at)
		VALUES (?, 'observation', 'note', ?)`, incidentID, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// insertVerdictRow seeds a minimal incident_verdicts row and returns its
// rowid, for use as situation_input_outbox.verdict_id.
func insertVerdictRow(ctx context.Context, s *Store, incidentID string, version int) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_verdicts (incident_id, version, verdict, source, label_confidence, expectation_json, created_at)
		VALUES (?, ?, 'confirmation', 'human', 1.0, '{}', ?)`, incidentID, version, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// artifactInputRow is a minimal, overridable set of columns for inserting a
// situation_input_outbox row directly, covering both artifact and
// non-artifact kinds for the CHECK tests below. journalState/status default
// to "pending" when left empty.
type artifactInputRow struct {
	id           string
	incidentID   string
	groupKey     string
	kind         string
	annotationID any
	verdictID    any
	journalState string
	status       string
	occurredAt   time.Time
}

func insertArtifactInput(ctx context.Context, s *Store, r artifactInputRow) error {
	journalState := r.journalState
	if journalState == "" {
		journalState = "pending"
	}
	status := r.status
	if status == "" {
		status = "pending"
	}
	occurredAt := r.occurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (
			id, idempotency_key, incident_id, kind, group_key, occurred_at,
			status, annotation_id, verdict_id, journal_state
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.id, "idem:"+r.id, r.incidentID, r.kind, r.groupKey, canonicalTime(occurredAt), status, r.annotationID, r.verdictID, journalState)
	return err
}

// TestOperatorArtifactInputSchema_ReferencePairingMatchesKind proves the
// artifact-reference CHECK: exactly the matching reference on each artifact
// kind, and neither reference on any other kind.
func TestOperatorArtifactInputSchema_ReferencePairingMatchesKind(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-artifact-ref", "group-artifact-ref")
	annID, err := insertAnnotationRow(ctx, s, "inc-artifact-ref")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	verdID, err := insertVerdictRow(ctx, s, "inc-artifact-ref", 1)
	if err != nil {
		t.Fatalf("seed verdict: %v", err)
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-1", incidentID: "inc-artifact-ref", groupKey: "group-artifact-ref", kind: "operator_annotation_recorded"}); err == nil {
		t.Fatal("expected annotation kind with no annotation_id to be rejected")
	}
	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-2", incidentID: "inc-artifact-ref", groupKey: "group-artifact-ref", kind: "operator_annotation_recorded", annotationID: annID, verdictID: verdID}); err == nil {
		t.Fatal("expected annotation kind also carrying a verdict_id to be rejected")
	}
	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-3", incidentID: "inc-artifact-ref", groupKey: "group-artifact-ref", kind: "operator_annotation_recorded", annotationID: annID}); err != nil {
		t.Fatalf("expected annotation kind with exactly annotation_id to be accepted: %v", err)
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-4", incidentID: "inc-artifact-ref", groupKey: "group-artifact-ref", kind: "captured_verdict_recorded"}); err == nil {
		t.Fatal("expected verdict kind with no verdict_id to be rejected")
	}
	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-5", incidentID: "inc-artifact-ref", groupKey: "group-artifact-ref", kind: "captured_verdict_recorded", verdictID: verdID}); err != nil {
		t.Fatalf("expected verdict kind with exactly verdict_id to be accepted: %v", err)
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-6", incidentID: "inc-artifact-ref", groupKey: "group-artifact-ref", kind: "incident_created", annotationID: annID, journalState: "not_applicable"}); err == nil {
		t.Fatal("expected a non-artifact kind carrying annotation_id to be rejected")
	}
}

// TestOperatorArtifactInputSchema_JournalStateMatchesKind proves
// journal_state='not_applicable' iff the kind is not an artifact kind.
func TestOperatorArtifactInputSchema_JournalStateMatchesKind(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-artifact-journal", "group-artifact-journal")
	annID, err := insertAnnotationRow(ctx, s, "inc-artifact-journal")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-j1", incidentID: "inc-artifact-journal", groupKey: "group-artifact-journal", kind: "operator_annotation_recorded", annotationID: annID, journalState: "not_applicable"}); err == nil {
		t.Fatal("expected an artifact-kind row with journal_state=not_applicable to be rejected")
	}
	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-j2", incidentID: "inc-artifact-journal", groupKey: "group-artifact-journal", kind: "incident_created", journalState: "pending"}); err == nil {
		t.Fatal("expected a non-artifact-kind row with journal_state=pending to be rejected")
	}
	if err := insertArtifactInput(ctx, s, artifactInputRow{id: "art-j3", incidentID: "inc-artifact-journal", groupKey: "group-artifact-journal", kind: "incident_created", journalState: "not_applicable"}); err != nil {
		t.Fatalf("expected a non-artifact-kind row with journal_state=not_applicable to be accepted: %v", err)
	}
}

// TestOperatorArtifactInputSchema_JournaledRequiresTransitionID proves
// journal_state='journaled' iff journaled_transition_id is set, following
// the legal sequence: enqueue pending, a Transition consumes it, then it is
// marked journaled with that Transition's id.
func TestOperatorArtifactInputSchema_JournaledRequiresTransitionID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-artifact-journaled", "group-artifact-journaled")
	annID, err := insertAnnotationRow(ctx, s, "inc-artifact-journaled")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{
		id: "art-journaled-bad", incidentID: "inc-artifact-journaled", groupKey: "group-artifact-journaled",
		kind: "operator_annotation_recorded", annotationID: annID, journalState: "journaled",
	}); err == nil {
		t.Fatal("expected journal_state=journaled with no journaled_transition_id to be rejected")
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{
		id: "art-journaled-ok", incidentID: "inc-artifact-journaled", groupKey: "group-artifact-journaled",
		kind: "operator_annotation_recorded", annotationID: annID, journalState: "pending",
	}); err != nil {
		t.Fatalf("insert pending artifact: %v", err)
	}
	if err := insertSituation(ctx, s, situationRow{id: "sit-artifact-journaled", groupKey: "group-artifact-journaled-owner", lifecycle: "active"}); err != nil {
		t.Fatalf("insert situation: %v", err)
	}
	if err := insertTransition(ctx, s, transitionRow{
		id: "tr-artifact-journaled", situationID: "sit-artifact-journaled", sequence: 1, lifecycle: "active",
		attention: "observe", reason: "operator_artifact_recorded", journalKind: "operator_note",
		actor: "attributed_operator", operatorArtifactInputID: "art-journaled-ok",
	}); err != nil {
		t.Fatalf("insert transition: %v", err)
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE situation_input_outbox SET journal_state = 'journaled', journaled_transition_id = ? WHERE id = 'art-journaled-ok'
	`, "tr-artifact-journaled"); err != nil {
		t.Fatalf("expected journal_state=journaled with journaled_transition_id set to be accepted: %v", err)
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{
		id: "art-journaled-2", incidentID: "inc-artifact-journaled", groupKey: "group-artifact-journaled",
		kind: "operator_annotation_recorded", annotationID: annID, journalState: "pending",
	}); err != nil {
		t.Fatalf("insert second pending artifact: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE situation_input_outbox SET journaled_transition_id = ? WHERE id = 'art-journaled-2'`, "tr-artifact-journaled"); err == nil {
		t.Fatal("expected setting journaled_transition_id while journal_state stays pending to be rejected")
	}
}

// TestOperatorArtifactInputSchema_OwnerTerminalRequiresAppliedStatus proves
// journal_state='owner_terminal' is accepted only alongside status='applied'.
func TestOperatorArtifactInputSchema_OwnerTerminalRequiresAppliedStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertOperationalIncident(ctx, t, s, "inc-artifact-ownerterm", "group-artifact-ownerterm")
	annID, err := insertAnnotationRow(ctx, s, "inc-artifact-ownerterm")
	if err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	now := time.Now().UTC()
	if err := insertSituation(ctx, s, situationRow{
		id: "sit-artifact-ownerterm", groupKey: "group-artifact-ownerterm-owner", lifecycle: "closed_unknown",
		terminalAt: canonicalTime(now), terminalReason: "resolution_missing",
	}); err != nil {
		t.Fatalf("insert terminal situation: %v", err)
	}

	if err := insertArtifactInput(ctx, s, artifactInputRow{
		id: "art-ownerterm-bad", incidentID: "inc-artifact-ownerterm", groupKey: "group-artifact-ownerterm",
		kind: "operator_annotation_recorded", annotationID: annID, journalState: "owner_terminal", status: "pending",
	}); err == nil {
		t.Fatal("expected journal_state=owner_terminal with status!=applied to be rejected")
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO situation_input_outbox (
			id, idempotency_key, incident_id, kind, group_key, occurred_at,
			status, annotation_id, journal_state, applied_situation_id, applied_at
		) VALUES (?, ?, ?, 'operator_annotation_recorded', ?, ?, 'applied', ?, 'owner_terminal', ?, ?)
	`, "art-ownerterm-ok", "idem:art-ownerterm-ok", "inc-artifact-ownerterm", "group-artifact-ownerterm",
		canonicalTime(now), annID, "sit-artifact-ownerterm", canonicalTime(now)); err != nil {
		t.Fatalf("expected journal_state=owner_terminal with status=applied to be accepted: %v", err)
	}
}
