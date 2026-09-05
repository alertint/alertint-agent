// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 3: bounded, sanitized Situation controller read views. These never
// return a rejected attempt's raw proposal/validated content, a provider
// response body, or free text — only closed/typed codes and the current
// bounded projection columns migration 0015/0016 added specifically so
// this surface never needs to join full attempt/Triage history.
// ----------------------------------------------------------------------

// maxRecentSanitizedAttempts bounds GetSituationControllerView's attempt
// history to the most recent 20 — this is a bounded operator/audit view,
// not full replay (Task 3 brief: "at most 20 recent sanitized attempts").
const maxRecentSanitizedAttempts = 20

// SanitizedAssessmentAttempt is one bounded, sanitized entry in a Situation
// controller view's recent-attempts history. It deliberately excludes
// proposal_json and assessment_json (raw L2 proposal / validated content)
// and exposes validation_errors_json only as parsed bounded typed codes,
// never as a free-text blob or provider response body.
type SanitizedAssessmentAttempt struct {
	ID                     string
	Sequence               int
	InputVersion           int
	RetryEpoch             int
	WorkAttempt            int
	Status                 string
	Derivation             *situationmodel.AssessmentDerivation
	ProviderRequestStarted situationmodel.ProviderRequestStarted
	ValidationErrorCodes   []string
	CreatedAt              time.Time
	CompletedAt            time.Time
}

// IncidentTriageView is one member Incident's bounded current Triage state —
// phase, attempt count, due time, and (once decided) the request/skip
// decision, when it was made, and the two canonical digests (membership,
// Incident-input) the decision itself was made against ("covered digests" —
// Task 9's MCP brief: "Incident Triage decision, phase, attempts, due time,
// and covered digests"). It never carries Finding prose or provider content.
type IncidentTriageView struct {
	IncidentID          string
	Phase               string
	Attempts            int
	Decision            *string
	DecidedAt           *time.Time
	NextAt              *time.Time
	MembershipDigest    *string
	IncidentInputDigest *string
}

// ControllerRetryState is a Situation's bounded controller retry/park
// projection (Task 9 MCP brief: "controller retry/park state") — read
// straight off situations' own retry/park columns, never by joining attempt
// history.
type ControllerRetryState struct {
	RetryEpoch     int
	WorkAttempts   int
	ParkedAt       *time.Time
	ParkedReason   *string
	RetryAt        *time.Time
	LastErrorClass *string
}

// SituationControllerView is the bounded, sanitized read surface MCP and
// audit tooling use: the current Assessment's identity, full content, and
// derivation, plus its bounded contract/hash/eligible-reason projection
// (read straight off situations' current_* columns — never by joining full
// attempt history), current due reasons, up to 20 recent sanitized
// attempts, current per-Incident Triage state, and controller retry/park
// state.
type SituationControllerView struct {
	SituationID                string
	CurrentAssessmentID        *string
	CurrentAssessment          *situationmodel.Assessment
	CurrentDerivation          *situationmodel.AssessmentDerivation
	CurrentActionContract      *situationmodel.ActionContract
	CurrentMaterialFactHash    *string
	CurrentAssessmentBasisHash *string
	// EligibleReasons is the eligible Sufficient-reason candidate set the
	// most recent controller commit derived (identity, code, catalog/
	// predicate versions, evidence references, deterministic-floor flag) —
	// never nil, empty until the first commit.
	EligibleReasons []situationmodel.ReasonCandidate
	DueReasons      []situationmodel.DueReason
	RecentAttempts  []SanitizedAssessmentAttempt
	Triage          []IncidentTriageView
	Retry           ControllerRetryState
}

// GetSituationControllerView reads situationID's bounded controller view.
// Returns ErrNotFound if no such Situation exists.
func (s *Store) GetSituationControllerView(ctx context.Context, situationID string) (SituationControllerView, error) {
	if strings.TrimSpace(situationID) == "" {
		return SituationControllerView{}, errors.New("store: situation controller view requires a situation id")
	}
	view := SituationControllerView{SituationID: situationID}

	var currentAssessmentID, actionContractJSON, materialHash, basisHash, dueReasonsJSON sql.NullString
	var parkedAt, parkedReason, retryAt, lastErrorClass sql.NullString
	var eligibleReasonsJSON string
	var retryEpoch, workAttempts int
	err := s.db.QueryRowContext(ctx, `
		SELECT current_assessment_id, current_action_contract_json, current_material_fact_hash,
		       current_assessment_basis_hash, current_eligible_reasons_json, due_reasons_json,
		       controller_retry_epoch, controller_work_attempts, controller_parked_at, controller_parked_reason,
		       retry_at, last_error_class
		FROM situations WHERE id = ?`, situationID).Scan(
		&currentAssessmentID, &actionContractJSON, &materialHash, &basisHash, &eligibleReasonsJSON, &dueReasonsJSON,
		&retryEpoch, &workAttempts, &parkedAt, &parkedReason, &retryAt, &lastErrorClass)
	if errors.Is(err, sql.ErrNoRows) {
		return SituationControllerView{}, ErrNotFound
	}
	if err != nil {
		return SituationControllerView{}, fmt.Errorf("store: read situation controller projection: %w", err)
	}

	view.CurrentAssessmentID = stringPtr(currentAssessmentID)
	view.CurrentMaterialFactHash = stringPtr(materialHash)
	view.CurrentAssessmentBasisHash = stringPtr(basisHash)
	if actionContractJSON.Valid {
		var contract situationmodel.ActionContract
		if err := json.Unmarshal([]byte(actionContractJSON.String), &contract); err != nil {
			return SituationControllerView{}, fmt.Errorf("store: unmarshal current action contract: %w", err)
		}
		view.CurrentActionContract = &contract
	}
	view.EligibleReasons = []situationmodel.ReasonCandidate{}
	if err := json.Unmarshal([]byte(eligibleReasonsJSON), &view.EligibleReasons); err != nil {
		return SituationControllerView{}, fmt.Errorf("store: unmarshal situation eligible reasons: %w", err)
	}
	if view.EligibleReasons == nil {
		view.EligibleReasons = []situationmodel.ReasonCandidate{}
	}
	view.DueReasons = []situationmodel.DueReason{}
	if dueReasonsJSON.Valid {
		if err := json.Unmarshal([]byte(dueReasonsJSON.String), &view.DueReasons); err != nil {
			return SituationControllerView{}, fmt.Errorf("store: unmarshal situation due reasons: %w", err)
		}
	}
	view.Retry = ControllerRetryState{
		RetryEpoch:     retryEpoch,
		WorkAttempts:   workAttempts,
		ParkedAt:       nil,
		LastErrorClass: stringPtr(lastErrorClass),
	}
	if parkedAt.Valid {
		t, err := time.Parse(time.RFC3339Nano, parkedAt.String)
		if err != nil {
			return SituationControllerView{}, fmt.Errorf("store: parse controller parked_at: %w", err)
		}
		view.Retry.ParkedAt = &t
	}
	view.Retry.ParkedReason = stringPtr(parkedReason)
	if retryAt.Valid {
		t, err := time.Parse(time.RFC3339Nano, retryAt.String)
		if err != nil {
			return SituationControllerView{}, fmt.Errorf("store: parse controller retry_at: %w", err)
		}
		view.Retry.RetryAt = &t
	}

	if currentAssessmentID.Valid {
		assessment, derivation, err := s.readCurrentAssessmentContent(ctx, currentAssessmentID.String)
		if err != nil {
			return SituationControllerView{}, err
		}
		view.CurrentAssessment = assessment
		view.CurrentDerivation = derivation
	}

	attempts, err := s.listRecentSanitizedAttempts(ctx, situationID)
	if err != nil {
		return SituationControllerView{}, err
	}
	view.RecentAttempts = attempts

	triage, err := s.listIncidentTriageViews(ctx, situationID)
	if err != nil {
		return SituationControllerView{}, err
	}
	view.Triage = triage

	return view, nil
}

// readCurrentAssessmentContent reads the full Assessment content and
// derivation off the authoritative attempt row current_assessment_id
// points at — the "current authoritative Assessment and derivation" Task 9's
// MCP brief names, plus the eligible reason cited (Assessment.
// SufficientReason, with its evidence references) and the schema version it
// carries. Never returns proposal_json, raw prompts, or provider content —
// only the already-validated, already-bounded assessment_json column every
// authoritative row carries.
func (s *Store) readCurrentAssessmentContent(ctx context.Context, attemptID string) (*situationmodel.Assessment, *situationmodel.AssessmentDerivation, error) {
	var assessmentJSON sql.NullString
	var derivation sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT assessment_json, derivation FROM situation_assessment_attempts WHERE id = ?`, attemptID).
		Scan(&assessmentJSON, &derivation)
	if errors.Is(err, sql.ErrNoRows) {
		// current_assessment_id pointed at a row that is gone — should not
		// happen given the FK, but a bounded read never fails the whole view.
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("store: read current assessment content: %w", err)
	}
	if !assessmentJSON.Valid {
		return nil, nil, nil
	}
	var a situationmodel.Assessment
	if err := json.Unmarshal([]byte(assessmentJSON.String), &a); err != nil {
		return nil, nil, fmt.Errorf("store: unmarshal current assessment content: %w", err)
	}
	var d *situationmodel.AssessmentDerivation
	if derivation.Valid {
		dv := situationmodel.AssessmentDerivation(derivation.String)
		d = &dv
	}
	return &a, d, nil
}

func (s *Store) listRecentSanitizedAttempts(ctx context.Context, situationID string) ([]SanitizedAssessmentAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, sequence, input_version, retry_epoch, work_attempt, status, derivation,
		       provider_request_started, validation_errors_json, created_at, completed_at
		FROM situation_assessment_attempts
		WHERE situation_id = ?
		ORDER BY sequence DESC
		LIMIT ?`, situationID, maxRecentSanitizedAttempts)
	if err != nil {
		return nil, fmt.Errorf("store: list recent sanitized attempts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []SanitizedAssessmentAttempt{}
	for rows.Next() {
		var a SanitizedAssessmentAttempt
		var derivation sql.NullString
		var providerStarted, validationErrorsJSON, createdAtStr, completedAtStr string
		if err := rows.Scan(&a.ID, &a.Sequence, &a.InputVersion, &a.RetryEpoch, &a.WorkAttempt, &a.Status, &derivation,
			&providerStarted, &validationErrorsJSON, &createdAtStr, &completedAtStr); err != nil {
			return nil, fmt.Errorf("store: scan sanitized attempt: %w", err)
		}
		if derivation.Valid {
			d := situationmodel.AssessmentDerivation(derivation.String)
			a.Derivation = &d
		}
		a.ProviderRequestStarted = situationmodel.ProviderRequestStarted(providerStarted)
		a.ValidationErrorCodes = []string{}
		if err := json.Unmarshal([]byte(validationErrorsJSON), &a.ValidationErrorCodes); err != nil {
			return nil, fmt.Errorf("store: unmarshal sanitized attempt validation error codes: %w", err)
		}
		var err error
		if a.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAtStr); err != nil {
			return nil, fmt.Errorf("store: parse sanitized attempt created_at: %w", err)
		}
		if a.CompletedAt, err = time.Parse(time.RFC3339Nano, completedAtStr); err != nil {
			return nil, fmt.Errorf("store: parse sanitized attempt completed_at: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate sanitized attempts: %w", err)
	}
	return out, nil
}

// listIncidentTriageViews reads each member Incident's Triage state. Phase,
// decision, due time and covered digests come from the incident_triage
// schedule row; the consumed-attempt count is the durable
// incident_triage_attempts ledger (never below the schedule's own counter),
// because a persisted Finding deletes the schedule row
// (CompleteIncidentTriage) while the consumed attempt stays on the ledger —
// the 2026-09-04 lab acceptance run caught the MCP read reporting zero
// attempts for a just-judged Incident. Once the schedule row is gone and a
// successful attempt exists, the phase reads "completed" rather than the
// pre-controller empty phase.
func (s *Store) listIncidentTriageViews(ctx context.Context, situationID string) ([]IncidentTriageView, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT si.incident_id,
		       CASE
		         WHEN t.incident_id IS NULL AND EXISTS (
		           SELECT 1 FROM incident_triage_attempts a
		           WHERE a.incident_id = si.incident_id AND a.result_code = 'success')
		         THEN 'completed'
		         ELSE COALESCE(t.phase, '')
		       END,
		       MAX(COALESCE(t.attempts, 0),
		           (SELECT COUNT(*) FROM incident_triage_attempts a WHERE a.incident_id = si.incident_id)),
		       t.decision, t.decided_at,
		       t.next_at, t.membership_digest, t.incident_input_digest
		FROM situation_incidents si
		LEFT JOIN incident_triage t ON t.incident_id = si.incident_id
		WHERE si.situation_id = ?
		ORDER BY si.attached_at ASC, si.incident_id ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: list incident triage views: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []IncidentTriageView{}
	for rows.Next() {
		var v IncidentTriageView
		var decision, decidedAt, nextAt, membershipDigest, incidentInputDigest sql.NullString
		if err := rows.Scan(&v.IncidentID, &v.Phase, &v.Attempts, &decision, &decidedAt,
			&nextAt, &membershipDigest, &incidentInputDigest); err != nil {
			return nil, fmt.Errorf("store: scan incident triage view: %w", err)
		}
		v.Decision = stringPtr(decision)
		decided, err := timePtr(decidedAt)
		if err != nil {
			return nil, err
		}
		v.DecidedAt = decided
		next, err := timePtr(nextAt)
		if err != nil {
			return nil, err
		}
		v.NextAt = next
		v.MembershipDigest = stringPtr(membershipDigest)
		v.IncidentInputDigest = stringPtr(incidentInputDigest)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate incident triage views: %w", err)
	}
	return out, nil
}

// ----------------------------------------------------------------------
// Plan 3 Task 5: bounded, coherent history read views. Slack delivery, MCP,
// the stdout stream, and replay all read durable history through these —
// never by joining the ledger ad hoc. Every page takes an explicit limit
// and a stable (sequence, id) cursor, and the Episode view reads its
// summary and that summary's source Transition inside ONE snapshot
// transaction so a caller can never combine a newer summary with a source
// Transition it cannot see.
// ----------------------------------------------------------------------

// maxSituationHistoryPage bounds one Transition/stream page. A caller may
// ask for less; it never gets more.
const maxSituationHistoryPage = 100

// TransitionCursor is the stable position of one Transition page: resume
// strictly after this (sequence, id). The zero value starts at the
// beginning.
type TransitionCursor struct {
	Sequence int
	ID       string
}

// SituationEpisodeView is a Situation's current Episode-summary projection
// together with the exact Transition it was folded from — read coherently,
// so the two can never disagree.
type SituationEpisodeView struct {
	Summary          situationmodel.EpisodeSummary
	SourceTransition situationmodel.Transition
}

// GetSituationEpisodeView reads situationID's current Episode summary and
// its source Transition in one snapshot transaction. Returns ErrNotFound
// when the Situation has no Transition folded yet.
func (s *Store) GetSituationEpisodeView(ctx context.Context, situationID string) (SituationEpisodeView, error) {
	if strings.TrimSpace(situationID) == "" {
		return SituationEpisodeView{}, errors.New("store: situation episode view requires a situation id")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SituationEpisodeView{}, fmt.Errorf("store: begin situation episode view: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	summary, err := loadEpisodeSummaryTx(ctx, tx, situationID)
	if err != nil {
		return SituationEpisodeView{}, err
	}
	if summary == nil {
		return SituationEpisodeView{}, ErrNotFound
	}
	source, err := scanTransition(tx.QueryRowContext(ctx,
		`SELECT `+transitionColumns+` FROM situation_transitions WHERE situation_id = ? AND sequence = ?`,
		situationID, summary.SourceTransitionSequence))
	if errors.Is(err, sql.ErrNoRows) {
		// Unreachable through the fenced commit (the summary's composite
		// foreign key names this exact row), so this can only mean a
		// hand-edited database — fail closed rather than return a summary
		// whose authority is missing.
		return SituationEpisodeView{}, fmt.Errorf("store: episode summary for %s names transition sequence %d, which does not exist",
			situationID, summary.SourceTransitionSequence)
	}
	if err != nil {
		return SituationEpisodeView{}, fmt.Errorf("store: read episode source transition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SituationEpisodeView{}, fmt.Errorf("store: commit situation episode view: %w", err)
	}
	return SituationEpisodeView{Summary: *summary, SourceTransition: source}, nil
}

// ListSituationTransitions reads one ordered page of situationID's
// immutable Transition ledger, strictly after cursor, oldest first. limit
// is clamped to maxSituationHistoryPage.
func (s *Store) ListSituationTransitions(ctx context.Context, situationID string, cursor TransitionCursor, limit int) ([]situationmodel.Transition, error) {
	if strings.TrimSpace(situationID) == "" {
		return nil, errors.New("store: situation transition page requires a situation id")
	}
	if limit <= 0 || limit > maxSituationHistoryPage {
		limit = maxSituationHistoryPage
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+transitionColumns+`
		FROM situation_transitions
		WHERE situation_id = ? AND (sequence > ? OR (sequence = ? AND id > ?))
		ORDER BY sequence ASC, id ASC
		LIMIT ?`, situationID, cursor.Sequence, cursor.Sequence, cursor.ID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list situation transitions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []situationmodel.Transition{}
	for rows.Next() {
		tr, err := scanTransition(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan situation transition: %w", err)
		}
		out = append(out, tr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation transitions: %w", err)
	}
	return out, nil
}

// GetSituationTransition reads one exact Transition by ID. Returns
// ErrNotFound when no such Transition exists.
func (s *Store) GetSituationTransition(ctx context.Context, transitionID string) (situationmodel.Transition, error) {
	if strings.TrimSpace(transitionID) == "" {
		return situationmodel.Transition{}, errors.New("store: situation transition read requires a transition id")
	}
	tr, err := scanTransition(s.db.QueryRowContext(ctx,
		`SELECT `+transitionColumns+` FROM situation_transitions WHERE id = ?`, transitionID))
	if errors.Is(err, sql.ErrNoRows) {
		return situationmodel.Transition{}, ErrNotFound
	}
	if err != nil {
		return situationmodel.Transition{}, fmt.Errorf("store: read situation transition: %w", err)
	}
	return tr, nil
}

// GetNotificationIntent reads one exact durable notification intent by ID.
// Returns ErrNotFound when no such intent exists.
func (s *Store) GetNotificationIntent(ctx context.Context, intentID string) (situationmodel.NotificationIntent, error) {
	if strings.TrimSpace(intentID) == "" {
		return situationmodel.NotificationIntent{}, errors.New("store: notification intent read requires an intent id")
	}
	intent, err := scanNotificationIntent(s.db.QueryRowContext(ctx,
		`SELECT `+notificationIntentColumns+` FROM notification_intents WHERE id = ?`, intentID))
	if errors.Is(err, sql.ErrNoRows) {
		return situationmodel.NotificationIntent{}, ErrNotFound
	}
	if err != nil {
		return situationmodel.NotificationIntent{}, fmt.Errorf("store: read notification intent: %w", err)
	}
	return intent, nil
}

// PendingTransitionStreamEntry is one undelivered stdout-stream row plus the
// immutable Transition it records — everything the stdout writer needs
// without a second lookup.
type PendingTransitionStreamEntry struct {
	StreamID   string
	Transition situationmodel.Transition
}

// ListPendingTransitionStream reads one ordered page of undelivered
// stdout-stream rows across every Situation, oldest first, joined to their
// Transitions in one snapshot transaction so an entry can never name a
// Transition the same read cannot see. limit is clamped to
// maxSituationHistoryPage.
func (s *Store) ListPendingTransitionStream(ctx context.Context, limit int) ([]PendingTransitionStreamEntry, error) {
	if limit <= 0 || limit > maxSituationHistoryPage {
		limit = maxSituationHistoryPage
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin pending transition stream page: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT st.id, `+prefixedTransitionColumns+`
		FROM situation_transition_stream st
		JOIN situation_transitions t ON t.id = st.transition_id
		WHERE st.status = 'pending'
		ORDER BY st.created_at ASC, st.situation_id ASC, st.sequence ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list pending transition stream: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []PendingTransitionStreamEntry{}
	for rows.Next() {
		var entry PendingTransitionStreamEntry
		tr, err := scanStreamEntry(rows, &entry.StreamID)
		if err != nil {
			return nil, err
		}
		entry.Transition = tr
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate pending transition stream: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit pending transition stream page: %w", err)
	}
	return out, nil
}
