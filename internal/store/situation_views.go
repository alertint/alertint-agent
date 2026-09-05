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
