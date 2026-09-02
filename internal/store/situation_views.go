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
// phase, attempt count, and (once decided) the request/skip decision and
// when it was made. It never carries Finding prose or provider content.
type IncidentTriageView struct {
	IncidentID string
	Phase      string
	Attempts   int
	Decision   *string
	DecidedAt  *time.Time
}

// SituationControllerView is the bounded, sanitized read surface MCP and
// audit tooling use: the current Assessment's identity plus its bounded
// contract/hash projection (read straight off situations' current_* columns
// — never by joining full attempt history), current due reasons, up to 20
// recent sanitized attempts, and current per-Incident Triage state.
type SituationControllerView struct {
	SituationID                string
	CurrentAssessmentID        *string
	CurrentActionContract      *situationmodel.ActionContract
	CurrentMaterialFactHash    *string
	CurrentAssessmentBasisHash *string
	DueReasons                 []situationmodel.DueReason
	RecentAttempts             []SanitizedAssessmentAttempt
	Triage                     []IncidentTriageView
}

// GetSituationControllerView reads situationID's bounded controller view.
// Returns ErrNotFound if no such Situation exists.
func (s *Store) GetSituationControllerView(ctx context.Context, situationID string) (SituationControllerView, error) {
	if strings.TrimSpace(situationID) == "" {
		return SituationControllerView{}, errors.New("store: situation controller view requires a situation id")
	}
	view := SituationControllerView{SituationID: situationID}

	var currentAssessmentID, actionContractJSON, materialHash, basisHash, dueReasonsJSON sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT current_assessment_id, current_action_contract_json, current_material_fact_hash,
		       current_assessment_basis_hash, due_reasons_json
		FROM situations WHERE id = ?`, situationID).Scan(
		&currentAssessmentID, &actionContractJSON, &materialHash, &basisHash, &dueReasonsJSON)
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
	view.DueReasons = []situationmodel.DueReason{}
	if dueReasonsJSON.Valid {
		if err := json.Unmarshal([]byte(dueReasonsJSON.String), &view.DueReasons); err != nil {
			return SituationControllerView{}, fmt.Errorf("store: unmarshal situation due reasons: %w", err)
		}
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

func (s *Store) listIncidentTriageViews(ctx context.Context, situationID string) ([]IncidentTriageView, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT si.incident_id, COALESCE(t.phase, ''), COALESCE(t.attempts, 0), t.decision, t.decided_at
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
		var decision, decidedAt sql.NullString
		if err := rows.Scan(&v.IncidentID, &v.Phase, &v.Attempts, &decision, &decidedAt); err != nil {
			return nil, fmt.Errorf("store: scan incident triage view: %w", err)
		}
		v.Decision = stringPtr(decision)
		decided, err := timePtr(decidedAt)
		if err != nil {
			return nil, err
		}
		v.DecidedAt = decided
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate incident triage views: %w", err)
	}
	return out, nil
}
