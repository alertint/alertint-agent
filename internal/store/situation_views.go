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

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Read-only Situation aggregate/evidence views for the MCP Situation tools
// (alertint_situation_list/get/evidence_get) and the existing Incident
// tools' acute_finding_status field. None of this mutates state; every
// write path lives in situations.go, situation_assessments.go, and
// situation_policy.go.

// SituationAnalysisState mirrors incident_analysis_state: the explicit B+
// acute-analysis gate persisted per Incident. An omitted finding is never
// ambiguous — an Incident with no row reads as not_requested.
type SituationAnalysisState struct {
	IncidentID      string
	Status          situation.L1Status
	DecisionReason  string
	LatestAttemptID *string
	UpdatedAt       time.Time
}

// AnalysisStates reads the B+ gate for a batch of Incident ids in one query.
// Ids with no incident_analysis_state row (a pre-migration or dispatch-
// managed=0 gap) map to not_requested rather than being omitted from the
// result.
func (s *Store) AnalysisStates(ctx context.Context, ids []string) (map[string]SituationAnalysisState, error) {
	out := make(map[string]SituationAnalysisState, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	for _, id := range ids {
		out[id] = SituationAnalysisState{IncidentID: id, Status: situation.L1StatusNotRequested, DecisionReason: "no_gate_row"}
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT incident_id, status, decision_reason, latest_attempt_id, updated_at
		FROM incident_analysis_state WHERE incident_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query analysis states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var incidentID, status, decisionReason, updatedAt string
		var latestAttemptID sql.NullString
		if err := rows.Scan(&incidentID, &status, &decisionReason, &latestAttemptID, &updatedAt); err != nil {
			return nil, fmt.Errorf("store: scan analysis state: %w", err)
		}
		at, err := parseSituationTime("incident_analysis_state.updated_at", updatedAt)
		if err != nil {
			return nil, err
		}
		out[incidentID] = SituationAnalysisState{
			IncidentID: incidentID, Status: situation.L1Status(status), DecisionReason: decisionReason,
			LatestAttemptID: nullStringPtr(latestAttemptID), UpdatedAt: at,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate analysis states: %w", err)
	}
	return out, nil
}

// ListSituations returns every Situation — including silent (never
// published, no public_handle) and terminal ones — newest-updated first.
func (s *Store) ListSituations(ctx context.Context, limit int) ([]model.Situation, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+situationColumns+` FROM situations ORDER BY updated_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list situations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []model.Situation
	for rows.Next() {
		sit, err := scanSituation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sit)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situations: %w", err)
	}
	return out, nil
}

// GetSituation resolves one Situation by id or (case-insensitive) public
// handle — either identity an MCP caller may hold.
func (s *Store) GetSituation(ctx context.Context, idOrHandle string) (model.Situation, error) {
	if strings.TrimSpace(idOrHandle) == "" {
		return model.Situation{}, errors.New("store: situation id or handle is required")
	}
	sit, err := querySituation(ctx, s.db, `SELECT `+situationColumns+` FROM situations WHERE id = ?`, idOrHandle)
	if err == nil {
		return sit, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return model.Situation{}, err
	}
	return querySituation(ctx, s.db, `SELECT `+situationColumns+` FROM situations WHERE public_handle = ? COLLATE NOCASE`, idOrHandle)
}

// SituationRootCoordinates returns the Situation's durable Slack root
// coordinates, set once at first publication. ok is false for a Situation
// that has never published (still silent).
func (s *Store) SituationRootCoordinates(ctx context.Context, situationID string) (channel, messageTS string, ok bool, err error) {
	var c, ts sql.NullString
	if scanErr := s.db.QueryRowContext(ctx, `SELECT slack_channel, slack_root_ts FROM situations WHERE id = ?`, situationID).Scan(&c, &ts); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", "", false, ErrNotFound
		}
		return "", "", false, fmt.Errorf("store: read situation root coordinates: %w", scanErr)
	}
	if !c.Valid || !ts.Valid {
		return "", "", false, nil
	}
	return c.String, ts.String, true, nil
}

// SituationMemberIncidents returns the Situation's member Incidents in
// attachment order — its immutable primary membership (situation_incidents).
func (s *Store) SituationMemberIncidents(ctx context.Context, situationID string) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT i.id, i.group_key, i.status, i.first_alert_at, i.last_alert_at, i.ready_at, i.alert_count,
		       COALESCE(i.summary,''), COALESCE(i.root_cause,''), COALESCE(i.confidence,0.0), COALESCE(i.output_json,''),
		       COALESCE(i.enrichment_json,''), i.created_at, i.updated_at, i.last_judged_at
		FROM situation_incidents si JOIN incidents i ON i.id = si.incident_id
		WHERE si.situation_id = ? ORDER BY si.attached_at ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query situation member incidents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Incident
	for rows.Next() {
		inc, err := scanIncidentFull(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation member incidents: %w", err)
	}
	return out, nil
}

// SituationDeliveries returns the immutable delivery ledger rows for every
// member Incident, oldest first — the evidence view's source of truth
// rather than the latest-wins Alert projection.
func (s *Store) SituationDeliveries(ctx context.Context, situationID string) ([]AlertDelivery, error) {
	rows, err := s.db.QueryContext(ctx, deliverySelect+`
		JOIN incident_alert_deliveries iad ON iad.delivery_id = ad.id
		JOIN situation_incidents si ON si.incident_id = iad.incident_id
		WHERE si.situation_id = ? ORDER BY ad.received_at ASC, ad.id ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query situation deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AlertDelivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan situation delivery: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation deliveries: %w", err)
	}
	return out, nil
}

const maxSituationViewRows = 500

// SituationFacts returns the Situation's immutable normalized facts,
// newest-observed first, capped at maxSituationViewRows.
func (s *Store) SituationFacts(ctx context.Context, situationID string) ([]observationmodel.Fact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, situation_id, input_version, kind, subject, value_json, source_capability,
		observed_at, freshness, result_status, digest, evidence_refs_json, material
		FROM situation_facts WHERE situation_id = ? ORDER BY observed_at DESC, id DESC LIMIT ?`, situationID, maxSituationViewRows)
	if err != nil {
		return nil, fmt.Errorf("store: query situation facts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []observationmodel.Fact
	for rows.Next() {
		var f observationmodel.Fact
		var value, observedAt, evidenceRefsJSON string
		var material int
		if err := rows.Scan(&f.ID, &f.SituationID, &f.InputVersion, &f.Kind, &f.Subject, &value, &f.SourceCapability,
			&observedAt, &f.Freshness, &f.ResultStatus, &f.Digest, &evidenceRefsJSON, &material); err != nil {
			return nil, fmt.Errorf("store: scan situation fact: %w", err)
		}
		f.Value = json.RawMessage(value)
		f.Material = material != 0
		if f.ObservedAt, err = parseSituationTime("situation fact observed_at", observedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(evidenceRefsJSON), &f.EvidenceRefs); err != nil {
			return nil, fmt.Errorf("store: decode situation fact evidence refs: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation facts: %w", err)
	}
	return out, nil
}

// SituationObservationRuns returns the Situation's bounded observation runs,
// newest first, capped at maxSituationViewRows.
func (s *Store) SituationObservationRuns(ctx context.Context, situationID string) ([]ObservationRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, situation_id, input_version, proposed_plan_json, validated_plan_json,
		capability, status, observed_at, freshness, truncated, digest, retry_error_class, token_cost, source_call_cost, created_at
		FROM situation_observation_runs WHERE situation_id = ? ORDER BY observed_at DESC, id DESC LIMIT ?`, situationID, maxSituationViewRows)
	if err != nil {
		return nil, fmt.Errorf("store: query situation observation runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ObservationRun
	for rows.Next() {
		var r ObservationRun
		var proposedJSON, validatedJSON, observedAt, createdAt string
		var retryClass sql.NullString
		var truncated int
		if err := rows.Scan(&r.ID, &r.SituationID, &r.InputVersion, &proposedJSON, &validatedJSON, &r.Capability, &r.Status,
			&observedAt, &r.Freshness, &truncated, &r.Digest, &retryClass, &r.TokenCost, &r.SourceCallCost, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan situation observation run: %w", err)
		}
		if err := json.Unmarshal([]byte(proposedJSON), &r.ProposedPlan); err != nil {
			return nil, fmt.Errorf("store: decode proposed observation plan: %w", err)
		}
		if err := json.Unmarshal([]byte(validatedJSON), &r.ValidatedPlan); err != nil {
			return nil, fmt.Errorf("store: decode validated observation plan: %w", err)
		}
		r.Truncated = truncated != 0
		r.RetryErrorClass = nullString(retryClass)
		if r.ObservedAt, err = parseSituationTime("observation run observed_at", observedAt); err != nil {
			return nil, err
		}
		if r.CreatedAt, err = parseSituationTime("observation run created_at", createdAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation observation runs: %w", err)
	}
	return out, nil
}

// SituationAssessmentAttempts returns every Assessment attempt for the
// Situation — proposed, authoritative, rejected, failed, and stale — in
// sequence order. The authoritative subsequence IS the Situation's
// Transition history (D1: no separate transitions table; a committed
// Transition's lifecycle/Attention/action-contract/reason all live in the
// authoritative attempt's validated Assessment).
func (s *Store) SituationAssessmentAttempts(ctx context.Context, situationID string) ([]AssessmentAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, situation_id, sequence, input_version, fact_hash, actor, status,
		trigger_reasons_json, snapshot_digest, proposal_json, validated_json, validation_adjustments_json, model_usage_json,
		created_at, completed_at
		FROM situation_assessment_attempts WHERE situation_id = ? ORDER BY sequence ASC LIMIT ?`, situationID, maxSituationViewRows)
	if err != nil {
		return nil, fmt.Errorf("store: query situation assessment attempts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AssessmentAttempt
	for rows.Next() {
		var a AssessmentAttempt
		var triggerReasonsJSON, createdAt string
		var proposal, validated, adjustments, modelUsage, completedAt sql.NullString
		if err := rows.Scan(&a.ID, &a.SituationID, &a.Sequence, &a.InputVersion, &a.FactHash, &a.Actor, &a.Status,
			&triggerReasonsJSON, &a.SnapshotDigest, &proposal, &validated, &adjustments, &modelUsage, &createdAt, &completedAt); err != nil {
			return nil, fmt.Errorf("store: scan situation assessment attempt: %w", err)
		}
		if err := json.Unmarshal([]byte(triggerReasonsJSON), &a.TriggerReasons); err != nil {
			return nil, fmt.Errorf("store: decode assessment trigger reasons: %w", err)
		}
		a.Proposal = nullableRawJSON(proposal)
		a.Validated = nullableRawJSON(validated)
		a.ValidationAdjustments = nullableRawJSON(adjustments)
		a.ModelUsage = nullableRawJSON(modelUsage)
		if a.CreatedAt, err = parseSituationTime("assessment attempt created_at", createdAt); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			at, err := parseSituationTime("assessment attempt completed_at", completedAt.String)
			if err != nil {
				return nil, err
			}
			a.CompletedAt = &at
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation assessment attempts: %w", err)
	}
	return out, nil
}

// SituationNotifications returns the Situation's notification history,
// oldest first.
func (s *Store) SituationNotifications(ctx context.Context, situationID string) ([]model.NotificationIntent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+notificationIntentColumns+`
		FROM notification_intents WHERE situation_id = ? ORDER BY created_at ASC, id ASC LIMIT ?`, situationID, maxSituationViewRows)
	if err != nil {
		return nil, fmt.Errorf("store: query situation notifications: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []model.NotificationIntent
	for rows.Next() {
		intent, err := scanNotificationIntent(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan situation notification: %w", err)
		}
		out = append(out, intent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation notifications: %w", err)
	}
	return out, nil
}

func nullString(v sql.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.String
}

func nullableRawJSON(v sql.NullString) json.RawMessage {
	if !v.Valid {
		return nil
	}
	return json.RawMessage(v.String)
}
