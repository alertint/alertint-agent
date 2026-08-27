// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// LLMHealthRecord mirrors the singleton row in the llm_health table: the
// durable rolled-up installation-level LLM dependency state.
type LLMHealthRecord struct {
	State             string
	ReasonCode        string
	Detail            string
	UnhealthySince    *time.Time
	OutageGeneration  int64
	LastRealSuccessAt *time.Time
	LastRealCallAt    *time.Time
	LastProbeAt       *time.Time
	LastProbeOutcome  string
	SlackTS           string
	SlackChannel      string
	SlackDelivery     string
	SlackState        string
	SlackGeneration   int64
	RecoveredAt       *time.Time
	UpdatedAt         time.Time
}

// LLMCapabilityRecord mirrors one row in llm_health_capabilities: the
// per-capability observation behind the LLMHealthRecord aggregate.
type LLMCapabilityRecord struct {
	Capability     string
	Healthy        bool
	ReasonCode     string
	Detail         string
	LastSuccessAt  *time.Time
	LastFailureAt  *time.Time
	UnhealthySince *time.Time
	// ContentSubjects is the bounded set of distinct subjects (Incident IDs)
	// that have content-class-failed this capability since its last success —
	// the H1 two-distinct-Incident corroboration evidence. nil/empty means
	// none recorded.
	ContentSubjects []string
	UpdatedAt       time.Time
}

// GetLLMHealth returns the durable aggregate row and every capability row,
// ordered by capability name. A fresh database returns the seeded healthy
// row and zero capabilities.
func (s *Store) GetLLMHealth(ctx context.Context) (LLMHealthRecord, []LLMCapabilityRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT state, reason_code, detail, unhealthy_since, outage_generation,
		       last_real_success_at, last_real_call_at, last_probe_at, last_probe_outcome,
		       slack_ts, slack_channel, slack_delivery, slack_state, slack_generation,
		       recovered_at, updated_at
		FROM llm_health WHERE id = 1
	`)
	rec, err := scanLLMHealth(row)
	if err != nil {
		return LLMHealthRecord{}, nil, fmt.Errorf("store: llm health: get: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT capability, healthy, reason_code, detail, last_success_at, last_failure_at, unhealthy_since, content_subjects, updated_at
		FROM llm_health_capabilities
		ORDER BY capability
	`)
	if err != nil {
		return LLMHealthRecord{}, nil, fmt.Errorf("store: llm health: get capabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var caps []LLMCapabilityRecord
	for rows.Next() {
		c, err := scanLLMCapability(rows)
		if err != nil {
			return LLMHealthRecord{}, nil, fmt.Errorf("store: llm health: scan capability: %w", err)
		}
		caps = append(caps, *c)
	}
	if err := rows.Err(); err != nil {
		return LLMHealthRecord{}, nil, fmt.Errorf("store: llm health: capability rows: %w", err)
	}
	return *rec, caps, nil
}

// SaveLLMHealth upserts the singleton aggregate row and every capability row
// in one transaction. UpdatedAt on both is set from time.Now().UTC() at save
// time, overriding whatever the caller passed.
func (s *Store) SaveLLMHealth(ctx context.Context, rec LLMHealthRecord, caps []LLMCapabilityRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: llm health: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE llm_health SET
			state = ?, reason_code = ?, detail = ?, unhealthy_since = ?, outage_generation = ?,
			last_real_success_at = ?, last_real_call_at = ?, last_probe_at = ?, last_probe_outcome = ?,
			slack_ts = ?, slack_channel = ?, slack_delivery = ?, slack_state = ?, slack_generation = ?,
			recovered_at = ?, updated_at = ?
		WHERE id = 1
	`,
		rec.State, rec.ReasonCode, rec.Detail, nullTime(rec.UnhealthySince), rec.OutageGeneration,
		nullTime(rec.LastRealSuccessAt), nullTime(rec.LastRealCallAt), nullTime(rec.LastProbeAt), rec.LastProbeOutcome,
		rec.SlackTS, rec.SlackChannel, rec.SlackDelivery, rec.SlackState, rec.SlackGeneration,
		nullTime(rec.RecoveredAt), now,
	); err != nil {
		return fmt.Errorf("store: llm health: save: %w", err)
	}

	for _, c := range caps {
		subjects, err := marshalContentSubjects(c.ContentSubjects)
		if err != nil {
			return fmt.Errorf("store: llm health: marshal content_subjects for %s: %w", c.Capability, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO llm_health_capabilities (capability, healthy, reason_code, detail, last_success_at, last_failure_at, unhealthy_since, content_subjects, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(capability) DO UPDATE SET
				healthy = excluded.healthy, reason_code = excluded.reason_code, detail = excluded.detail,
				last_success_at = excluded.last_success_at, last_failure_at = excluded.last_failure_at,
				unhealthy_since = excluded.unhealthy_since, content_subjects = excluded.content_subjects,
				updated_at = excluded.updated_at
		`,
			c.Capability, c.Healthy, c.ReasonCode, c.Detail,
			nullTime(c.LastSuccessAt), nullTime(c.LastFailureAt), nullTime(c.UnhealthySince), subjects, now,
		); err != nil {
			return fmt.Errorf("store: llm health: save capability %s: %w", c.Capability, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: llm health: commit: %w", err)
	}
	return nil
}

// nullTime renders t as a RFC3339Nano string, or nil when t is nil — the
// shape database/sql needs to write SQL NULL for an absent timestamp.
func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// parseNullTime turns a nullable stored timestamp back into *time.Time.
func parseNullTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil //nolint:nilnil // SQL NULL legitimately has no timestamp and no error; callers branch on nil
	}
	v, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func scanLLMHealth(s scanner) (*LLMHealthRecord, error) {
	var (
		rec                                                            LLMHealthRecord
		unhealthySince, lastRealSuccessAt, lastRealCallAt, lastProbeAt sql.NullString
		recoveredAt                                                    sql.NullString
		updatedStr                                                     string
	)
	if err := s.Scan(
		&rec.State, &rec.ReasonCode, &rec.Detail, &unhealthySince, &rec.OutageGeneration,
		&lastRealSuccessAt, &lastRealCallAt, &lastProbeAt, &rec.LastProbeOutcome,
		&rec.SlackTS, &rec.SlackChannel, &rec.SlackDelivery, &rec.SlackState, &rec.SlackGeneration,
		&recoveredAt, &updatedStr,
	); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	var err error
	if rec.UnhealthySince, err = parseNullTime(unhealthySince); err != nil {
		return nil, fmt.Errorf("parse unhealthy_since: %w", err)
	}
	if rec.LastRealSuccessAt, err = parseNullTime(lastRealSuccessAt); err != nil {
		return nil, fmt.Errorf("parse last_real_success_at: %w", err)
	}
	if rec.LastRealCallAt, err = parseNullTime(lastRealCallAt); err != nil {
		return nil, fmt.Errorf("parse last_real_call_at: %w", err)
	}
	if rec.LastProbeAt, err = parseNullTime(lastProbeAt); err != nil {
		return nil, fmt.Errorf("parse last_probe_at: %w", err)
	}
	if rec.RecoveredAt, err = parseNullTime(recoveredAt); err != nil {
		return nil, fmt.Errorf("parse recovered_at: %w", err)
	}
	if rec.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedStr); err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &rec, nil
}

// marshalContentSubjects renders subjects as a JSON array for the
// content_subjects column; nil/empty renders "[]" (the column's NOT NULL
// default), never SQL NULL.
func marshalContentSubjects(subjects []string) (string, error) {
	if len(subjects) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(subjects)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalContentSubjects parses the content_subjects column back into a
// slice; "[]" (or empty) yields nil, matching the zero-value
// LLMCapabilityRecord.ContentSubjects a fresh capability has. Anything that
// is not a JSON array of strings is an error, never an empty set: corrupt
// corroboration evidence must fail loud at load (llmhealth.New) rather than
// silently weaken the two-Incident rule to zero recorded failures.
func unmarshalContentSubjects(raw string) ([]string, error) {
	if raw == "" || raw == "[]" {
		return nil, nil
	}
	var subjects []string
	if err := json.Unmarshal([]byte(raw), &subjects); err != nil {
		return nil, err
	}
	return subjects, nil
}

func scanLLMCapability(s scanner) (*LLMCapabilityRecord, error) {
	var (
		c                                            LLMCapabilityRecord
		lastSuccessAt, lastFailureAt, unhealthySince sql.NullString
		contentSubjects                              string
		updatedStr                                   string
	)
	if err := s.Scan(&c.Capability, &c.Healthy, &c.ReasonCode, &c.Detail, &lastSuccessAt, &lastFailureAt, &unhealthySince, &contentSubjects, &updatedStr); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	var err error
	if c.ContentSubjects, err = unmarshalContentSubjects(contentSubjects); err != nil {
		return nil, fmt.Errorf("parse content_subjects: %w", err)
	}
	if c.LastSuccessAt, err = parseNullTime(lastSuccessAt); err != nil {
		return nil, fmt.Errorf("parse last_success_at: %w", err)
	}
	if c.LastFailureAt, err = parseNullTime(lastFailureAt); err != nil {
		return nil, fmt.Errorf("parse last_failure_at: %w", err)
	}
	if c.UnhealthySince, err = parseNullTime(unhealthySince); err != nil {
		return nil, fmt.Errorf("parse unhealthy_since: %w", err)
	}
	if c.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedStr); err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &c, nil
}
