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

	"github.com/google/uuid"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// ErrVersionConflict means a semantic-profile head changed before the caller's
// optimistic write reached the store.
var ErrVersionConflict = errors.New("store: semantic profile version conflict")

// SemanticProfileChange is a durable, advisory-only profile-change handoff for
// the later Situation scheduler. It grants no authority to this package.
type SemanticProfileChange struct {
	SignatureKey string
	Version      int
	Reason       string
	CreatedAt    time.Time
}

// SemanticProfile returns the current head together with every immutable
// version, oldest first.
func (s *Store) SemanticProfile(ctx context.Context, signature string) (*profilemodel.History, error) {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return nil, errors.New("store: semantic profile signature is required")
	}
	history := &profilemodel.History{SignatureKey: signature}
	if err := s.db.QueryRowContext(ctx, `SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, signature).Scan(&history.CurrentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: read semantic profile head: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, signature_key, version, source, signature_material_json, profile_json,
		       origin, input_digest, model, prompt_version, token_usage_json, asserted_by, created_at, superseded_at
		FROM semantic_profile_versions WHERE signature_key = ? ORDER BY version ASC`, signature)
	if err != nil {
		return nil, fmt.Errorf("store: read semantic profile versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		v, err := scanSemanticProfileVersion(rows)
		if err != nil {
			return nil, err
		}
		history.Versions = append(history.Versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate semantic profile versions: %w", err)
	}
	if len(history.Versions) != history.CurrentVersion {
		return nil, errors.New("store: semantic profile head/version history mismatch")
	}
	return history, nil
}

// SemanticProfileChanges exposes the durable profile-change outbox in creation
// order. Consumption/acknowledgement belongs to the later Situation scheduler.
func (s *Store) SemanticProfileChanges(ctx context.Context, limit int) ([]SemanticProfileChange, error) {
	if limit <= 0 {
		return nil, errors.New("store: semantic profile change limit must be positive")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT signature_key, version, reason, created_at FROM semantic_profile_change_outbox ORDER BY created_at ASC, signature_key ASC, version ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: read semantic profile changes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]SemanticProfileChange, 0, limit)
	for rows.Next() {
		var change SemanticProfileChange
		var created string
		if err := rows.Scan(&change.SignatureKey, &change.Version, &change.Reason, &created); err != nil {
			return nil, fmt.Errorf("store: scan semantic profile change: %w", err)
		}
		var err error
		if change.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
			return nil, fmt.Errorf("store: parse semantic profile change created at: %w", err)
		}
		out = append(out, change)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate semantic profile changes: %w", err)
	}
	return out, nil
}

// AppendSemanticProfileVersion appends expected+1 and changes the current head
// in the same transaction. Version rows are never otherwise rewritten.
func (s *Store) AppendSemanticProfileVersion(ctx context.Context, expected int, v profilemodel.ProfileVersion) error {
	if expected < 0 {
		return errors.New("store: semantic profile expected version must be nonnegative")
	}
	if err := validateSemanticProfileVersion(v); err != nil {
		return err
	}
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	v.Version = expected + 1
	v.CreatedAt = v.CreatedAt.UTC()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}

	profileJSON, err := json.Marshal(v.Profile)
	if err != nil {
		return fmt.Errorf("store: marshal semantic profile: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin semantic profile append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var current int
	err = tx.QueryRowContext(ctx, `SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, v.SignatureKey).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expected != 0 {
			return ErrVersionConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO semantic_profile_heads(signature_key, current_version, updated_at) VALUES (?, 0, ?)`, v.SignatureKey, canonicalTime(v.CreatedAt)); err != nil {
			return fmt.Errorf("store: create semantic profile head: %w", err)
		}
	case err != nil:
		return fmt.Errorf("store: read semantic profile head for append: %w", err)
	case current != expected:
		return ErrVersionConflict
	case expected > 0:
		res, err := tx.ExecContext(ctx, `UPDATE semantic_profile_versions SET superseded_at = ? WHERE signature_key = ? AND version = ? AND superseded_at IS NULL`, canonicalTime(v.CreatedAt), v.SignatureKey, expected)
		if err != nil {
			return fmt.Errorf("store: supersede semantic profile version: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: count superseded semantic profile versions: %w", err)
		}
		if n != 1 {
			return ErrVersionConflict
		}
	}

	var modelName, promptVersion, tokenUsage, assertedBy any
	if v.Model != "" {
		modelName = v.Model
	}
	if v.PromptVersion != "" {
		promptVersion = v.PromptVersion
	}
	if len(v.TokenUsage) != 0 {
		tokenUsage = string(v.TokenUsage)
	}
	if v.AssertedBy != "" {
		assertedBy = v.AssertedBy
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_versions
			(id, signature_key, version, source, signature_material_json, profile_json, origin, input_digest, model, prompt_version, token_usage_json, asserted_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.SignatureKey, v.Version, v.Source, string(v.SignatureMaterial), string(profileJSON), v.Origin, v.InputDigest,
		modelName, promptVersion, tokenUsage, assertedBy, canonicalTime(v.CreatedAt)); err != nil {
		return fmt.Errorf("store: insert semantic profile version: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE semantic_profile_heads SET current_version = ?, updated_at = ? WHERE signature_key = ? AND current_version = ?`, v.Version, canonicalTime(v.CreatedAt), v.SignatureKey, expected)
	if err != nil {
		return fmt.Errorf("store: advance semantic profile head: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count advanced semantic profile heads: %w", err)
	}
	if n != 1 {
		return ErrVersionConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO semantic_profile_change_outbox(signature_key, version, reason, created_at) VALUES (?, ?, 'semantic_profile_changed', ?)`, v.SignatureKey, v.Version, canonicalTime(v.CreatedAt)); err != nil {
		return fmt.Errorf("store: enqueue semantic profile change: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit semantic profile append: %w", err)
	}
	return nil
}

func validateSemanticProfileVersion(v profilemodel.ProfileVersion) error {
	if strings.TrimSpace(v.SignatureKey) == "" || strings.TrimSpace(v.Source) == "" || strings.TrimSpace(v.InputDigest) == "" {
		return errors.New("store: semantic profile signature, source, and input digest are required")
	}
	if len(v.SignatureMaterial) == 0 || !json.Valid(v.SignatureMaterial) {
		return errors.New("store: semantic profile signature material must be JSON")
	}
	if v.Origin != profilemodel.OriginInferred && v.Origin != profilemodel.OriginCorrection {
		return fmt.Errorf("store: semantic profile origin %q is invalid", v.Origin)
	}
	if len(v.TokenUsage) != 0 && !json.Valid(v.TokenUsage) {
		return errors.New("store: semantic profile token usage must be JSON")
	}
	return nil
}

func scanSemanticProfileVersion(s scanner) (profilemodel.ProfileVersion, error) {
	var v profilemodel.ProfileVersion
	var material, profile, created string
	var modelName, promptVersion, tokenUsage, assertedBy, superseded sql.NullString
	if err := s.Scan(&v.ID, &v.SignatureKey, &v.Version, &v.Source, &material, &profile, &v.Origin, &v.InputDigest,
		&modelName, &promptVersion, &tokenUsage, &assertedBy, &created, &superseded); err != nil {
		return profilemodel.ProfileVersion{}, fmt.Errorf("store: scan semantic profile version: %w", err)
	}
	v.SignatureMaterial = json.RawMessage(material)
	if err := json.Unmarshal([]byte(profile), &v.Profile); err != nil {
		return profilemodel.ProfileVersion{}, fmt.Errorf("store: decode semantic profile: %w", err)
	}
	v.Model, v.PromptVersion, v.AssertedBy = modelName.String, promptVersion.String, assertedBy.String
	if tokenUsage.Valid {
		v.TokenUsage = json.RawMessage(tokenUsage.String)
	}
	var err error
	if v.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return profilemodel.ProfileVersion{}, fmt.Errorf("store: parse semantic profile created at: %w", err)
	}
	if superseded.Valid {
		at, err := time.Parse(time.RFC3339Nano, superseded.String)
		if err != nil {
			return profilemodel.ProfileVersion{}, fmt.Errorf("store: parse semantic profile superseded at: %w", err)
		}
		v.SupersededAt = &at
	}
	return v, nil
}
