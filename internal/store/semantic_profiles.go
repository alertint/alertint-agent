// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Plan 4 Task 7: durable advisory semantic-profile inference. See spec.md
// "Source identity and advisory signatures" and "Durable semantic-profile
// inference".
// ----------------------------------------------------------------------

// defaultSemanticProfileMaxAttempts mirrors config.SituationsConfig.
// SemanticProfiles' own default (config.go) — used only when
// SetSemanticProfileMaxAttempts has never been called (every pre-Task-9
// build, and every test that does not care about this value).
const defaultSemanticProfileMaxAttempts = 3

// SetSemanticProfileMaxAttempts configures the max_attempts value frozen
// onto every NEW inference job's row from here on — mirroring Controller.
// SetEvidencePreparer's own setter-after-construction pattern (Task 6):
// cmd/alertint (Task 9) calls this once, from config.SituationsConfig.
// SemanticProfiles.MaxAttempts, before serving traffic. n <= 0 is ignored
// (keeps the current value, defaultSemanticProfileMaxAttempts until set).
func (s *Store) SetSemanticProfileMaxAttempts(n int) {
	if n > 0 {
		s.semanticProfileMaxAttempts = n
	}
}

func (s *Store) maxSemanticProfileAttempts() int {
	if s.semanticProfileMaxAttempts > 0 {
		return s.semanticProfileMaxAttempts
	}
	return defaultSemanticProfileMaxAttempts
}

// semanticSignatureInputForDeliveryTx reads deliveryID's immutable
// alert_deliveries row and reduces it to the profilemodel.SignatureInput
// BuildSignature needs — proven source signal identity when the adapter
// proved one, else the sorted label/annotation key schema and alert name.
// It reads only immutable delivery columns, never the mutable alerts
// projection (spec.md: "Mappings derive only from immutable delivery
// rows"). ProvenTemplateID stays empty: no connector in this build proves a
// rule/template identity distinct from source_signal_id yet.
func semanticSignatureInputForDeliveryTx(ctx context.Context, tx *sql.Tx, deliveryID string) (profilemodel.SignatureInput, error) {
	var source, labelsJSON, annotationsJSON string
	var signalID, signalVersion sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT source, source_signal_id, source_signal_version, labels_json, annotations_json
		FROM alert_deliveries WHERE id = ?`, deliveryID).
		Scan(&source, &signalID, &signalVersion, &labelsJSON, &annotationsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return profilemodel.SignatureInput{}, fmt.Errorf("store: semantic signature input for delivery %s: %w", deliveryID, ErrNotFound)
	}
	if err != nil {
		return profilemodel.SignatureInput{}, fmt.Errorf("store: read delivery for semantic signature: %w", err)
	}

	var labels map[string]string
	if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
		return profilemodel.SignatureInput{}, fmt.Errorf("store: unmarshal delivery labels for semantic signature: %w", err)
	}
	var annotations map[string]string
	if err := json.Unmarshal([]byte(annotationsJSON), &annotations); err != nil {
		return profilemodel.SignatureInput{}, fmt.Errorf("store: unmarshal delivery annotations for semantic signature: %w", err)
	}

	in := profilemodel.SignatureInput{
		Source:         source,
		AlertName:      labels["alertname"],
		LabelKeys:      sortedMapKeys(labels),
		AnnotationKeys: sortedMapKeys(annotations),
	}
	if signalID.Valid {
		in.ProvenSignalID = signalID.String
	}
	if signalVersion.Valid {
		in.ProvenVersion = signalVersion.String
	}
	return in, nil
}

func sortedMapKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// attachDeliverySemanticSignatureTx attaches deliveryID's deterministic
// advisory signature inside an already-open transaction — idempotent (a
// delivery already mapped is a no-op, matching ApplySituationInput's own
// replay safety) — and, only for a genuinely brand-new signature (no head
// and no live job yet: "the missing-profile job", spec.md), enqueues its
// pending inference job with a frozen semantic input digest that later
// arrivals under the SAME signature never touch again. An oversize/invalid
// signature material is a best-effort miss (no row, no job, no error): a
// signature failure must never block the owning Situation's own lifecycle,
// mirroring Plan 4 Task 6's own "connector failure is durable evidence
// limitation, never a fatal Reconcile error" principle.
func attachDeliverySemanticSignatureTx(ctx context.Context, tx *sql.Tx, deliveryID string, maxAttempts int, now time.Time) error {
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM delivery_semantic_signatures WHERE delivery_id = ?`, deliveryID).Scan(&exists)
	if err == nil {
		return nil // already attached — immutable, nothing to redo.
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: check existing delivery semantic signature: %w", err)
	}

	in, err := semanticSignatureInputForDeliveryTx(ctx, tx, deliveryID)
	if err != nil {
		return err
	}
	sig, err := semanticprofile.BuildSignature(in)
	if err != nil {
		return nil //nolint:nilerr // best-effort: oversize/invalid signature material never blocks Situation lifecycle.
	}

	createdAt := canonicalTime(now)
	advisoryOnly := 0
	if sig.AdvisoryOnly {
		advisoryOnly = 1
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO delivery_semantic_signatures (
			delivery_id, signature_key, signature_digest, schema_version, material_json, mode, advisory_only, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		deliveryID, sig.Key, sig.Digest, sig.SchemaVersion, string(sig.Material), sig.Mode, advisoryOnly, createdAt); err != nil {
		return fmt.Errorf("store: insert delivery semantic signature: %w", err)
	}

	var headExists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM semantic_profile_heads WHERE signature_key = ?`, sig.Key).Scan(&headExists)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: check existing semantic profile head: %w", err)
	}
	if err == nil {
		return nil // a profile already exists for this signature — no fresh job needed.
	}

	var liveJobExists int
	err = tx.QueryRowContext(ctx, `
		SELECT 1 FROM semantic_profile_inference_jobs WHERE signature_key = ? AND status IN ('pending','running')`,
		sig.Key).Scan(&liveJobExists)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: check existing live inference job: %w", err)
	}
	if err == nil {
		return nil // another delivery under this same signature already enqueued the (deduplicated) job.
	}

	return insertSemanticProfileInferenceJobTx(ctx, tx, sig.Key, in, maxAttempts, createdAt)
}

func insertSemanticProfileInferenceJobTx(ctx context.Context, tx *sql.Tx, signatureKey string, frozenInput profilemodel.SignatureInput, maxAttempts int, createdAt string) error {
	frozenJSON, err := json.Marshal(frozenInput)
	if err != nil {
		return fmt.Errorf("store: marshal frozen semantic input: %w", err)
	}
	sum := sha256.Sum256(frozenJSON)
	digest := hex.EncodeToString(sum[:])
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_inference_jobs (
			id, signature_key, frozen_input_json, frozen_input_digest, expected_head_version,
			status, attempt, max_attempts, created_at
		) VALUES (?, ?, ?, ?, 0, ?, 0, ?, ?)`,
		uuid.NewString(), signatureKey, string(frozenJSON), digest, profilemodel.JobStatePending, maxAttempts, createdAt); err != nil {
		return fmt.Errorf("store: insert semantic profile inference job: %w", err)
	}
	return nil
}

// BackfillActiveSemanticMappings attaches a semantic signature (and, for a
// brand-new signature, enqueues its inference job) for up to limit
// deliveries belonging to a nonterminal Situation that have no
// delivery_semantic_signatures row yet — recovering rows an interrupted
// ApplySituationInput crash left unattached, or upgrading a pre-Task-7
// database. Deliveries whose only owning Situation is already terminal are
// left for lazy, non-job-creating derivation at read time (spec.md:
// "without queueing inference for terminal-only episodes") — this function
// never attaches them. Returns the number of deliveries attached.
func (s *Store) BackfillActiveSemanticMappings(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT ad.id
		FROM alert_deliveries ad
		JOIN incident_alert_deliveries iad ON iad.delivery_id = ad.id
		JOIN situation_incidents si ON si.incident_id = iad.incident_id
		JOIN situations s ON s.id = si.situation_id
		LEFT JOIN delivery_semantic_signatures dss ON dss.delivery_id = ad.id
		WHERE dss.delivery_id IS NULL AND s.lifecycle IN ('active', 'recovery_pending')
		ORDER BY ad.received_at ASC, ad.id ASC
		LIMIT ?`, limit)
	if err != nil {
		return 0, fmt.Errorf("store: query deliveries missing semantic signatures: %w", err)
	}
	ids, err := scanStringRows(rows)
	if err != nil {
		return 0, fmt.Errorf("store: read delivery ids missing semantic signatures: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin backfill active semantic mappings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	maxAttempts := s.maxSemanticProfileAttempts()
	for _, id := range ids {
		if err := attachDeliverySemanticSignatureTx(ctx, tx, id, maxAttempts, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit backfill active semantic mappings: %w", err)
	}
	return len(ids), nil
}

// RecoverSemanticInference releases every inference job whose lease expired
// before now (a worker process died mid-attempt): a job that had not yet
// spent its last attempt returns to pending, immediately eligible for a
// fresh claim; one already at its own frozen max_attempts is recovered
// directly as exhausted (spec.md: "A crash after the final reservation is
// recovered as exhausted even if no outcome committed") — never re-armed by
// recovery alone, only by a later correction or a newer durable healthy
// generation (Task 8's own concern). Returns the number of jobs recovered.
func (s *Store) RecoverSemanticInference(ctx context.Context, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin recover semantic inference: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, attempt, max_attempts FROM semantic_profile_inference_jobs
		WHERE status = 'running' AND lease_expires_at < ?`, canonicalTime(now))
	if err != nil {
		return 0, fmt.Errorf("store: query stranded semantic inference jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type stranded struct {
		id                   string
		attempt, maxAttempts int
	}
	var jobs []stranded
	for rows.Next() {
		var j stranded
		if err := rows.Scan(&j.id, &j.attempt, &j.maxAttempts); err != nil {
			return 0, fmt.Errorf("store: scan stranded semantic inference job: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: iterate stranded semantic inference jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("store: close stranded semantic inference jobs query: %w", err)
	}

	for _, j := range jobs {
		status := profilemodel.JobStatePending
		var retryAt any
		if j.attempt >= j.maxAttempts {
			status = profilemodel.JobStateExhausted
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE semantic_profile_inference_jobs
			SET status = ?, owner = NULL, lease_expires_at = NULL, retry_at = ?
			WHERE id = ?`, status, retryAt, j.id); err != nil {
			return 0, fmt.Errorf("store: recover stranded semantic inference job %s: %w", j.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit recover semantic inference: %w", err)
	}
	return len(jobs), nil
}

// LoadProfileGuidanceForDeliveries reads the CURRENT head profile for every
// distinct signature deliveryIDs map to (via delivery_semantic_signatures),
// projected down to the narrow observationmodel.ProfileGuidance shape the
// planner consumes — never the full advisory Profile content (subject_kind/
// event_kind/possible_role/companion_signal_kinds/uncertainty are the
// model's own prose, meaningless to plan construction). A delivery with no
// signature mapping yet, or a signature with no head yet (never corrected
// or inferred), contributes nothing — never a synthesized placeholder. The
// result is deduplicated by signature: multiple deliveries sharing one
// signature contribute exactly one guidance entry. versionIDs is the
// parallel slice of frozen version IDs the returned guidance came from,
// for CycleDraft.ProfileVersionIDs.
func (s *Store) LoadProfileGuidanceForDeliveries(ctx context.Context, deliveryIDs []string) ([]observationmodel.ProfileGuidance, []string, error) {
	if len(deliveryIDs) == 0 {
		return nil, nil, nil
	}

	placeholders := make([]string, len(deliveryIDs))
	args := make([]any, len(deliveryIDs))
	for i, id := range deliveryIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT dss.signature_key, h.version_id, v.profile_json
		FROM delivery_semantic_signatures dss
		JOIN semantic_profile_heads h ON h.signature_key = dss.signature_key
		JOIN semantic_profile_versions v ON v.id = h.version_id
		WHERE dss.delivery_id IN (`+strings.Join(placeholders, ",")+`)
		ORDER BY dss.signature_key ASC`, args...) // #nosec G202 -- placeholders is a fixed "?,?,..." run built from len(deliveryIDs) only; all runtime values bound via ? in args
	if err != nil {
		return nil, nil, fmt.Errorf("store: query profile guidance for deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var guidance []observationmodel.ProfileGuidance
	var versionIDs []string
	for rows.Next() {
		var signatureKey, versionID, profileJSON string
		if err := rows.Scan(&signatureKey, &versionID, &profileJSON); err != nil {
			return nil, nil, fmt.Errorf("store: scan profile guidance: %w", err)
		}
		var profile profilemodel.Profile
		if err := json.Unmarshal([]byte(profileJSON), &profile); err != nil {
			return nil, nil, fmt.Errorf("store: unmarshal profile guidance content: %w", err)
		}
		capabilities := make([]observationmodel.Capability, 0, len(profile.UsefulCapabilities))
		for _, c := range profile.UsefulCapabilities {
			capabilities = append(capabilities, observationmodel.Capability(c))
		}
		guidance = append(guidance, observationmodel.ProfileGuidance{
			SignatureKey: signatureKey, VersionID: versionID, HorizonTier: profile.HorizonTier,
			UsefulCapabilities: capabilities, CandidateScope: profile.CandidateScope,
		})
		versionIDs = append(versionIDs, versionID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("store: iterate profile guidance: %w", err)
	}
	return guidance, versionIDs, nil
}

// CorrectSemanticProfile applies an MCP-submitted, confirmed operator
// override: Correction.ExpectedVersion must equal the signature's current
// head version exactly (0 permits creating a missing head) or
// ErrVersionConflict is returned. A valid correction always creates a new
// immutable Version and advances the head — even when its content matches
// the prior version exactly (spec.md: "Correcting to the same effective
// guidance still versions/audits the artifact") — and enqueues one
// head-change outbox row for fan-out. semantic_input_digest reuses the
// signature's most recently created inference job's own frozen digest when
// one exists (so a later completed inference under that job can still
// compare against a coherent value), or the digest of empty content when
// none does — a correction has no inference attempt of its own.
func (s *Store) CorrectSemanticProfile(ctx context.Context, c profilemodel.Correction, now time.Time) (profilemodel.Version, error) {
	if !c.Confirm {
		return profilemodel.Version{}, errors.New("store: correct semantic profile requires confirm=true")
	}
	if c.AssertedBy == "" {
		return profilemodel.Version{}, errors.New("store: correct semantic profile requires a non-empty asserted_by")
	}
	if err := semanticprofile.ValidateProfile(c.Profile); err != nil {
		return profilemodel.Version{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: begin correct semantic profile: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentVersion int
	err = tx.QueryRowContext(ctx, `SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, c.Signature).Scan(&currentVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return profilemodel.Version{}, fmt.Errorf("store: read current semantic profile head: %w", err)
	}
	if currentVersion != c.ExpectedVersion {
		return profilemodel.Version{}, profilemodel.ErrVersionConflict
	}

	inputDigest, err := latestFrozenInputDigestTx(ctx, tx, c.Signature)
	if err != nil {
		return profilemodel.Version{}, err
	}

	profileJSON, err := json.Marshal(c.Profile)
	if err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: marshal corrected profile: %w", err)
	}
	newVersion := currentVersion + 1
	versionID := uuid.NewString()
	createdAt := canonicalTime(now)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_versions (
			id, signature_key, version, schema_version, prompt_version, semantic_input_digest,
			origin, profile_json, created_at, asserted_by
		) VALUES (?, ?, ?, ?, ?, ?, 'correction', ?, ?, ?)`,
		versionID, c.Signature, newVersion, profilemodel.ProfileSchemaVersion, profilemodel.PromptVersion,
		inputDigest, string(profileJSON), createdAt, c.AssertedBy); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: insert corrected semantic profile version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_heads (signature_key, current_version, version_id, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(signature_key) DO UPDATE SET current_version = excluded.current_version,
			version_id = excluded.version_id, updated_at = excluded.updated_at`,
		c.Signature, newVersion, versionID, createdAt); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: advance semantic profile head: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_changes (id, signature_key, version_id, created_at)
		VALUES (?, ?, ?, ?)`, uuid.NewString(), c.Signature, versionID, createdAt); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: enqueue semantic profile change: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: commit correct semantic profile: %w", err)
	}

	return profilemodel.Version{
		ID: versionID, Signature: c.Signature, Version: newVersion,
		SchemaVersion: profilemodel.ProfileSchemaVersion, PromptVersion: profilemodel.PromptVersion,
		SemanticInputDigest: inputDigest, Origin: profilemodel.OriginCorrection,
		Profile: c.Profile, AssertedBy: c.AssertedBy,
	}, nil
}

// GetSemanticProfile reads one advisory signature's bounded profile
// history for alertint_get_semantic_profile: its current head (nil when no
// version has ever been committed — a signature that has only ever had
// inference jobs run/fail), a bounded page of ALL its immutable versions
// newest-first, and its current LIVE inference job state (nil when no job
// is pending/running — the partial unique index on
// semantic_profile_inference_jobs guarantees at most one). limit is
// clamped to [1,100], defaulting to 20; cursor resumes strictly below the
// last page's oldest version number.
func (s *Store) GetSemanticProfile(ctx context.Context, signatureKey, cursor string, limit int) (profilemodel.History, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	var currentVersion int
	err := s.db.QueryRowContext(ctx, `SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, signatureKey).Scan(&currentVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return profilemodel.History{}, fmt.Errorf("store: read semantic profile head: %w", err)
	}

	query := `
		SELECT id, version, schema_version, prompt_version, semantic_input_digest, origin, provider, model,
		       usage_input_tokens, usage_output_tokens, profile_json, created_at, asserted_by
		FROM semantic_profile_versions WHERE signature_key = ?`
	args := []any{signatureKey}
	if cursor != "" {
		before, err := strconv.Atoi(cursor)
		if err != nil {
			return profilemodel.History{}, fmt.Errorf("store: malformed semantic profile cursor %q", cursor)
		}
		query += ` AND version < ?`
		args = append(args, before)
	}
	query += ` ORDER BY version DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return profilemodel.History{}, fmt.Errorf("store: query semantic profile versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var versions []profilemodel.Version
	for rows.Next() {
		v, err := scanSemanticProfileVersionRow(rows, signatureKey)
		if err != nil {
			return profilemodel.History{}, err
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return profilemodel.History{}, fmt.Errorf("store: iterate semantic profile versions: %w", err)
	}
	// Close explicitly before the further queries below (current-version
	// fallback lookup, live job state) — the store's single pooled
	// connection (SetMaxOpenConns(1)) would self-deadlock on a nested query
	// while this rows cursor is still open. The deferred Close above becomes
	// a safe no-op afterward.
	if err := rows.Close(); err != nil {
		return profilemodel.History{}, fmt.Errorf("store: close semantic profile versions query: %w", err)
	}

	nextCursor := ""
	if len(versions) > limit {
		nextCursor = strconv.Itoa(versions[limit-1].Version)
		versions = versions[:limit]
	}

	var current *profilemodel.Version
	if currentVersion > 0 {
		v, err := s.loadSemanticProfileVersionByNumber(ctx, signatureKey, currentVersion)
		if err != nil {
			return profilemodel.History{}, err
		}
		current = &v
	}

	job, err := s.loadLiveSemanticInferenceJobState(ctx, signatureKey)
	if err != nil {
		return profilemodel.History{}, err
	}

	return profilemodel.History{Current: current, Versions: versions, Job: job, NextCursor: nextCursor}, nil
}

// scanSemanticProfileVersionRow scans one semantic_profile_versions row (id,
// version, schema_version, prompt_version, semantic_input_digest, origin,
// provider, model, usage_input_tokens, usage_output_tokens, profile_json,
// created_at, asserted_by, in that order) into a profilemodel.Version.
func scanSemanticProfileVersionRow(rows *sql.Rows, signatureKey string) (profilemodel.Version, error) {
	var (
		id, origin, provider, model, profileJSON, createdAt, assertedBy string
		version, schemaVersion, promptVersion, inTokens, outTokens      int
		semanticInputDigest                                             string
	)
	if err := rows.Scan(&id, &version, &schemaVersion, &promptVersion, &semanticInputDigest, &origin, &provider, &model,
		&inTokens, &outTokens, &profileJSON, &createdAt, &assertedBy); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: scan semantic profile version: %w", err)
	}
	var profile profilemodel.Profile
	if err := json.Unmarshal([]byte(profileJSON), &profile); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: unmarshal semantic profile version content: %w", err)
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: parse semantic profile version created_at: %w", err)
	}
	return profilemodel.Version{
		ID: id, Signature: signatureKey, Version: version, SchemaVersion: schemaVersion, PromptVersion: promptVersion,
		SemanticInputDigest: semanticInputDigest, Origin: origin, Provider: provider, Model: model,
		UsageInputTokens: inTokens, UsageOutputTokens: outTokens, Profile: profile, CreatedAt: created, AssertedBy: assertedBy,
	}, nil
}

// loadSemanticProfileVersionByNumber reads exactly one immutable version by
// its (signature_key, version) unique key — used to resolve the head's
// current version directly rather than relying on it appearing inside
// whatever bounded page GetSemanticProfile's caller happened to request.
func (s *Store) loadSemanticProfileVersionByNumber(ctx context.Context, signatureKey string, version int) (profilemodel.Version, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, version, schema_version, prompt_version, semantic_input_digest, origin, provider, model,
		       usage_input_tokens, usage_output_tokens, profile_json, created_at, asserted_by
		FROM semantic_profile_versions WHERE signature_key = ? AND version = ?`, signatureKey, version)
	var (
		id, origin, provider, model, profileJSON, createdAt, assertedBy string
		v, schemaVersion, promptVersion, inTokens, outTokens            int
		semanticInputDigest                                             string
	)
	if err := row.Scan(&id, &v, &schemaVersion, &promptVersion, &semanticInputDigest, &origin, &provider, &model,
		&inTokens, &outTokens, &profileJSON, &createdAt, &assertedBy); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: read semantic profile head version: %w", err)
	}
	var profile profilemodel.Profile
	if err := json.Unmarshal([]byte(profileJSON), &profile); err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: unmarshal semantic profile head version content: %w", err)
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return profilemodel.Version{}, fmt.Errorf("store: parse semantic profile head version created_at: %w", err)
	}
	return profilemodel.Version{
		ID: id, Signature: signatureKey, Version: v, SchemaVersion: schemaVersion, PromptVersion: promptVersion,
		SemanticInputDigest: semanticInputDigest, Origin: origin, Provider: provider, Model: model,
		UsageInputTokens: inTokens, UsageOutputTokens: outTokens, Profile: profile, CreatedAt: created, AssertedBy: assertedBy,
	}, nil
}

// loadLiveSemanticInferenceJobState reads signatureKey's current
// pending/running job, if one exists — the partial unique index on
// semantic_profile_inference_jobs guarantees at most one such row per
// signature, so no ordering/limit is needed to pick "the" live job.
func (s *Store) loadLiveSemanticInferenceJobState(ctx context.Context, signatureKey string) (*profilemodel.JobState, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT status, attempt, retry_at, error_class FROM semantic_profile_inference_jobs
		WHERE signature_key = ? AND status IN ('pending', 'running')`, signatureKey)
	var status string
	var attempt int
	var retryAt, errorClass sql.NullString
	err := row.Scan(&status, &attempt, &retryAt, &errorClass)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no live pending/running job is a legitimate, common outcome, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("store: read live semantic inference job: %w", err)
	}
	state := &profilemodel.JobState{Status: status, Attempt: attempt}
	if retryAt.Valid {
		t, err := time.Parse(time.RFC3339Nano, retryAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse semantic inference job retry_at: %w", err)
		}
		state.RetryAt = &t
	}
	if errorClass.Valid {
		ec := errorClass.String
		state.ErrorClass = &ec
	}
	return state, nil
}

// ListSituationSemanticSignatures returns the distinct advisory signature
// keys among situationID's current member deliveries — 1 in the common
// case, more when the Situation's deliveries span sources/schemas with
// different proven identity. Used by alertint_get_semantic_profile's
// Situation-handle lookup path to resolve which signature(s) to read.
func (s *Store) ListSituationSemanticSignatures(ctx context.Context, situationID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT dss.signature_key
		FROM delivery_semantic_signatures dss
		JOIN incident_alert_deliveries iad ON iad.delivery_id = dss.delivery_id
		JOIN situation_incidents si ON si.incident_id = iad.incident_id
		WHERE si.situation_id = ?
		ORDER BY dss.signature_key ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query situation semantic signatures: %w", err)
	}
	keys, err := scanStringRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: read situation semantic signatures: %w", err)
	}
	return keys, nil
}

func latestFrozenInputDigestTx(ctx context.Context, tx *sql.Tx, signatureKey string) (string, error) {
	var digest string
	err := tx.QueryRowContext(ctx, `
		SELECT frozen_input_digest FROM semantic_profile_inference_jobs
		WHERE signature_key = ? ORDER BY created_at DESC, id DESC LIMIT 1`, signatureKey).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}
	if err != nil {
		return "", fmt.Errorf("store: read latest frozen semantic input digest: %w", err)
	}
	return digest, nil
}

// ----------------------------------------------------------------------
// Job claim / call reservation / completion — the dispatch surface Task 8's
// worker consumes. Mirrors Task 2's BeginPreparation/
// ReserveObservationRequest/CommitObservationRun split: claiming a job
// never spends a call ("Claiming does not spend a call", spec.md);
// reserving a call durably consumes exactly one attempt slot before the
// request; completing records the immutable outcome and decides the job's
// next state.
// ----------------------------------------------------------------------

// ErrSemanticInferenceAttemptsExhausted is returned by
// ReserveSemanticInferenceCall when the job's frozen max_attempts is
// already spent — the job is durably marked exhausted in the SAME
// transaction, so the caller never needs a separate call to record it. It
// IS semanticprofile.ErrAttemptsExhausted (the same value, not a lookalike
// duplicate) — internal/semanticprofile's own Worker recognizes exhaustion
// via errors.Is against that package's sentinel, and it must never import
// internal/store to reference this one directly, so *Store structurally
// satisfying Worker's ProfileStore interface requires returning the exact
// same underlying error here, mirroring how profilemodel.ErrLeaseLost/
// ErrVersionConflict are already reused directly rather than duplicated.
var ErrSemanticInferenceAttemptsExhausted = semanticprofile.ErrAttemptsExhausted

// ExtendSemanticInferenceJobLease renews jobID's lease to now+lease,
// fenced by owner/token exactly like ExtendControllerLease — the worker's
// own heartbeat while a single bounded CompleteOnce call is still running
// (plan.md: "Heartbeat the job's own owner/token; cancel on lease loss").
// Returns profilemodel.ErrLeaseLost if owner/token no longer match the live
// claim.
func (s *Store) ExtendSemanticInferenceJobLease(ctx context.Context, jobID, owner string, token int64, now time.Time, lease time.Duration) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE semantic_profile_inference_jobs SET lease_expires_at = ?
		WHERE id = ? AND status = 'running' AND owner = ? AND token = ?`,
		canonicalTime(now.Add(lease)), jobID, owner, token)
	if err != nil {
		return fmt.Errorf("store: extend semantic inference job lease: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count extended semantic inference job lease: %w", err)
	}
	if n != 1 {
		return profilemodel.ErrLeaseLost
	}
	return nil
}

// ClaimSemanticInferenceJob claims one due pending job (retry_at NULL or
// already past) for owner, fencing it with a fresh token and a lease
// expiring in lease. found is false (no error) when no job is currently
// due — an ordinary empty-queue poll, not a failure. Claiming never touches
// attempt or spends a call.
func (s *Store) ClaimSemanticInferenceJob(ctx context.Context, owner string, now time.Time, lease time.Duration) (profilemodel.JobClaim, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return profilemodel.JobClaim{}, false, fmt.Errorf("store: begin claim semantic inference job: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var id, signatureKey, frozenInputJSON, frozenInputDigest string
	var expectedHeadVersion, attempt, token int
	err = tx.QueryRowContext(ctx, `
		SELECT id, signature_key, frozen_input_json, frozen_input_digest, expected_head_version, attempt, token
		FROM semantic_profile_inference_jobs
		WHERE status = 'pending' AND (retry_at IS NULL OR retry_at <= ?)
		ORDER BY created_at ASC, id ASC LIMIT 1`, canonicalTime(now)).
		Scan(&id, &signatureKey, &frozenInputJSON, &frozenInputDigest, &expectedHeadVersion, &attempt, &token)
	if errors.Is(err, sql.ErrNoRows) {
		return profilemodel.JobClaim{}, false, nil
	}
	if err != nil {
		return profilemodel.JobClaim{}, false, fmt.Errorf("store: query due semantic inference job: %w", err)
	}

	newToken := token + 1
	leaseExpiresAt := now.Add(lease)
	if _, err := tx.ExecContext(ctx, `
		UPDATE semantic_profile_inference_jobs
		SET status = 'running', owner = ?, token = ?, lease_expires_at = ?, retry_at = NULL
		WHERE id = ?`, owner, newToken, canonicalTime(leaseExpiresAt), id); err != nil {
		return profilemodel.JobClaim{}, false, fmt.Errorf("store: claim semantic inference job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return profilemodel.JobClaim{}, false, fmt.Errorf("store: commit claim semantic inference job: %w", err)
	}

	return profilemodel.JobClaim{
		JobID: id, Signature: signatureKey, FrozenInputJSON: json.RawMessage(frozenInputJSON),
		FrozenInputDigest: frozenInputDigest, ExpectedHeadVersion: expectedHeadVersion,
		Owner: owner, Token: int64(newToken), LeaseExpiresAt: leaseExpiresAt, Attempt: attempt,
	}, true, nil
}

// ReserveSemanticInferenceCall durably reserves exactly one CompleteOnce
// dispatch for jobID — incrementing its attempt counter and inserting the
// immutable semantic_profile_calls row — BEFORE the caller ever issues the
// request, so a crash between this reservation and CompleteSemanticInference
// still durably consumes the attempt (mirroring
// internal/observation.ReserveObservationRequest's own contract). Returns
// ErrLeaseLost if owner/token no longer match the live claim, or
// ErrSemanticInferenceAttemptsExhausted (marking the job exhausted in the
// same transaction) if every configured attempt is already spent.
func (s *Store) ReserveSemanticInferenceCall(ctx context.Context, jobID, owner string, token int64, now time.Time) (string, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, fmt.Errorf("store: begin reserve semantic inference call: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var rowOwner sql.NullString
	var rowToken int64
	var status string
	var attempt, maxAttempts int
	err = tx.QueryRowContext(ctx, `
		SELECT owner, token, status, attempt, max_attempts FROM semantic_profile_inference_jobs WHERE id = ?`, jobID).
		Scan(&rowOwner, &rowToken, &status, &attempt, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, fmt.Errorf("store: reserve semantic inference call: job %s: %w", jobID, ErrNotFound)
	}
	if err != nil {
		return "", 0, fmt.Errorf("store: read semantic inference job for reservation: %w", err)
	}
	if status != "running" || !rowOwner.Valid || rowOwner.String != owner || rowToken != token {
		return "", 0, profilemodel.ErrLeaseLost
	}

	if attempt >= maxAttempts {
		if _, err := tx.ExecContext(ctx, `
			UPDATE semantic_profile_inference_jobs
			SET status = 'exhausted', owner = NULL, lease_expires_at = NULL
			WHERE id = ?`, jobID); err != nil {
			return "", 0, fmt.Errorf("store: mark semantic inference job exhausted: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return "", 0, fmt.Errorf("store: commit exhaust semantic inference job: %w", err)
		}
		return "", 0, ErrSemanticInferenceAttemptsExhausted
	}

	newAttempt := attempt + 1
	callID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_calls (id, job_id, attempt, dispatched_at) VALUES (?, ?, ?, ?)`,
		callID, jobID, newAttempt, canonicalTime(now)); err != nil {
		return "", 0, fmt.Errorf("store: insert semantic inference call: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE semantic_profile_inference_jobs SET attempt = ? WHERE id = ?`, newAttempt, jobID); err != nil {
		return "", 0, fmt.Errorf("store: advance semantic inference job attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("store: commit reserve semantic inference call: %w", err)
	}
	return callID, newAttempt, nil
}

// CompleteSemanticInference records callID's immutable outcome and decides
// the owning job's next state. An outcome the caller reports as accepted is
// downgraded to stale, with no version/head created, if the signature's
// head has advanced since this job began (spec.md: "A late inference
// commits only if the expected head is still absent" / "A correction or
// winning inference makes it stale-complete, without replacing that
// head") — this CAS check and the version/head/change-outbox insert happen
// in the SAME transaction, so no concurrent correction can race between
// the check and the write. A non-accepted outcome retries (status=pending,
// retryAt) while attempts remain, or exhausts once max_attempts is spent.
// retryAt is ignored for an accepted (or downgraded-to-stale) outcome, and
// may be nil for a final (exhausting) non-accepted one.
func (s *Store) CompleteSemanticInference(ctx context.Context, callID, owner string, token int64, result profilemodel.InferenceResult, now time.Time, retryAt *time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin complete semantic inference: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var jobID, signatureKey string
	var rowOwner sql.NullString
	var rowToken int64
	var status string
	var attempt, maxAttempts int
	err = tx.QueryRowContext(ctx, `
		SELECT c.job_id, j.signature_key, j.owner, j.token, j.status, j.attempt, j.max_attempts
		FROM semantic_profile_calls c JOIN semantic_profile_inference_jobs j ON j.id = c.job_id
		WHERE c.id = ?`, callID).
		Scan(&jobID, &signatureKey, &rowOwner, &rowToken, &status, &attempt, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: complete semantic inference: call %s: %w", callID, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("store: read semantic inference call for completion: %w", err)
	}
	if status != "running" || !rowOwner.Valid || rowOwner.String != owner || rowToken != token {
		return profilemodel.ErrLeaseLost
	}

	outcome := result.Outcome
	newJobStatus := profilemodel.JobStateComplete
	var newRetryAt any
	switch result.Outcome {
	case profilemodel.InferenceOutcomeAccepted:
		var headExists int
		herr := tx.QueryRowContext(ctx, `SELECT 1 FROM semantic_profile_heads WHERE signature_key = ?`, signatureKey).Scan(&headExists)
		if herr != nil && !errors.Is(herr, sql.ErrNoRows) {
			return fmt.Errorf("store: check semantic profile head for completion: %w", herr)
		}
		if herr == nil {
			outcome = profilemodel.InferenceOutcomeStale // the expected head is no longer absent — a correction or a sibling job already won.
		} else {
			if err := commitAcceptedInferenceTx(ctx, tx, jobID, signatureKey, *result.Profile, result, now); err != nil {
				return err
			}
		}
	default:
		if attempt >= maxAttempts {
			newJobStatus = profilemodel.JobStateExhausted
		} else {
			newJobStatus = profilemodel.JobStatePending
			if retryAt != nil {
				newRetryAt = canonicalTime(*retryAt)
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_call_outcomes (
			call_id, outcome, request_started, usage_input_tokens, usage_output_tokens, provider, model, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		callID, outcome, result.RequestStarted, result.UsageInputTokens, result.UsageOutputTokens,
		result.Provider, result.Model, canonicalTime(now)); err != nil {
		return fmt.Errorf("store: insert semantic inference call outcome: %w", err)
	}

	if newJobStatus == profilemodel.JobStatePending {
		if _, err := tx.ExecContext(ctx, `
			UPDATE semantic_profile_inference_jobs
			SET status = ?, owner = NULL, lease_expires_at = NULL, retry_at = ?
			WHERE id = ?`, newJobStatus, newRetryAt, jobID); err != nil {
			return fmt.Errorf("store: return semantic inference job to pending: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			UPDATE semantic_profile_inference_jobs
			SET status = ?, owner = NULL, lease_expires_at = NULL
			WHERE id = ?`, newJobStatus, jobID); err != nil {
			return fmt.Errorf("store: finish semantic inference job: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit complete semantic inference: %w", err)
	}
	return nil
}

// DeliverSemanticProfileChanges advances ONE currently-unacknowledged
// head-change outbox row by up to batchSize matching Situations per
// spec.md's "paginated, 100 Situations/transaction" — every nonterminal
// (active|recovery_pending) Situation with a member delivery under the
// change's own signature that has not yet received this exact
// (change_id, situation_id) delivery. Each newly-woken Situation gets the
// existing DueSemanticProfileChanged reason merged and its
// next_assessment_at pulled forward, mirroring
// wakeOneDependencyRecoveredSituationTx's own lightweight wake pattern — no
// input_version bump, no parked-state reset: a profile change is advisory
// guidance, never a material policy change. The outbox row is acknowledged
// only once a page returns fewer than batchSize matches (this page reached
// every remaining match). A concurrent attachment under the same signature
// that lands on either side of the cursor is never lost: an unmatched
// Situation still loads the current head at its own next reconcile
// (spec.md: "must either be included or load the new head itself"). Returns
// the number of Situations woken this call — 0 when no change is currently
// due for another page.
func (s *Store) DeliverSemanticProfileChanges(ctx context.Context, now time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 100
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin deliver semantic profile changes: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var changeID, signatureKey string
	var cursor sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT id, signature_key, fan_out_cursor FROM semantic_profile_changes
		WHERE acknowledged = 0 ORDER BY id ASC LIMIT 1`).Scan(&changeID, &signatureKey, &cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: query due semantic profile change: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT s.id
		FROM delivery_semantic_signatures dss
		JOIN alert_deliveries ad ON ad.id = dss.delivery_id
		JOIN incident_alert_deliveries iad ON iad.delivery_id = ad.id
		JOIN situation_incidents si ON si.incident_id = iad.incident_id
		JOIN situations s ON s.id = si.situation_id
		LEFT JOIN semantic_profile_change_deliveries scd ON scd.change_id = ? AND scd.situation_id = s.id
		WHERE dss.signature_key = ? AND s.lifecycle IN ('active', 'recovery_pending')
		  AND scd.situation_id IS NULL AND (? IS NULL OR s.id > ?)
		ORDER BY s.id ASC LIMIT ?`,
		changeID, signatureKey, cursor, cursor, batchSize)
	if err != nil {
		return 0, fmt.Errorf("store: query semantic profile change fan-out page: %w", err)
	}
	ids, err := scanStringRows(rows)
	if err != nil {
		return 0, fmt.Errorf("store: read semantic profile change fan-out page: %w", err)
	}

	for _, situationID := range ids {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO semantic_profile_change_deliveries (change_id, situation_id, delivered_at)
			VALUES (?, ?, ?)`, changeID, situationID, canonicalTime(now)); err != nil {
			return 0, fmt.Errorf("store: record semantic profile change delivery: %w", err)
		}
		if err := mergeSituationDueReasonTx(ctx, tx, situationID, situationmodel.DueSemanticProfileChanged, now); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE situations SET next_assessment_at = min(next_assessment_at, ?), updated_at = ? WHERE id = ?`,
			canonicalTime(now), canonicalTime(now), situationID); err != nil {
			return 0, fmt.Errorf("store: pull semantic profile change wake forward: %w", err)
		}
	}

	if len(ids) > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE semantic_profile_changes SET fan_out_cursor = ? WHERE id = ?`, ids[len(ids)-1], changeID); err != nil {
			return 0, fmt.Errorf("store: advance semantic profile change fan-out cursor: %w", err)
		}
	}
	if len(ids) < batchSize {
		if _, err := tx.ExecContext(ctx, `
			UPDATE semantic_profile_changes SET acknowledged = 1 WHERE id = ?`, changeID); err != nil {
			return 0, fmt.Errorf("store: acknowledge exhausted semantic profile change: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit deliver semantic profile changes: %w", err)
	}
	return len(ids), nil
}

// commitAcceptedInferenceTx creates the accepted inference's immutable
// Version, advances the signature's head, and enqueues its change-outbox
// row — the SAME three writes CorrectSemanticProfile makes for a
// correction, since both are "a new head advancement" (spec.md: "Head
// advancement and a profile-change outbox row commit together").
func commitAcceptedInferenceTx(ctx context.Context, tx *sql.Tx, jobID, signatureKey string, profile profilemodel.Profile, result profilemodel.InferenceResult, now time.Time) error {
	var currentVersion int
	err := tx.QueryRowContext(ctx, `SELECT current_version FROM semantic_profile_heads WHERE signature_key = ?`, signatureKey).Scan(&currentVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: read current semantic profile head for inference: %w", err)
	}
	newVersion := currentVersion + 1

	var frozenInputDigest string
	if err := tx.QueryRowContext(ctx, `SELECT frozen_input_digest FROM semantic_profile_inference_jobs WHERE id = ?`, jobID).Scan(&frozenInputDigest); err != nil {
		return fmt.Errorf("store: read frozen input digest for inference job %s: %w", jobID, err)
	}

	profileJSON, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("store: marshal inferred profile: %w", err)
	}
	versionID := uuid.NewString()
	createdAt := canonicalTime(now)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_versions (
			id, signature_key, version, schema_version, prompt_version, semantic_input_digest,
			origin, provider, model, usage_input_tokens, usage_output_tokens, profile_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, 'inferred', ?, ?, ?, ?, ?, ?)`,
		versionID, signatureKey, newVersion, profilemodel.ProfileSchemaVersion, result.PromptVersion, frozenInputDigest,
		result.Provider, result.Model, result.UsageInputTokens, result.UsageOutputTokens, string(profileJSON), createdAt); err != nil {
		return fmt.Errorf("store: insert inferred semantic profile version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_heads (signature_key, current_version, version_id, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(signature_key) DO UPDATE SET current_version = excluded.current_version,
			version_id = excluded.version_id, updated_at = excluded.updated_at`,
		signatureKey, newVersion, versionID, createdAt); err != nil {
		return fmt.Errorf("store: advance semantic profile head for inference: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO semantic_profile_changes (id, signature_key, version_id, created_at)
		VALUES (?, ?, ?, ?)`, uuid.NewString(), signatureKey, versionID, createdAt); err != nil {
		return fmt.Errorf("store: enqueue semantic profile change for inference: %w", err)
	}
	return nil
}
