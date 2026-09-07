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
	"strconv"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// Task 2: Persist frozen cycles, request reservations, runs, and cursors.
// See spec.md "Preparation cycles, request accounting, and reuse" and
// "Observation history retention" (ADR-0051).
// ----------------------------------------------------------------------

const observationDetailRetention = 10 * 24 * time.Hour

// investigationCreditCostPerRequest is the fixed cost (spec.md "each
// optional physical reservation spends three units") one optional physical
// reservation debits from a Situation's durable investigation credit.
const investigationCreditCostPerRequest = 3

// verifyFenceTx confirms f's (situation id, lease owner, claim token, input
// version) still matches the Situation's current row — the observation-
// package counterpart of verifyClaimTx, operating on the narrow Fence shape
// instead of a full situation.Claim (internal/observation/model imports
// nothing but the standard library, so it cannot depend on internal/
// situation's Claim type).
func verifyFenceTx(ctx context.Context, tx *sql.Tx, f observationmodel.Fence) error {
	var inputVersion int
	err := tx.QueryRowContext(ctx, `
		SELECT input_version FROM situations WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		f.SituationID, f.Owner, f.Token).Scan(&inputVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return situationmodel.ErrSituationLeaseLost
	}
	if err != nil {
		return fmt.Errorf("store: verify observation fence: %w", err)
	}
	if inputVersion != f.InputVersion {
		return ErrSituationVersionConflict
	}
	return nil
}

// deterministicCycleID derives a stable, reproducible cycle identity from
// its natural key — no UUID, matching the same content-addressing spirit
// CanonicalPlanID uses for plans (spec.md never requires this specifically
// for cycles, but a retry always looks up this exact row by its natural
// key regardless, so a deterministic id costs nothing and makes fixtures
// reproducible).
func deterministicCycleID(situationID string, inputVersion int, generation int64) string {
	sum := sha256.Sum256([]byte(situationID + "|" + strconv.Itoa(inputVersion) + "|" + strconv.FormatInt(generation, 10)))
	return "cycle:sha256:" + hex.EncodeToString(sum[:])
}

// BeginPreparation creates or loads the one frozen preparation cycle for
// f's exact (situation_id, input_version, current preparation generation)
// key. situations.preparation_generation is "cycles already sealed for
// this Situation"; the cycle this call resolves always uses
// generation+1 — an open (unsealed) cycle at that same generation is
// returned UNCHANGED regardless of what draft the caller recomputed
// (spec.md: "Retry uses those exact values even if the wall clock ... has
// changed"). Sealing (CommitController, via sealPreparationCycleTx) is the
// only thing that ever advances the stored generation, so retries within an
// open cycle keep resolving the identical key.
func (s *Store) BeginPreparation(ctx context.Context, f observationmodel.Fence, draft observationmodel.CycleDraft, maxRequests int) (observationmodel.Cycle, error) {
	if maxRequests < 1 {
		return observationmodel.Cycle{}, errors.New("store: begin preparation requires a positive max requests")
	}
	if len(draft.Plans) > observationmodel.MaxPlansPerCycle {
		return observationmodel.Cycle{}, fmt.Errorf("store: cycle draft has %d plans, exceeds cap %d", len(draft.Plans), observationmodel.MaxPlansPerCycle)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: begin preparation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := verifyFenceTx(ctx, tx, f); err != nil {
		return observationmodel.Cycle{}, err
	}

	var storedGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT preparation_generation FROM situations WHERE id = ?`, f.SituationID).
		Scan(&storedGeneration); err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: read preparation generation: %w", err)
	}
	generation := storedGeneration + 1

	existing, found, err := loadCycleByKeyTx(ctx, tx, f.SituationID, f.InputVersion, generation)
	if err != nil {
		return observationmodel.Cycle{}, err
	}
	if found {
		if _, err := tx.ExecContext(ctx, `UPDATE situations SET current_preparation_cycle_id = ? WHERE id = ?`, existing.ID, f.SituationID); err != nil {
			return observationmodel.Cycle{}, fmt.Errorf("store: update current preparation cycle pointer: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return observationmodel.Cycle{}, fmt.Errorf("store: commit begin preparation (retry): %w", err)
		}
		return existing, nil
	}

	cycleID := deterministicCycleID(f.SituationID, f.InputVersion, generation)
	preparedPlans := make([]observationmodel.Plan, len(draft.Plans))
	for i, p := range draft.Plans {
		id, err := observationmodel.CanonicalPlanID(cycleID, p)
		if err != nil {
			return observationmodel.Cycle{}, fmt.Errorf("store: canonical plan id: %w", err)
		}
		p.ID = id
		p.CycleID = cycleID
		preparedPlans[i] = p
	}
	draft.Plans = preparedPlans

	profileVersionIDs := draft.ProfileVersionIDs
	if profileVersionIDs == nil {
		profileVersionIDs = []string{}
	}
	profileGuidance := draft.ProfileGuidance
	if profileGuidance == nil {
		profileGuidance = []observationmodel.ProfileGuidance{}
	}
	profileVersionIDsJSON, err := json.Marshal(profileVersionIDs)
	if err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: marshal profile version ids: %w", err)
	}
	profileGuidanceJSON, err := json.Marshal(profileGuidance)
	if err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: marshal profile guidance: %w", err)
	}
	allocationJSON, err := json.Marshal(draft.Allocation)
	if err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: marshal phase allocation: %w", err)
	}

	createdAt := canonicalTime(draft.Anchor)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_preparation_cycles (
			id, situation_id, input_version, generation, anchor, config_digest,
			profile_version_ids_json, profile_guidance_json, max_requests, allocation_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cycleID, f.SituationID, f.InputVersion, generation, createdAt, draft.ConfigDigest,
		string(profileVersionIDsJSON), string(profileGuidanceJSON), maxRequests, string(allocationJSON), createdAt); err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: insert preparation cycle: %w", err)
	}

	for _, p := range draft.Plans {
		if err := insertObservationPlanTx(ctx, tx, cycleID, p, createdAt); err != nil {
			return observationmodel.Cycle{}, err
		}
	}

	// A genuinely new cycle supersedes any still-live current/open-cycle
	// reference this Situation's PREVIOUS cycle held — transferring
	// current-cycle protection forward, per spec.md "Transfer temporary
	// current-cycle protection atomically."
	if _, err := tx.ExecContext(ctx, `
		UPDATE situation_observation_references SET superseded = 1
		WHERE superseded = 0 AND reference_kind IN ('current_cycle','open_cycle')
		  AND run_id IN (
		      SELECT r.id FROM situation_observation_runs r
		      JOIN situation_preparation_cycles c ON c.id = r.cycle_id
		      WHERE c.situation_id = ? AND c.id != ?
		  )`, f.SituationID, cycleID); err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: supersede prior cycle references: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE situations SET current_preparation_cycle_id = ? WHERE id = ?`, cycleID, f.SituationID); err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: update current preparation cycle pointer: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return observationmodel.Cycle{}, fmt.Errorf("store: commit begin preparation: %w", err)
	}

	return observationmodel.Cycle{
		ID:          cycleID,
		Fence:       f,
		Generation:  generation,
		Draft:       draft,
		MaxRequests: maxRequests,
		Sealed:      false,
	}, nil
}

func insertObservationPlanTx(ctx context.Context, tx *sql.Tx, cycleID string, p observationmodel.Plan, createdAt string) error {
	scopeJSON, err := json.Marshal(p.Scope)
	if err != nil {
		return fmt.Errorf("store: marshal plan scope: %w", err)
	}
	params := p.Parameters
	if len(params) == 0 {
		params = json.RawMessage("null")
	}
	reconsiderOn := p.ReconsiderOn
	if reconsiderOn == nil {
		reconsiderOn = []string{}
	}
	stopOn := p.StopOn
	if stopOn == nil {
		stopOn = []string{}
	}
	reconsiderJSON, err := json.Marshal(reconsiderOn)
	if err != nil {
		return fmt.Errorf("store: marshal plan reconsider_on: %w", err)
	}
	stopOnJSON, err := json.Marshal(stopOn)
	if err != nil {
		return fmt.Errorf("store: marshal plan stop_on: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO situation_observation_plans (
			id, cycle_id, capability, phase, scope_json, parameters_json,
			start_at, end_at, eligible_at, limit_count, max_requests, purpose,
			reconsider_on_json, stop_on_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, cycleID, string(p.Capability), string(p.Phase), string(scopeJSON), string(params),
		canonicalTime(p.Start), canonicalTime(p.End), canonicalTime(p.EligibleAt),
		p.Limit, p.MaxRequests, p.Purpose, string(reconsiderJSON), string(stopOnJSON), createdAt)
	if err != nil {
		return fmt.Errorf("store: insert observation plan: %w", err)
	}
	return nil
}

// loadCycleByKeyTx loads the cycle at the exact (situation_id, input_version,
// generation) key, including its full plan set, or found=false if none
// exists yet.
func loadCycleByKeyTx(ctx context.Context, tx *sql.Tx, situationID string, inputVersion int, generation int64) (observationmodel.Cycle, bool, error) {
	var (
		cycleID, anchor, configDigest              string
		profileVersionIDsJSON, profileGuidanceJSON string
		maxRequests                                int
		allocationJSON                             string
		sealed                                     int
		owner                                      string
		token                                      int64
	)
	row := tx.QueryRowContext(ctx, `
		SELECT c.id, c.anchor, c.config_digest, c.profile_version_ids_json, c.profile_guidance_json,
		       c.max_requests, c.allocation_json, c.sealed, s.lease_owner, s.claim_token
		FROM situation_preparation_cycles c
		JOIN situations s ON s.id = c.situation_id
		WHERE c.situation_id = ? AND c.input_version = ? AND c.generation = ?`,
		situationID, inputVersion, generation)
	var leaseOwner sql.NullString
	if err := row.Scan(&cycleID, &anchor, &configDigest, &profileVersionIDsJSON, &profileGuidanceJSON,
		&maxRequests, &allocationJSON, &sealed, &leaseOwner, &token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return observationmodel.Cycle{}, false, nil
		}
		return observationmodel.Cycle{}, false, fmt.Errorf("store: load preparation cycle: %w", err)
	}
	if leaseOwner.Valid {
		owner = leaseOwner.String
	}

	anchorTime, err := time.Parse(time.RFC3339Nano, anchor)
	if err != nil {
		return observationmodel.Cycle{}, false, fmt.Errorf("store: parse cycle anchor: %w", err)
	}
	var profileVersionIDs []string
	if err := json.Unmarshal([]byte(profileVersionIDsJSON), &profileVersionIDs); err != nil {
		return observationmodel.Cycle{}, false, fmt.Errorf("store: unmarshal profile version ids: %w", err)
	}
	var profileGuidance []observationmodel.ProfileGuidance
	if err := json.Unmarshal([]byte(profileGuidanceJSON), &profileGuidance); err != nil {
		return observationmodel.Cycle{}, false, fmt.Errorf("store: unmarshal profile guidance: %w", err)
	}
	var allocation observationmodel.PhaseAllocation
	if err := json.Unmarshal([]byte(allocationJSON), &allocation); err != nil {
		return observationmodel.Cycle{}, false, fmt.Errorf("store: unmarshal phase allocation: %w", err)
	}

	plans, err := loadObservationPlansTx(ctx, tx, cycleID)
	if err != nil {
		return observationmodel.Cycle{}, false, err
	}

	return observationmodel.Cycle{
		ID:         cycleID,
		Fence:      observationmodel.Fence{SituationID: situationID, InputVersion: inputVersion, Owner: owner, Token: token},
		Generation: generation,
		Draft: observationmodel.CycleDraft{
			Anchor: anchorTime, ConfigDigest: configDigest,
			ProfileVersionIDs: profileVersionIDs, ProfileGuidance: profileGuidance,
			Plans: plans, Allocation: allocation,
		},
		MaxRequests: maxRequests,
		Sealed:      sealed == 1,
	}, true, nil
}

func loadObservationPlansTx(ctx context.Context, tx *sql.Tx, cycleID string) ([]observationmodel.Plan, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, capability, phase, scope_json, parameters_json, start_at, end_at, eligible_at,
		       limit_count, max_requests, purpose, reconsider_on_json, stop_on_json
		FROM situation_observation_plans WHERE cycle_id = ? ORDER BY id`, cycleID)
	if err != nil {
		return nil, fmt.Errorf("store: query observation plans: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var plans []observationmodel.Plan
	for rows.Next() {
		var (
			id, capability, phase, scopeJSON, paramsJSON string
			startAt, endAt, eligibleAt                   string
			limitCount, maxRequests                      int
			purpose, reconsiderJSON, stopOnJSON          string
		)
		if err := rows.Scan(&id, &capability, &phase, &scopeJSON, &paramsJSON, &startAt, &endAt, &eligibleAt,
			&limitCount, &maxRequests, &purpose, &reconsiderJSON, &stopOnJSON); err != nil {
			return nil, fmt.Errorf("store: scan observation plan: %w", err)
		}
		var scope observationmodel.Scope
		if err := json.Unmarshal([]byte(scopeJSON), &scope); err != nil {
			return nil, fmt.Errorf("store: unmarshal plan scope: %w", err)
		}
		var reconsiderOn, stopOn []string
		if err := json.Unmarshal([]byte(reconsiderJSON), &reconsiderOn); err != nil {
			return nil, fmt.Errorf("store: unmarshal plan reconsider_on: %w", err)
		}
		if err := json.Unmarshal([]byte(stopOnJSON), &stopOn); err != nil {
			return nil, fmt.Errorf("store: unmarshal plan stop_on: %w", err)
		}
		start, err := time.Parse(time.RFC3339Nano, startAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse plan start: %w", err)
		}
		end, err := time.Parse(time.RFC3339Nano, endAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse plan end: %w", err)
		}
		eligible, err := time.Parse(time.RFC3339Nano, eligibleAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse plan eligible_at: %w", err)
		}
		plans = append(plans, observationmodel.Plan{
			ID: id, CycleID: cycleID, Capability: observationmodel.Capability(capability),
			Phase: observationmodel.Phase(phase), Scope: scope, Parameters: json.RawMessage(paramsJSON),
			Start: start, End: end, EligibleAt: eligible, Limit: limitCount, MaxRequests: maxRequests,
			Purpose: purpose, ReconsiderOn: reconsiderOn, StopOn: stopOn,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate observation plans: %w", err)
	}
	return plans, nil
}

// ReserveObservationRequest durably reserves exactly one physical request
// slot for planID within cycleID, enforcing both the cycle-wide and the
// plan-own MaxRequests caps, and — when planID is the cycle's protected
// optional plan — debiting the Situation's durable investigation credit.
// ordinal is a per-cycle monotonic counter shared across every plan, which
// trivially also satisfies plan-scoped uniqueness.
func (s *Store) ReserveObservationRequest(ctx context.Context, f observationmodel.Fence, cycleID, planID string, now time.Time) (observationmodel.RequestReservation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: begin reserve observation request: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := verifyFenceTx(ctx, tx, f); err != nil {
		return observationmodel.RequestReservation{}, err
	}

	var cycleSituationID, allocationJSON string
	var cycleMaxRequests, sealed int
	if err := tx.QueryRowContext(ctx, `SELECT situation_id, max_requests, allocation_json, sealed FROM situation_preparation_cycles WHERE id = ?`, cycleID).
		Scan(&cycleSituationID, &cycleMaxRequests, &allocationJSON, &sealed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return observationmodel.RequestReservation{}, fmt.Errorf("store: unknown cycle %q", cycleID)
		}
		return observationmodel.RequestReservation{}, fmt.Errorf("store: load cycle for reservation: %w", err)
	}
	if cycleSituationID != f.SituationID {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: cycle %q does not belong to situation %q", cycleID, f.SituationID)
	}
	if sealed == 1 {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: cycle %q is already sealed", cycleID)
	}

	var planMaxRequests int
	if err := tx.QueryRowContext(ctx, `SELECT max_requests FROM situation_observation_plans WHERE id = ? AND cycle_id = ?`, planID, cycleID).
		Scan(&planMaxRequests); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return observationmodel.RequestReservation{}, fmt.Errorf("store: unknown plan %q in cycle %q", planID, cycleID)
		}
		return observationmodel.RequestReservation{}, fmt.Errorf("store: load plan for reservation: %w", err)
	}

	var cycleCount, planCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_requests WHERE cycle_id = ?`, cycleID).Scan(&cycleCount); err != nil {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: count cycle reservations: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM situation_observation_requests WHERE plan_id = ?`, planID).Scan(&planCount); err != nil {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: count plan reservations: %w", err)
	}
	if cycleCount >= cycleMaxRequests || planCount >= planMaxRequests {
		return observationmodel.RequestReservation{}, observationmodel.ErrBudgetExhausted
	}

	var allocation observationmodel.PhaseAllocation
	if err := json.Unmarshal([]byte(allocationJSON), &allocation); err != nil {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: unmarshal allocation: %w", err)
	}
	if allocation.OptionalPlanID != "" && allocation.OptionalPlanID == planID {
		var credit int
		if err := tx.QueryRowContext(ctx, `SELECT investigation_credit FROM situations WHERE id = ?`, f.SituationID).Scan(&credit); err != nil {
			return observationmodel.RequestReservation{}, fmt.Errorf("store: read investigation credit: %w", err)
		}
		if credit < investigationCreditCostPerRequest {
			return observationmodel.RequestReservation{}, observationmodel.ErrBudgetExhausted
		}
		if _, err := tx.ExecContext(ctx, `UPDATE situations SET investigation_credit = investigation_credit - ? WHERE id = ?`,
			investigationCreditCostPerRequest, f.SituationID); err != nil {
			return observationmodel.RequestReservation{}, fmt.Errorf("store: debit investigation credit: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE situation_preparation_cycles SET optional_credit_spent = optional_credit_spent + ? WHERE id = ?`,
			investigationCreditCostPerRequest, cycleID); err != nil {
			return observationmodel.RequestReservation{}, fmt.Errorf("store: record optional credit spend: %w", err)
		}
	}

	ordinal := cycleCount + 1
	id := fmt.Sprintf("request:%s:%d", cycleID, ordinal)
	reservedAt := canonicalTime(now)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_observation_requests (id, cycle_id, plan_id, ordinal, reserved_at) VALUES (?, ?, ?, ?, ?)`,
		id, cycleID, planID, ordinal, reservedAt); err != nil {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: insert observation request reservation: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return observationmodel.RequestReservation{}, fmt.Errorf("store: commit reserve observation request: %w", err)
	}
	return observationmodel.RequestReservation{ID: id, CycleID: cycleID, PlanID: planID, Ordinal: ordinal, ReservedAt: now.UTC()}, nil
}

// CompleteObservationRequest finishes one reservation with its closed
// outcome. It carries no Fence: a reservation's identity is already
// immutable, and its outcome must be recordable even after the owning
// Situation's claim is lost, to account for work that really happened
// (spec.md: "Request outcomes may append after the Situation claim is
// lost ... Such outcomes never make stale facts current"). Repeating an
// identical outcome for the same reservation is a no-op; differing content
// is a replay conflict.
func (s *Store) CompleteObservationRequest(ctx context.Context, outcome observationmodel.RequestOutcome) error {
	if outcome.ReservationID == "" || outcome.Code == "" {
		return errors.New("store: complete observation request requires a reservation id and code")
	}
	switch outcome.RequestStarted {
	case observationmodel.RequestStartedTrue, observationmodel.RequestStartedFalse, observationmodel.RequestStartedUnknown:
	default:
		return fmt.Errorf("store: unknown request_started %q", outcome.RequestStarted)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin complete observation request: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM situation_observation_requests WHERE id = ?`, outcome.ReservationID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: unknown observation reservation %q", outcome.ReservationID)
		}
		return fmt.Errorf("store: verify observation reservation: %w", err)
	}

	var existingStarted, existingCode string
	err = tx.QueryRowContext(ctx, `SELECT request_started, code FROM situation_observation_request_outcomes WHERE reservation_id = ?`,
		outcome.ReservationID).Scan(&existingStarted, &existingCode)
	switch {
	case err == nil:
		if existingStarted == outcome.RequestStarted && existingCode == outcome.Code {
			return tx.Commit()
		}
		return observationmodel.ErrConflictingReplay
	case errors.Is(err, sql.ErrNoRows):
		// fall through to insert
	default:
		return fmt.Errorf("store: load existing observation request outcome: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_observation_request_outcomes (reservation_id, request_started, code, completed_at)
		VALUES (?, ?, ?, ?)`,
		outcome.ReservationID, outcome.RequestStarted, outcome.Code, canonicalTime(outcome.CompletedAt)); err != nil {
		return fmt.Errorf("store: insert observation request outcome: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit complete observation request: %w", err)
	}
	return nil
}

// CommitObservationRun persists one completed plan execution — its
// normalized facts and payloads — under fence f. now is this store's own
// durable completion clock, stamped onto Run.CompletedAt on first commit
// only (a documented, deliberate deviation from plan.md's literal
// Cross-Task Contracts signature, made for the same reason controller.go
// already documents for AssessmentCall/AssessmentAttempt: every other
// mutating store method in this codebase takes an explicit `now` for
// determinism/testability — CommitObservationRun's own doc comment calling
// CompletedAt "the store's own durable completion clock" only makes sense
// if the store receives that clock value, never calling time.Now()
// internally). Repeating an identical run under the same ID is a no-op
// success; differing content under the same ID is ErrConflictingReplay.
func (s *Store) CommitObservationRun(ctx context.Context, f observationmodel.Fence, run observationmodel.Run, now time.Time) error {
	if err := observationmodel.ValidateRun(run); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin commit observation run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := verifyFenceTx(ctx, tx, f); err != nil {
		return err
	}

	var cycleSituationID string
	var sealed int
	if err := tx.QueryRowContext(ctx, `SELECT situation_id, sealed FROM situation_preparation_cycles WHERE id = ?`, run.CycleID).
		Scan(&cycleSituationID, &sealed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: unknown cycle %q", run.CycleID)
		}
		return fmt.Errorf("store: load cycle for run commit: %w", err)
	}
	if cycleSituationID != f.SituationID {
		return fmt.Errorf("store: cycle %q does not belong to situation %q", run.CycleID, f.SituationID)
	}

	existingCanonical, found, err := loadRunCanonicalTx(ctx, tx, run.ID)
	if err != nil {
		return err
	}
	newCanonical, err := canonicalRunPayload(run)
	if err != nil {
		return err
	}
	if found {
		if existingCanonical == newCanonical {
			return tx.Commit()
		}
		return observationmodel.ErrConflictingReplay
	}

	completedAt := canonicalTime(now)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_observation_runs (
			id, cycle_id, plan_id, status, coverage_start, coverage_end, coverage_complete,
			coverage_returned, coverage_omitted, limitation_codes_json, observed_at, expires_at,
			completed_at, reused_from_run_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.CycleID, run.PlanID, string(run.Status),
		canonicalTime(run.Coverage.Start), canonicalTime(run.Coverage.End), boolToInt(run.Coverage.Complete),
		run.Coverage.Returned, run.Coverage.Omitted, limitationCodesJSON(run.LimitationCodes),
		canonicalTime(run.ObservedAt), canonicalTime(run.ExpiresAt), completedAt, nullableString(run.ReusedFromRunID)); err != nil {
		return fmt.Errorf("store: insert observation run: %w", err)
	}

	for _, fact := range run.Facts {
		if err := insertObservationFactTx(ctx, tx, run.ID, fact); err != nil {
			return err
		}
	}

	refID := "ref:open_cycle:" + run.ID
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_observation_references (id, run_id, reference_kind, owner_id, permanent, created_at)
		VALUES (?, ?, 'open_cycle', ?, 0, ?)`, refID, run.ID, run.CycleID, completedAt); err != nil {
		return fmt.Errorf("store: insert open-cycle reference: %w", err)
	}
	if run.ReusedFromRunID != nil {
		reuseRefID := "ref:current_cycle:" + run.CycleID + ":" + *run.ReusedFromRunID
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO situation_observation_references (id, run_id, reference_kind, owner_id, permanent, created_at)
			VALUES (?, ?, 'current_cycle', ?, 0, ?)`, reuseRefID, *run.ReusedFromRunID, run.CycleID, completedAt); err != nil {
			return fmt.Errorf("store: insert reused-run current-cycle reference: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit observation run: %w", err)
	}
	return nil
}

func limitationCodesJSON(codes []string) string {
	if codes == nil {
		codes = []string{}
	}
	b, err := json.Marshal(codes)
	if err != nil {
		// codes is always a []string of plain identifiers; Marshal cannot
		// fail for that shape.
		panic(fmt.Sprintf("store: marshal limitation codes: %v", err))
	}
	return string(b)
}

// canonicalRunFactPayload is CommitObservationRun's replay-comparison shape
// for one fact: exactly the fields a differing replay must match on.
type canonicalRunFactPayload struct {
	ID            string                        `json:"id"`
	Kind          string                        `json:"kind"`
	Subject       string                        `json:"subject"`
	Digest        string                        `json:"digest"`
	SchemaVersion int                           `json:"schema_version"`
	Value         json.RawMessage               `json:"value"`
	ResultStatus  observationmodel.ResultStatus `json:"result_status"`
	Freshness     observationmodel.Freshness    `json:"freshness"`
	Material      bool                          `json:"material"`
}

type canonicalRunPayloadShape struct {
	PlanID          string                        `json:"plan_id"`
	Status          observationmodel.ResultStatus `json:"status"`
	CoverageStart   string                        `json:"coverage_start"`
	CoverageEnd     string                        `json:"coverage_end"`
	Complete        bool                          `json:"complete"`
	Returned        int                           `json:"returned"`
	Omitted         int                           `json:"omitted"`
	LimitationCodes []string                      `json:"limitation_codes"`
	Facts           []canonicalRunFactPayload     `json:"facts"`
}

// canonicalRunPayload builds run's replay-comparison digest — everything an
// identical retry must reproduce byte-for-byte, and nothing a legitimate
// replay is allowed to vary (collection generation/reservation counts and
// ObservedAt/ExpiresAt are deliberately excluded, matching MaterialDigest's
// own exclusions).
func canonicalRunPayload(run observationmodel.Run) (string, error) {
	codes := run.LimitationCodes
	if codes == nil {
		codes = []string{}
	}
	facts := make([]canonicalRunFactPayload, len(run.Facts))
	for i, f := range run.Facts {
		facts[i] = canonicalRunFactPayload{
			ID: f.ID, Kind: f.Kind, Subject: f.Subject, Digest: f.Digest,
			SchemaVersion: f.SchemaVersion, Value: f.Value, ResultStatus: f.ResultStatus,
			Freshness: f.Freshness, Material: f.Material,
		}
	}
	shape := canonicalRunPayloadShape{
		PlanID: run.PlanID, Status: run.Status,
		CoverageStart: canonicalTime(run.Coverage.Start), CoverageEnd: canonicalTime(run.Coverage.End),
		Complete: run.Coverage.Complete, Returned: run.Coverage.Returned, Omitted: run.Coverage.Omitted,
		LimitationCodes: codes, Facts: facts,
	}
	b, err := json.Marshal(shape)
	if err != nil {
		return "", fmt.Errorf("store: marshal canonical run payload: %w", err)
	}
	return string(b), nil
}

func loadRunCanonicalTx(ctx context.Context, tx *sql.Tx, runID string) (string, bool, error) {
	var (
		planID, status, coverageStart, coverageEnd, limitationCodes string
		complete                                                    int
		returned, omitted                                           int
	)
	err := tx.QueryRowContext(ctx, `
		SELECT plan_id, status, coverage_start, coverage_end, coverage_complete, coverage_returned, coverage_omitted, limitation_codes_json
		FROM situation_observation_runs WHERE id = ?`, runID).
		Scan(&planID, &status, &coverageStart, &coverageEnd, &complete, &returned, &omitted, &limitationCodes)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: load existing observation run: %w", err)
	}
	var codes []string
	if err := json.Unmarshal([]byte(limitationCodes), &codes); err != nil {
		return "", false, fmt.Errorf("store: unmarshal existing limitation codes: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, kind, subject, digest, schema_version, result_status, freshness, material,
		       COALESCE((SELECT value_json FROM situation_observation_fact_payloads WHERE fact_id = f.id), 'null')
		FROM situation_observation_facts f WHERE run_id = ? ORDER BY id`, runID)
	if err != nil {
		return "", false, fmt.Errorf("store: query existing observation facts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var facts []canonicalRunFactPayload
	for rows.Next() {
		var (
			id, kind, subject, digest, resultStatus, freshness, valueJSON string
			schemaVersion                                                 int
			material                                                      int
		)
		if err := rows.Scan(&id, &kind, &subject, &digest, &schemaVersion, &resultStatus, &freshness, &material, &valueJSON); err != nil {
			return "", false, fmt.Errorf("store: scan existing observation fact: %w", err)
		}
		facts = append(facts, canonicalRunFactPayload{
			ID: id, Kind: kind, Subject: subject, Digest: digest, SchemaVersion: schemaVersion,
			Value: json.RawMessage(valueJSON), ResultStatus: observationmodel.ResultStatus(resultStatus),
			Freshness: observationmodel.Freshness(freshness), Material: material == 1,
		})
	}
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("store: iterate existing observation facts: %w", err)
	}

	shape := canonicalRunPayloadShape{
		PlanID: planID, Status: observationmodel.ResultStatus(status),
		CoverageStart: coverageStart, CoverageEnd: coverageEnd, Complete: complete == 1,
		Returned: returned, Omitted: omitted, LimitationCodes: codes, Facts: facts,
	}
	b, err := json.Marshal(shape)
	if err != nil {
		return "", false, fmt.Errorf("store: marshal existing canonical run payload: %w", err)
	}
	return string(b), true, nil
}

func insertObservationFactTx(ctx context.Context, tx *sql.Tx, runID string, f observationmodel.Fact) error {
	refs := f.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		return fmt.Errorf("store: marshal fact evidence refs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_observation_facts (
			id, run_id, kind, subject, digest, schema_version, result_status, freshness,
			observed_at, expires_at, evidence_refs_json, material
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, runID, f.Kind, f.Subject, f.Digest, f.SchemaVersion, string(f.ResultStatus), string(f.Freshness),
		canonicalTime(f.ObservedAt), canonicalTime(f.ExpiresAt), string(refsJSON), boolToInt(f.Material)); err != nil {
		return fmt.Errorf("store: insert observation fact: %w", err)
	}
	value := f.Value
	if len(value) == 0 {
		value = json.RawMessage("null")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO situation_observation_fact_payloads (fact_id, value_json) VALUES (?, ?)`, f.ID, string(value)); err != nil {
		return fmt.Errorf("store: insert observation fact payload: %w", err)
	}
	return nil
}

// HasObservationRun reports whether planID already has a committed run —
// the Runner's (internal/observation) own check for "each phase reuses
// completed runs and executes only missing ones" (spec.md "Two preparation
// phases"), so a retry never re-dispatches a physical request for a plan
// whose run already committed.
func (s *Store) HasObservationRun(ctx context.Context, planID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM situation_observation_runs WHERE plan_id = ?`, planID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: check existing observation run: %w", err)
	}
	return true, nil
}

// ListObservationRuns returns a bounded, cursor-paginated page of runs for
// situationID (optionally filtered to one cycleID), ordered by completion
// time then ID for stable pagination. limit is clamped to [1,100],
// defaulting to 20. Facts under an expired run are omitted; DetailState
// reports "expired" in that case.
func (s *Store) ListObservationRuns(ctx context.Context, situationID, cycleID, cursor string, limit int) ([]observationmodel.RunRecord, string, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	var cursorCompletedAt, cursorID string
	if cursor != "" {
		parts, err := decodeRunCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		cursorCompletedAt, cursorID = parts[0], parts[1]
	}

	args := []any{situationID}
	query := `
		SELECT r.id, r.cycle_id, r.plan_id, r.status, r.coverage_start, r.coverage_end, r.coverage_complete,
		       r.coverage_returned, r.coverage_omitted, r.limitation_codes_json, r.observed_at, r.expires_at,
		       r.completed_at, r.reused_from_run_id,
		       e.expired_at
		FROM situation_observation_runs r
		JOIN situation_preparation_cycles c ON c.id = r.cycle_id
		LEFT JOIN situation_observation_detail_expirations e ON e.run_id = r.id
		WHERE c.situation_id = ?`
	if cycleID != "" {
		query += ` AND r.cycle_id = ?`
		args = append(args, cycleID)
	}
	if cursor != "" {
		query += ` AND (r.completed_at, r.id) > (?, ?)`
		args = append(args, cursorCompletedAt, cursorID)
	}
	query += ` ORDER BY r.completed_at ASC, r.id ASC LIMIT ?`
	args = append(args, limit+1)

	// Fully drain and close this query before issuing any further query
	// (buildRunRecord's own loadFactsForRun call below) — the store's
	// connection pool is capped at one open connection (SetMaxOpenConns(1)),
	// so a nested query while this rows cursor is still open would
	// self-deadlock waiting for a connection this same goroutine is holding.
	type rawRun struct {
		id, cycleID, planID, status, coverageStart, coverageEnd, limitationCodes string
		complete, returned, omitted                                              int
		observedAt, expiresAt, completedAt                                       string
		reusedFrom, expiredAt                                                    sql.NullString
	}
	var raws []rawRun
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("store: query observation runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r rawRun
		if err := rows.Scan(&r.id, &r.cycleID, &r.planID, &r.status, &r.coverageStart, &r.coverageEnd, &r.complete,
			&r.returned, &r.omitted, &r.limitationCodes, &r.observedAt, &r.expiresAt, &r.completedAt, &r.reusedFrom, &r.expiredAt); err != nil {
			return nil, "", fmt.Errorf("store: scan observation run: %w", err)
		}
		raws = append(raws, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("store: iterate observation runs: %w", err)
	}
	// Close explicitly now (the deferred Close above becomes a safe no-op)
	// so buildRunRecord's own queries below don't contend with this rows
	// cursor for the pool's single connection.
	if err := rows.Close(); err != nil {
		return nil, "", fmt.Errorf("store: close observation runs query: %w", err)
	}

	var records []observationmodel.RunRecord
	for _, r := range raws {
		record, err := buildRunRecord(ctx, s.db, r.id, r.cycleID, r.planID, r.status, r.coverageStart, r.coverageEnd,
			r.complete, r.returned, r.omitted, r.limitationCodes, r.observedAt, r.expiresAt, r.completedAt, r.reusedFrom, r.expiredAt)
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}

	nextCursor := ""
	if len(records) > limit {
		last := records[limit-1]
		nextCursor = encodeRunCursor(canonicalTime(last.Run.CompletedAt), last.Run.ID)
		records = records[:limit]
	}
	return records, nextCursor, nil
}

// dbQuerier is the subset of *sql.DB / *sql.Tx buildRunRecord/
// loadFactsForRun need. Accepting it explicitly (rather than *sql.DB
// directly) lets loadPreparedStateTx reuse these exact same queries from
// inside an ALREADY OPEN transaction — the store runs on a single pooled
// connection (SetMaxOpenConns(1)), so passing s.db there instead would wait
// forever for a connection this same goroutine's own transaction is
// holding.
type dbQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func buildRunRecord(ctx context.Context, db dbQuerier, id, cycleID, planID, status, coverageStart, coverageEnd string,
	complete, returned, omitted int, limitationCodes, observedAt, expiresAt, completedAt string,
	reusedFrom, expiredAt sql.NullString) (observationmodel.RunRecord, error) {
	var codes []string
	if err := json.Unmarshal([]byte(limitationCodes), &codes); err != nil {
		return observationmodel.RunRecord{}, fmt.Errorf("store: unmarshal run limitation codes: %w", err)
	}
	cov, err := parseCoverage(coverageStart, coverageEnd, complete, returned, omitted)
	if err != nil {
		return observationmodel.RunRecord{}, err
	}
	observed, err := time.Parse(time.RFC3339Nano, observedAt)
	if err != nil {
		return observationmodel.RunRecord{}, fmt.Errorf("store: parse run observed_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return observationmodel.RunRecord{}, fmt.Errorf("store: parse run expires_at: %w", err)
	}
	completed, err := time.Parse(time.RFC3339Nano, completedAt)
	if err != nil {
		return observationmodel.RunRecord{}, fmt.Errorf("store: parse run completed_at: %w", err)
	}
	var reusedPtr *string
	if reusedFrom.Valid {
		v := reusedFrom.String
		reusedPtr = &v
	}

	run := observationmodel.Run{
		ID: id, CycleID: cycleID, PlanID: planID, Status: observationmodel.ResultStatus(status),
		Coverage: cov, LimitationCodes: codes, ObservedAt: observed, ExpiresAt: expires,
		CompletedAt: completed, ReusedFromRunID: reusedPtr,
	}

	record := observationmodel.RunRecord{Run: run, DetailState: observationmodel.DetailStateRetained}
	if expiredAt.Valid {
		record.DetailState = observationmodel.DetailStateExpired
		t, err := time.Parse(time.RFC3339Nano, expiredAt.String)
		if err != nil {
			return observationmodel.RunRecord{}, fmt.Errorf("store: parse detail expired_at: %w", err)
		}
		record.DetailExpiredAt = &t
		return record, nil
	}

	facts, err := loadFactsForRun(ctx, db, id)
	if err != nil {
		return observationmodel.RunRecord{}, err
	}
	record.Run.Facts = facts
	return record, nil
}

func parseCoverage(start, end string, complete, returned, omitted int) (observationmodel.Coverage, error) {
	s, err := time.Parse(time.RFC3339Nano, start)
	if err != nil {
		return observationmodel.Coverage{}, fmt.Errorf("store: parse coverage start: %w", err)
	}
	e, err := time.Parse(time.RFC3339Nano, end)
	if err != nil {
		return observationmodel.Coverage{}, fmt.Errorf("store: parse coverage end: %w", err)
	}
	return observationmodel.Coverage{Start: s, End: e, Complete: complete == 1, Returned: returned, Omitted: omitted}, nil
}

func loadFactsForRun(ctx context.Context, db dbQuerier, runID string) ([]observationmodel.Fact, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT f.id, f.kind, f.subject, f.digest, f.schema_version, f.result_status, f.freshness,
		       f.observed_at, f.expires_at, f.evidence_refs_json, f.material, p.value_json
		FROM situation_observation_facts f
		JOIN situation_observation_fact_payloads p ON p.fact_id = f.id
		WHERE f.run_id = ? ORDER BY f.id`, runID)
	if err != nil {
		return nil, fmt.Errorf("store: query observation facts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var facts []observationmodel.Fact
	for rows.Next() {
		var (
			id, kind, subject, digest, resultStatus, freshness string
			schemaVersion                                      int
			observedAt, expiresAt, refsJSON, valueJSON         string
			material                                           int
		)
		if err := rows.Scan(&id, &kind, &subject, &digest, &schemaVersion, &resultStatus, &freshness,
			&observedAt, &expiresAt, &refsJSON, &material, &valueJSON); err != nil {
			return nil, fmt.Errorf("store: scan observation fact: %w", err)
		}
		var refs []string
		if err := json.Unmarshal([]byte(refsJSON), &refs); err != nil {
			return nil, fmt.Errorf("store: unmarshal fact evidence refs: %w", err)
		}
		observed, err := time.Parse(time.RFC3339Nano, observedAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse fact observed_at: %w", err)
		}
		expires, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse fact expires_at: %w", err)
		}
		facts = append(facts, observationmodel.Fact{
			ID: id, RunID: runID, Kind: kind, Subject: subject, Digest: digest, SchemaVersion: schemaVersion,
			Value: json.RawMessage(valueJSON), ResultStatus: observationmodel.ResultStatus(resultStatus),
			Freshness: observationmodel.Freshness(freshness), ObservedAt: observed, ExpiresAt: expires,
			EvidenceRefs: refs, Material: material == 1,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate observation facts: %w", err)
	}
	return facts, nil
}

func encodeRunCursor(completedAt, id string) string {
	return completedAt + "|" + id
}

func decodeRunCursor(cursor string) ([2]string, error) {
	for i := len(cursor) - 1; i >= 0; i-- {
		if cursor[i] == '|' {
			return [2]string{cursor[:i], cursor[i+1:]}, nil
		}
	}
	return [2]string{}, fmt.Errorf("store: malformed observation run cursor %q", cursor)
}

// ObservationRefreshCursor is one (subject, capability, scope) admission
// cursor's read-only projection for the planner (converted to
// observation.RefreshCursor by the runtime adapter, cmd/alertint — this
// package returns a plain transport-neutral struct rather than importing
// internal/observation, the same "store stays shape-neutral" convention
// triageAttemptStoreAdapter's own doc comment documents).
type ObservationRefreshCursor struct {
	Subject, Capability, ScopeDigest string
	NextRefreshAt                    time.Time
}

// LoadObservationRefreshCursors reads every currently-tracked refresh
// cursor for situationID — spec.md: "A separate per-subject/capability
// refresh cursor survives cycles and input versions." An empty result
// means every capability/subject pair is due (no admission has ever been
// recorded), matching BuildPlans' own "no cursor -> due" default.
func (s *Store) LoadObservationRefreshCursors(ctx context.Context, situationID string) ([]ObservationRefreshCursor, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT subject, capability, scope_digest, next_refresh_at
		FROM situation_observation_refresh WHERE situation_id = ?`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query observation refresh cursors: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ObservationRefreshCursor
	for rows.Next() {
		var c ObservationRefreshCursor
		var nextRefreshAt string
		if err := rows.Scan(&c.Subject, &c.Capability, &c.ScopeDigest, &nextRefreshAt); err != nil {
			return nil, fmt.Errorf("store: scan observation refresh cursor: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, nextRefreshAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse observation refresh cursor next_refresh_at: %w", err)
		}
		c.NextRefreshAt = t
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate observation refresh cursors: %w", err)
	}
	return out, nil
}

// RecordObservationRefreshAdmissions upserts one refresh cursor per
// distinct (subject, capability, scope) among plans, admitting a fresh
// read as of now and setting next_refresh_at to now+refreshInterval —
// spec.md: "Record admission of a fresh read with its first durable
// request reservation, not only with a successful run commit." This
// implementation's own anchor is "once this phase's plans have been
// handed to the Runner" rather than literally the first physical
// reservation inside a multi-request plan — a deliberate, documented
// simplification: both anchors equally prevent an immediate re-plan storm
// next cycle, and the plan set handed to RunPhase is exactly the same
// bounded, deduplicated set a true per-reservation hook would admit onto.
// A later admission for an already-tracked (subject, capability, scope)
// upserts in place (never a second row), always moving next_refresh_at
// forward from the call's own now.
func (s *Store) RecordObservationRefreshAdmissions(ctx context.Context, situationID, cycleID string, plans []observationmodel.Plan, refreshInterval time.Duration, now time.Time) error {
	if len(plans) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin record observation refresh admissions: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	servedAt := canonicalTime(now)
	nextRefreshAt := canonicalTime(now.Add(refreshInterval))
	seen := make(map[string]bool, len(plans))
	for _, p := range plans {
		digest, err := scopeDigest(p.Scope)
		if err != nil {
			return fmt.Errorf("store: digest observation plan scope: %w", err)
		}
		key := p.Scope.SubjectID + "|" + string(p.Capability) + "|" + digest
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO situation_observation_refresh (
				situation_id, subject, capability, scope_digest, last_served_at, next_refresh_at, admitted_cycle_id
			) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(situation_id, subject, capability, scope_digest) DO UPDATE SET
				last_served_at = excluded.last_served_at, next_refresh_at = excluded.next_refresh_at,
				admitted_cycle_id = excluded.admitted_cycle_id`,
			situationID, p.Scope.SubjectID, string(p.Capability), digest, servedAt, nextRefreshAt, cycleID); err != nil {
			return fmt.Errorf("store: upsert observation refresh cursor: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit record observation refresh admissions: %w", err)
	}
	return nil
}

// scopeDigest deterministically hashes p's Scope — json.Marshal already
// sorts map keys, so this is stable regardless of Labels' iteration order.
func scopeDigest(scope observationmodel.Scope) (string, error) {
	b, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// PruneUnusedObservationDetails deletes unused (unreferenced) fact-value
// payloads whose owning run completed at least ten days ago, in batches of
// at most 100 runs per transaction, and records an immutable expiration
// marker atomically with each deletion. It is safe to call repeatedly
// (idempotent: an already-expired run is simply skipped) and safe to
// interrupt (each batch commits independently). Returns the number of runs
// whose detail was newly expired this call.
func (s *Store) PruneUnusedObservationDetails(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	cutoff := canonicalTime(now.Add(-observationDetailRetention))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin prune observation details: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT r.id FROM situation_observation_runs r
		WHERE r.completed_at <= ?
		  AND NOT EXISTS (SELECT 1 FROM situation_observation_detail_expirations e WHERE e.run_id = r.id)
		  AND NOT EXISTS (SELECT 1 FROM situation_observation_references ref WHERE ref.run_id = r.id AND ref.superseded = 0)
		ORDER BY r.completed_at ASC, r.id ASC
		LIMIT ?`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: query prunable observation runs: %w", err)
	}
	runIDs, err := scanStringRows(rows)
	if err != nil {
		return 0, fmt.Errorf("store: read prunable observation run ids: %w", err)
	}

	expiredAt := canonicalTime(now)
	for _, runID := range runIDs {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM situation_observation_fact_payloads
			WHERE fact_id IN (SELECT id FROM situation_observation_facts WHERE run_id = ?)`, runID); err != nil {
			return 0, fmt.Errorf("store: delete expired fact payloads for run %s: %w", runID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO situation_observation_detail_expirations (run_id, expired_at) VALUES (?, ?)`, runID, expiredAt); err != nil {
			return 0, fmt.Errorf("store: record detail expiration for run %s: %w", runID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit prune observation details: %w", err)
	}
	return len(runIDs), nil
}

// AccrueInvestigationCredit adds up to cycleCap integer credit units to
// situationID's durable investigation-credit balance (spec.md: "accrue C
// integer credit units per refresh round ... cap saved credit at 3*C"),
// but only once per refreshInterval — a caller invoking this on every
// retry, on unchanged input, or for a schedule-only cycle gets no new
// credit, since the check is against the durably persisted last-accrual
// time, not trusted from the caller. It reports the resulting balance.
func (s *Store) AccrueInvestigationCredit(ctx context.Context, situationID string, now time.Time, refreshInterval time.Duration, cycleCap int) (int, error) {
	if cycleCap < 0 {
		return 0, errors.New("store: accrue investigation credit requires a non-negative cycle cap")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin accrue investigation credit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var credit int
	var accruedAt sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT investigation_credit, investigation_credit_accrued_at FROM situations WHERE id = ?`, situationID).
		Scan(&credit, &accruedAt); err != nil {
		return 0, fmt.Errorf("store: read investigation credit: %w", err)
	}

	eligible := !accruedAt.Valid
	if accruedAt.Valid {
		last, err := time.Parse(time.RFC3339Nano, accruedAt.String)
		if err != nil {
			return 0, fmt.Errorf("store: parse investigation credit accrual time: %w", err)
		}
		eligible = !now.Before(last.Add(refreshInterval))
	}
	if !eligible {
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("store: commit accrue investigation credit (no-op): %w", err)
		}
		return credit, nil
	}

	creditCap := 3 * cycleCap
	credit += cycleCap
	if credit > creditCap {
		credit = creditCap
	}
	if _, err := tx.ExecContext(ctx, `UPDATE situations SET investigation_credit = ?, investigation_credit_accrued_at = ? WHERE id = ?`,
		credit, canonicalTime(now), situationID); err != nil {
		return 0, fmt.Errorf("store: update investigation credit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit accrue investigation credit: %w", err)
	}
	return credit, nil
}

// loadPreparedStateTx reads situationID's CURRENT preparation cycle fence (the
// situations.current_preparation_cycle_id pointer BeginPreparation
// maintains) inside an already-open transaction — LoadReconciliationInput's
// own "reload" (preparation.go's own doc comment: the durable truth a
// commit reasons from, never an in-memory EvidencePreparer receipt). No
// pointer at all (a fresh Situation, or one that predates migration 0022)
// returns the zero PreparedState, matching SnapshotInput.Prepared's own
// documented "no preparer configured, or no cycle has begun yet" meaning.
//
// Runs carry a bounded latest-per-subject view across compatible cycles.
// Lifecycle decodes fresh "source_lifecycle"-kind Fact Values —
// each one a JSON array of situation.SourceObservation (the same
// one-fact-per-run-holds-an-array convention situationSummaryFact/
// findingsFact already use) — into ReduceSourceLifecycle's own input shape.
// No connector in this build writes that kind yet (Task 9 wires the real
// adapter); this decode path is exercised here by direct fixture only,
// exactly like RecoveryGraceDuration's own not-yet-reachable polling branch.
func loadPreparedStateTx(ctx context.Context, tx *sql.Tx, situationID string, now time.Time) (situation.PreparedState, error) {
	var cycleID sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT current_preparation_cycle_id FROM situations WHERE id = ?`, situationID).Scan(&cycleID)
	if errors.Is(err, sql.ErrNoRows) {
		return situation.PreparedState{}, ErrNotFound
	}
	if err != nil {
		return situation.PreparedState{}, fmt.Errorf("store: read current preparation cycle pointer: %w", err)
	}
	if !cycleID.Valid || cycleID.String == "" {
		return situation.PreparedState{}, nil
	}

	var generation int64
	var profileVersionIDsJSON, profileGuidanceJSON string
	err = tx.QueryRowContext(ctx, `
		SELECT generation, profile_version_ids_json, profile_guidance_json
		FROM situation_preparation_cycles WHERE id = ?`, cycleID.String).
		Scan(&generation, &profileVersionIDsJSON, &profileGuidanceJSON)
	if err != nil {
		// current_preparation_cycle_id references situation_preparation_cycles
		// by foreign key: a missing row here means a corrupted database, not
		// an ordinary "no cycle yet" case (already handled above).
		return situation.PreparedState{}, fmt.Errorf("store: load current preparation cycle %s: %w", cycleID.String, err)
	}
	var profileVersionIDs []string
	if err := json.Unmarshal([]byte(profileVersionIDsJSON), &profileVersionIDs); err != nil {
		return situation.PreparedState{}, fmt.Errorf("store: unmarshal profile version ids: %w", err)
	}
	var profileGuidance []observationmodel.ProfileGuidance
	if err := json.Unmarshal([]byte(profileGuidanceJSON), &profileGuidance); err != nil {
		return situation.PreparedState{}, fmt.Errorf("store: unmarshal profile guidance: %w", err)
	}

	runs, lifecycle, err := loadCurrentEvidenceTx(ctx, tx, situationID, cycleID.String, now)
	if err != nil {
		return situation.PreparedState{}, err
	}

	return situation.PreparedState{
		CycleID: cycleID.String, Generation: generation,
		Runs: runs, ProfileVersionIDs: profileVersionIDs, ProfileGuidance: profileGuidance,
		Lifecycle: lifecycle,
	}, nil
}

// sealPreparationCycleTx seals cycleID inside an already-open transaction —
// shared by every CommitController success path (plan.md: "Add sealing to
// every successful CommitController path through one shared transaction
// helper; no new commit from the preparer"). Sealing also advances the
// owning Situation's preparation_generation to the sealed cycle's own
// generation, so the next BeginPreparation call resolves generation+1.
// Sealing an already-sealed cycle, or one that does not exist, is a no-op
// (idempotent — CommitController may re-run the same commit's history
// after a crash before its own transaction committed).
func sealPreparationCycleTx(ctx context.Context, tx *sql.Tx, situationID, cycleID string, now time.Time) error {
	if cycleID == "" {
		return nil
	}
	var generation int64
	var sealed int
	err := tx.QueryRowContext(ctx, `SELECT generation, sealed FROM situation_preparation_cycles WHERE id = ? AND situation_id = ?`,
		cycleID, situationID).Scan(&generation, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: load cycle for sealing: %w", err)
	}
	if sealed == 1 {
		return nil
	}
	sealedAt := canonicalTime(now)
	if _, err := tx.ExecContext(ctx, `UPDATE situation_preparation_cycles SET sealed = 1, sealed_at = ? WHERE id = ?`,
		sealedAt, cycleID); err != nil {
		return fmt.Errorf("store: seal preparation cycle: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE situations SET preparation_generation = ? WHERE id = ? AND preparation_generation < ?`,
		generation, situationID, generation); err != nil {
		return fmt.Errorf("store: advance preparation generation: %w", err)
	}

	// A sealed cycle is no longer "open": its runs' open_cycle references
	// lift, and each becomes protected instead by a fresh current_cycle
	// reference (spec.md: "a fresh prior run reused by cadence is
	// represented by an explicit current-cycle reference"). This
	// current_cycle protection persists until BeginPreparation supersedes
	// it on behalf of a genuinely later cycle — never merely because this
	// one sealed.
	runRows, err := tx.QueryContext(ctx, `SELECT id FROM situation_observation_runs WHERE cycle_id = ?`, cycleID)
	if err != nil {
		return fmt.Errorf("store: query sealed cycle runs: %w", err)
	}
	runIDs, err := scanStringRows(runRows)
	if err != nil {
		return fmt.Errorf("store: read sealed cycle run ids: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE situation_observation_references SET superseded = 1
		WHERE reference_kind = 'open_cycle' AND owner_id = ? AND superseded = 0`, cycleID); err != nil {
		return fmt.Errorf("store: supersede open-cycle references on seal: %w", err)
	}
	for _, runID := range runIDs {
		refID := "ref:current_cycle:" + cycleID + ":" + runID
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO situation_observation_references (id, run_id, reference_kind, owner_id, permanent, created_at)
			VALUES (?, ?, 'current_cycle', ?, 0, ?)`, refID, runID, cycleID, sealedAt); err != nil {
			return fmt.Errorf("store: insert current-cycle reference for run %s: %w", runID, err)
		}
	}
	return nil
}
