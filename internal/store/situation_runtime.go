// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// SituationRuntime binds the durable store to the narrow boundaries the
// Situation runtime declares in internal/situation (Controller.Store,
// PublisherStore, InputStore, ControllerStore, NotificationStore, and
// ReconstructStore). It lives here rather than in cmd/alertint because every
// method is SQL over this package's own schema; internal/situation cannot
// hold it, since internal/store already imports internal/situation.
//
// One runtime value serves every worker: the boundaries are narrow by
// design, but they all fence against the same aggregate rows.
type SituationRuntime struct {
	st *Store
	// clientMessageID computes the deterministic Slack client_msg_id for one
	// idempotency key. It is injected because internal/notify/slack imports
	// this package, so this package cannot import it back.
	clientMessageID func(idempotencyKey string) string
	// profileSignature derives the deterministic semantic signature of one
	// delivery. Injected for the same reason (internal/semanticprofile
	// imports this package).
	profileSignature func(AlertDelivery) string
	clock            func() time.Time
	policy           SituationRuntimePolicy
	// observer receives every newly authoritative transition — including a
	// silent Situation's — after it is durably committed. It is how the
	// outward stdout Situation unit is emitted without this package knowing
	// anything about notifiers.
	observer SituationTransitionObserver
}

// SituationTransitionObserver is notified once per durably committed
// authoritative transition. It must never fail the commit: the transition is
// already durable by the time it is called, and an observability write is
// never allowed to rewrite authoritative state.
type SituationTransitionObserver interface {
	OnSituationTransition(ctx context.Context, sit model.Situation, tr model.Transition, incidentIDs []string, drill bool)
}

// SituationRuntimePolicy carries the resolved operator policy the runtime
// applies while planning outward effects. Every value is resolved from
// config by the caller; zero values are safe defaults.
type SituationRuntimePolicy struct {
	// MinSeverity is the outward main-channel poke floor.
	MinSeverity model.InterruptionPriority
	// RepageCooldownSeconds bounds how often a materially changed required
	// action may re-page.
	RepageCooldownSeconds int
	// RecurrenceMode "off" disables recurrence thread output entirely.
	RecurrenceMode string
	// HorizonTier is the installation's base advisory lifecycle horizon
	// ("minutes" | "hours" | "days" | "unknown"). Advisory L0 profiles may
	// only widen the resulting deadline, never shorten it.
	HorizonTier string
}

// NewSituationRuntime builds the runtime adapter. clientMessageID and
// profileSignature may be nil (a nil client-message function makes intent
// creation fail closed, which is correct: an intent without a deterministic
// Slack identity cannot be retried safely).
func NewSituationRuntime(st *Store, clientMessageID func(string) string, profileSignature func(AlertDelivery) string, clock func() time.Time, policy SituationRuntimePolicy) *SituationRuntime {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &SituationRuntime{st: st, clientMessageID: clientMessageID, profileSignature: profileSignature, clock: clock, policy: policy}
}

// Store exposes the underlying store for callers that also need ordinary
// read views (the MCP server, the funnel CLI).
func (r *SituationRuntime) Store() *Store { return r.st }

// SetTransitionObserver attaches the post-commit observer (nil detaches it).
func (r *SituationRuntime) SetTransitionObserver(observer SituationTransitionObserver) {
	r.observer = observer
}

// --------------------------------------------------------------------------
// situation.InputStore
// --------------------------------------------------------------------------

// ClaimSituationInputs leases pending Situation inputs for this worker.
func (r *SituationRuntime) ClaimSituationInputs(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.InputClaim, error) {
	claimed, err := r.st.ClaimSituationInputs(ctx, owner, now, lease, limit)
	if err != nil {
		return nil, err
	}
	out := make([]situation.InputClaim, 0, len(claimed))
	for _, in := range claimed {
		out = append(out, situation.InputClaim{
			ID: in.ID, IncidentID: in.IncidentID, GroupKey: in.GroupKey, Kind: in.Kind,
			ClaimOwner: in.ClaimOwner, ClaimToken: in.ClaimToken, AttemptCount: in.AttemptCount,
		})
	}
	return out, nil
}

// ApplySituationInput applies one claimed input through the store's atomic
// attach/version transaction.
func (r *SituationRuntime) ApplySituationInput(ctx context.Context, claim situation.InputClaim) error {
	_, err := r.st.ApplySituationInput(ctx, storeInputClaim(claim))
	return err
}

// RetrySituationInput releases a claimed input for a later attempt or records
// a terminal, operator-visible dead letter.
func (r *SituationRuntime) RetrySituationInput(ctx context.Context, claim situation.InputClaim, class string, retryAt time.Time, terminal bool) error {
	return r.st.RetrySituationInput(ctx, storeInputClaim(claim), class, retryAt, terminal)
}

func storeInputClaim(claim situation.InputClaim) SituationInput {
	return SituationInput{
		ID: claim.ID, IncidentID: claim.IncidentID, GroupKey: claim.GroupKey, Kind: claim.Kind,
		ClaimOwner: claim.ClaimOwner, ClaimToken: claim.ClaimToken,
	}
}

// --------------------------------------------------------------------------
// situation.ControllerStore
// --------------------------------------------------------------------------

// ClaimDueSituations leases due nonterminal aggregates in deterministic
// priority order.
func (r *SituationRuntime) ClaimDueSituations(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]situation.DueClaim, error) {
	claimed, err := r.st.ClaimDueSituations(ctx, owner, now, lease, limit)
	if err != nil {
		return nil, err
	}
	out := make([]situation.DueClaim, 0, len(claimed))
	for _, claim := range claimed {
		out = append(out, situation.DueClaim{SituationID: claim.Situation.ID, ClaimOwner: claim.ClaimOwner, ClaimToken: claim.ClaimToken})
	}
	return out, nil
}

// ExtendSituationLease heartbeats a live claim this worker still owns.
func (r *SituationRuntime) ExtendSituationLease(ctx context.Context, situationID, owner string, claimToken int64, now time.Time, lease time.Duration) error {
	return r.st.ExtendSituationLease(ctx, situationID, owner, claimToken, now, lease)
}

// ReleaseSituation drops a claim whose reconciliation failed, recording the
// failure class and the next attempt time. The aggregate stays durable and
// claimable; nothing about a failed attempt advances lifecycle.
//
// A claim that is already gone — the transition released it, or the lease
// lapsed and another worker took over — reached the same end state, so this
// reports success. Releasing is idempotent by design: routine lease
// contention must never be mistaken for a storage failure by a caller that
// gates readiness on round outcomes.
func (r *SituationRuntime) ReleaseSituation(ctx context.Context, claim situation.DueClaim, class string, retryAt time.Time) error {
	if strings.TrimSpace(claim.SituationID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: releasing a situation requires a complete claim")
	}
	now := r.clock().UTC()
	if _, err := r.st.db.ExecContext(ctx, `
		UPDATE situations
		SET lease_owner = NULL, lease_expires_at = NULL, last_error_class = ?, retry_at = ?, updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		class, canonicalTime(retryAt), canonicalTime(now), claim.SituationID, claim.ClaimOwner, claim.ClaimToken); err != nil {
		return fmt.Errorf("store: release situation claim: %w", err)
	}
	return nil
}

// CompleteSituation releases a claim whose reconciliation succeeded and, when
// that reconciliation committed no transition (the current fact hash was
// already covered by a trustworthy Assessment), schedules the next checkpoint
// so the aggregate does not stay perpetually due. A reconciliation that DID
// commit has already released its own lease and set its own next assessment
// time, so this finds nothing to change and succeeds.
func (r *SituationRuntime) CompleteSituation(ctx context.Context, claim situation.DueClaim, nextAt time.Time) error {
	if strings.TrimSpace(claim.SituationID) == "" || strings.TrimSpace(claim.ClaimOwner) == "" || claim.ClaimToken <= 0 {
		return errors.New("store: completing a situation requires a complete claim")
	}
	now := r.clock().UTC()
	if _, err := r.st.db.ExecContext(ctx, `
		UPDATE situations
		SET lease_owner = NULL, lease_expires_at = NULL,
		    next_assessment_at = MAX(next_assessment_at, ?), updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		canonicalTime(nextAt), canonicalTime(now), claim.SituationID, claim.ClaimOwner, claim.ClaimToken); err != nil {
		return fmt.Errorf("store: complete situation claim: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// situation.NotificationStore and situation.PublisherStore
// --------------------------------------------------------------------------

// ClaimNotificationIntents leases due pending intents for delivery.
func (r *SituationRuntime) ClaimNotificationIntents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]model.NotificationIntent, error) {
	return r.st.ClaimNotificationIntents(ctx, now, lease, limit)
}

// MarkNotificationDelivered records one successful outward effect.
func (r *SituationRuntime) MarkNotificationDelivered(ctx context.Context, id, channel, messageTS string, deliveredAt time.Time) error {
	return r.st.MarkNotificationDelivered(ctx, id, channel, messageTS, deliveredAt)
}

// RetryNotificationIntent releases a claimed intent for a later attempt with
// the same durable identity, or records a terminal dead letter.
func (r *SituationRuntime) RetryNotificationIntent(ctx context.Context, id, class string, retryAt time.Time, terminal bool) error {
	return r.st.RetryNotificationIntent(ctx, id, class, retryAt, terminal)
}

// CreateNotificationIntent persists one standalone intent (dependency health,
// envelope review). Situation-scope intents never come through here: they
// commit atomically with their transition instead.
func (r *SituationRuntime) CreateNotificationIntent(ctx context.Context, in model.NotificationIntent) error {
	prepared, err := r.withClientMessageID(in)
	if err != nil {
		return err
	}
	return r.st.CreateNotificationIntent(ctx, prepared)
}

// HasRootCreateIntent reports whether the Situation already owns its one root.
func (r *SituationRuntime) HasRootCreateIntent(ctx context.Context, situationID string) (bool, error) {
	return r.st.HasRootCreateIntent(ctx, situationID)
}

func (r *SituationRuntime) withClientMessageID(in model.NotificationIntent) (model.NotificationIntent, error) {
	if in.ClientMessageID != "" {
		return in, nil
	}
	if r.clientMessageID == nil {
		return model.NotificationIntent{}, errors.New("store: notification intent needs a deterministic client message id function")
	}
	in.ClientMessageID = r.clientMessageID(in.IdempotencyKey)
	return in, nil
}

// --------------------------------------------------------------------------
// situation.ReconstructStore
// --------------------------------------------------------------------------

// RecoverExpiredLeases releases every abandoned durable claim so the work
// becomes claimable again. It never discards or acknowledges work.
func (r *SituationRuntime) RecoverExpiredLeases(ctx context.Context, now time.Time) (situation.LeaseRecovery, error) {
	var out situation.LeaseRecovery
	now = now.UTC()
	dispatches, err := r.st.db.ExecContext(ctx, `
		UPDATE alert_delivery_dispatches
		SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL
		WHERE status = 'claimed' AND lease_expires_at <= ?`, canonicalTime(now))
	if err != nil {
		return out, fmt.Errorf("store: recover expired alert dispatch leases: %w", err)
	}
	if out.AlertDispatches, err = dispatches.RowsAffected(); err != nil {
		return out, fmt.Errorf("store: count recovered alert dispatch leases: %w", err)
	}

	inputs, err := r.st.db.ExecContext(ctx, `
		UPDATE situation_input_outbox
		SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL
		WHERE status = 'claimed' AND lease_expires_at <= ?`, canonicalTime(now))
	if err != nil {
		return out, fmt.Errorf("store: recover expired situation input leases: %w", err)
	}
	if out.SituationInputs, err = inputs.RowsAffected(); err != nil {
		return out, fmt.Errorf("store: count recovered situation input leases: %w", err)
	}

	if out.Situations, err = r.st.RecoverExpiredSituationLeases(ctx, now); err != nil {
		return out, err
	}
	return out, nil
}

// UnrepresentedActiveIncidents returns every nonterminal Incident that no
// Situation owns yet, carrying its persisted group identity and canonical
// times. This is the one-time pre-0011 upgrade population: after the first
// successful reconstruction the durable attachment keeps the list empty.
func (r *SituationRuntime) UnrepresentedActiveIncidents(ctx context.Context) ([]situation.UpgradeIncident, error) {
	rows, err := r.st.db.QueryContext(ctx, `
		SELECT i.id, i.group_key, i.first_alert_at, i.created_at, i.last_alert_at
		FROM incidents AS i
		WHERE i.status IN ('collecting', 'ready', 'processing', 'analyzed')
		  AND NOT EXISTS (SELECT 1 FROM situation_incidents AS si WHERE si.incident_id = i.id)
		ORDER BY i.group_key ASC, i.created_at ASC, i.id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: query unrepresented active incidents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []situation.UpgradeIncident
	for rows.Next() {
		var id, groupKey, firstAlertAt, createdAt, lastAlertAt string
		if err := rows.Scan(&id, &groupKey, &firstAlertAt, &createdAt, &lastAlertAt); err != nil {
			return nil, fmt.Errorf("store: scan unrepresented active incident: %w", err)
		}
		effective, err := parseSituationTime("incident first_alert_at", firstAlertAt)
		if err != nil {
			return nil, err
		}
		received, err := parseSituationTime("incident created_at", createdAt)
		if err != nil {
			return nil, err
		}
		observed, err := parseSituationTime("incident last_alert_at", lastAlertAt)
		if err != nil {
			return nil, err
		}
		out = append(out, situation.UpgradeIncident{
			IncidentID: id, GroupKey: groupKey,
			EffectiveStartedAt: effective, EffectiveStartedAtBasis: model.SourceTimeBasisReceiptFallback,
			FirstReceivedAt: received, LastLifecycleObservedAt: observed,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate unrepresented active incidents: %w", err)
	}
	return out, nil
}

// ReconstructSituation creates (or joins) exactly one nonterminal Situation
// for the exact group key and attaches every supplied Incident once. A
// created Situation is seeded at input_version 1 with the
// upgrade_reconstruction due reason and scheduled immediately — it carries no
// public handle, no Assessment, and no notification intent, so nothing about
// the restart itself can publish. Current evidence decides that on the first
// reconciliation pass.
func (r *SituationRuntime) ReconstructSituation(ctx context.Context, groupKey string, incidents []situation.UpgradeIncident, now time.Time) (string, error) {
	if strings.TrimSpace(groupKey) == "" || len(incidents) == 0 {
		return "", errors.New("store: reconstruction requires a group key and at least one incident")
	}
	now = now.UTC()
	tx, err := r.st.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: begin situation reconstruction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	situationID := ""
	current, currentErr := currentSituationForGroupTx(ctx, tx, groupKey)
	switch {
	case currentErr == nil && (current.Lifecycle == model.LifecycleActive || current.Lifecycle == model.LifecycleRecoveryPending):
		situationID = current.ID
	case currentErr != nil && !errors.Is(currentErr, ErrNotFound):
		return "", fmt.Errorf("store: read current situation for reconstruction: %w", currentErr)
	default:
		var previousID *string
		if currentErr == nil {
			previousID = &current.ID
		}
		times := reconstructedTimes(incidents)
		reasonsJSON, err := json.Marshal([]model.DueReason{model.DueUpgradeReconstruction})
		if err != nil {
			return "", fmt.Errorf("store: marshal reconstruction due reason: %w", err)
		}
		situationID = uuid.NewString()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO situations (
				id, previous_situation_id, group_key, lifecycle, attention, input_version,
				opened_at, effective_started_at, effective_started_at_basis,
				first_received_at, last_lifecycle_observed_at, next_assessment_at,
				due_reasons_json, attempt_count, created_at, updated_at
			) VALUES (?, ?, ?, 'active', 'observe', 1, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
			situationID, nullableString(previousID), groupKey, canonicalTime(now),
			canonicalTime(times.EffectiveStartedAt), model.SourceTimeBasisReceiptFallback,
			canonicalTime(times.FirstReceivedAt), canonicalTime(times.LastLifecycleObservedAt),
			canonicalTime(now), string(reasonsJSON), canonicalTime(now), canonicalTime(now)); err != nil {
			return "", fmt.Errorf("store: create reconstructed situation: %w", err)
		}
	}

	for _, incident := range incidents {
		if err := attachIncidentTx(ctx, tx, situationID, incident.IncidentID, now); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit situation reconstruction: %w", err)
	}
	return situationID, nil
}

type reconstructedSituationTimes struct {
	EffectiveStartedAt      time.Time
	FirstReceivedAt         time.Time
	LastLifecycleObservedAt time.Time
}

// reconstructedTimes folds the group's Incidents into the earliest canonical
// start/receipt and the newest lifecycle observation, so a reconstructed
// Situation inherits real persisted history rather than restart wall clock.
func reconstructedTimes(incidents []situation.UpgradeIncident) reconstructedSituationTimes {
	out := reconstructedSituationTimes{
		EffectiveStartedAt: incidents[0].EffectiveStartedAt,
		FirstReceivedAt:    incidents[0].FirstReceivedAt,
	}
	for _, incident := range incidents {
		if incident.EffectiveStartedAt.Before(out.EffectiveStartedAt) {
			out.EffectiveStartedAt = incident.EffectiveStartedAt
		}
		if incident.FirstReceivedAt.Before(out.FirstReceivedAt) {
			out.FirstReceivedAt = incident.FirstReceivedAt
		}
		if incident.LastLifecycleObservedAt.After(out.LastLifecycleObservedAt) {
			out.LastLifecycleObservedAt = incident.LastLifecycleObservedAt
		}
	}
	return out
}

// --------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------

// situationDeliveryRow is one immutable delivery plus the Incident that owns
// it — the acute ownership link the snapshot's membership view needs.
type situationDeliveryRow struct {
	Delivery   AlertDelivery
	IncidentID string
}

func (r *SituationRuntime) situationDeliveryRows(ctx context.Context, situationID string) ([]situationDeliveryRow, error) {
	rows, err := r.st.db.QueryContext(ctx, deliverySelect+`
		JOIN incident_alert_deliveries iad ON iad.delivery_id = ad.id
		JOIN situation_incidents si ON si.incident_id = iad.incident_id
		WHERE si.situation_id = ? ORDER BY ad.received_at ASC, ad.id ASC`, situationID)
	if err != nil {
		return nil, fmt.Errorf("store: query situation delivery rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []situationDeliveryRow
	var ids []string
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan situation delivery row: %w", err)
		}
		out = append(out, situationDeliveryRow{Delivery: d})
		ids = append(ids, d.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate situation delivery rows: %w", err)
	}
	owners, err := r.deliveryIncidentOwners(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].IncidentID = owners[out[i].Delivery.ID]
	}
	return out, nil
}

func (r *SituationRuntime) deliveryIncidentOwners(ctx context.Context, deliveryIDs []string) (map[string]string, error) {
	out := make(map[string]string, len(deliveryIDs))
	if len(deliveryIDs) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(deliveryIDs))
	args := make([]any, len(deliveryIDs))
	for i, id := range deliveryIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := r.st.db.QueryContext(ctx,
		`SELECT delivery_id, incident_id FROM incident_alert_deliveries WHERE delivery_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query delivery incident owners: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var deliveryID, incidentID string
		if err := rows.Scan(&deliveryID, &incidentID); err != nil {
			return nil, fmt.Errorf("store: scan delivery incident owner: %w", err)
		}
		out[deliveryID] = incidentID
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate delivery incident owners: %w", err)
	}
	return out, nil
}

// degradedDependencies lists the shared dependencies currently observed as
// degraded or unavailable, so reconciliation can carry honest limitations
// instead of silently treating missing evidence as a healthy empty result.
func (r *SituationRuntime) degradedDependencies(ctx context.Context) ([]DependencyHealth, error) {
	rows, err := r.st.db.QueryContext(ctx, `SELECT `+dependencyHealthColumns+` FROM dependency_health WHERE status IN ('degraded','unavailable') ORDER BY dependency ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: query degraded dependencies: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DependencyHealth
	for rows.Next() {
		health, err := scanDependencyHealth(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, health)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate degraded dependencies: %w", err)
	}
	return out, nil
}

// --------------------------------------------------------------------------
// situation.DependencyHealthStore
// --------------------------------------------------------------------------

// RecordDependencyDegraded persists one shared dependency as degraded (or
// unavailable), preserving the first observation so a sustained-outage
// threshold stays anchored to when the outage actually started.
func (r *SituationRuntime) RecordDependencyDegraded(ctx context.Context, dependency string, unavailable bool, observedAt time.Time) (situation.DependencyHealthState, bool, error) {
	health, transitioned, err := r.st.RecordDependencyDegraded(ctx, dependency, unavailable, observedAt)
	if err != nil {
		return situation.DependencyHealthState{}, false, err
	}
	return situation.DependencyHealthState{Dependency: health.Dependency, DegradedSince: health.DegradedSince}, transitioned, nil
}

// RecordDependencyRecovered persists one shared dependency as healthy again.
// A dependency never recorded degraded is a quiet no-op, not a failure.
func (r *SituationRuntime) RecordDependencyRecovered(ctx context.Context, dependency string, observedAt time.Time) (situation.DependencyHealthState, bool, error) {
	health, transitioned, err := r.st.RecordDependencyRecovered(ctx, dependency, observedAt)
	if errors.Is(err, ErrNotFound) {
		return situation.DependencyHealthState{}, false, situation.ErrDependencyNotObserved
	}
	if err != nil {
		return situation.DependencyHealthState{}, false, err
	}
	return situation.DependencyHealthState{Dependency: health.Dependency, DegradedSince: health.DegradedSince}, transitioned, nil
}

// HasDependencyRootIntent reports whether this dependency already owns its one
// health root, in any status. A sustained shared outage produces at most one.
func (r *SituationRuntime) HasDependencyRootIntent(ctx context.Context, dependency string) (bool, error) {
	if strings.TrimSpace(dependency) == "" {
		return false, errors.New("store: dependency root check requires a dependency name")
	}
	var exists int
	if err := r.st.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM notification_intents
		WHERE subject_kind = 'dependency_health' AND subject_id = ? AND kind = 'health_root'
	)`, dependency).Scan(&exists); err != nil {
		return false, fmt.Errorf("store: check existing dependency health root: %w", err)
	}
	return exists == 1, nil
}

// ScheduleAffectedSituations unions reason into every nonterminal Situation's
// due reasons and pulls its next reconciliation earlier. A shared outage
// changes what AlertINT can see, so every affected Situation reconsiders —
// but it produces no per-Situation Slack noise on its own.
func (r *SituationRuntime) ScheduleAffectedSituations(ctx context.Context, dependency string, reason model.DueReason, at time.Time) error {
	if strings.TrimSpace(dependency) == "" || strings.TrimSpace(string(reason)) == "" {
		return errors.New("store: scheduling affected situations requires a dependency and reason")
	}
	rows, err := r.st.db.QueryContext(ctx,
		`SELECT id FROM situations WHERE lifecycle IN ('active', 'recovery_pending')`)
	if err != nil {
		return fmt.Errorf("store: query situations affected by dependency health: %w", err)
	}
	ids := make([]string, 0, 16)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: scan situation affected by dependency health: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("store: iterate situations affected by dependency health: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("store: close situations affected by dependency health: %w", err)
	}
	var failures []error
	for _, id := range ids {
		if err := r.MarkDue(ctx, id, reason, at); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
