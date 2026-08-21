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
	"strings"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// The Situation controller's durable boundary (situation.Store). Every method
// here reads or writes only this package's own schema; none performs
// connector, model, or Slack I/O.

// ClaimedSituation reads the aggregate a worker already holds a lease on.
func (r *SituationRuntime) ClaimedSituation(ctx context.Context, situationID string) (situation.Claim, error) {
	if strings.TrimSpace(situationID) == "" {
		return situation.Claim{}, errors.New("store: claimed situation requires an id")
	}
	sit, err := querySituation(ctx, r.st.db, `SELECT `+situationColumns+` FROM situations WHERE id = ?`, situationID)
	if err != nil {
		return situation.Claim{}, err
	}
	if sit.LeaseOwner == nil {
		return situation.Claim{}, ErrSituationLeaseLost
	}
	var token int64
	if err := r.st.db.QueryRowContext(ctx, `SELECT claim_token FROM situations WHERE id = ?`, situationID).Scan(&token); err != nil {
		return situation.Claim{}, fmt.Errorf("store: read claimed situation token: %w", err)
	}
	return situation.Claim{Situation: sit, ClaimOwner: *sit.LeaseOwner, ClaimToken: token}, nil
}

// LoadReconciliationInput assembles the immutable read model BuildSnapshot
// reduces, and returns the Situation's primary Incident id for the B+ gate.
//
// The deterministic `symptom_state` facts this derives are the store_read
// capability's own bounded observation: they restate the immutable delivery
// ledger for the exact claimed input version. A lease-holding reconciliation
// persists them before using them, so the evidence a published Assessment
// cites is durable rather than in-memory; a lease-free read (the MCP
// judgment/snapshot path) sees the identical facts without writing.
func (r *SituationRuntime) LoadReconciliationInput(ctx context.Context, claim situation.Claim) (situation.SnapshotInput, string, error) {
	in := situation.SnapshotInput{Situation: claim.Situation}
	situationID := claim.Situation.ID

	incidents, err := r.st.SituationMemberIncidents(ctx, situationID)
	if err != nil {
		return in, "", err
	}
	primaryIncidentID := ""
	if len(incidents) > 0 {
		primaryIncidentID = incidents[0].ID
	}
	for _, incident := range incidents {
		in.Memberships = append(in.Memberships, situation.Membership{IncidentID: incident.ID})
	}

	rows, err := r.situationDeliveryRows(ctx, situationID)
	if err != nil {
		return in, primaryIncidentID, err
	}
	in.Deliveries = r.snapshotDeliveries(rows)
	// Reuse BuildSnapshot's own delivery-to-symptom reduction (rather than a
	// second, potentially divergent one) so ReconcileLifecycle's
	// symptom-driven recovery/refire checks (hasFiringSymptom/
	// allSymptomsResolved, controller.go — which run BEFORE BuildSnapshot
	// derives Snapshot.Symptoms) see the same current lifecycle/severity the
	// snapshot itself will.
	in.Symptoms = situation.DeriveSymptomsFromDeliveries(in.Deliveries)

	derived := deriveSymptomStateFacts(claim, in.Deliveries)
	if len(derived) > 0 && leaseFenced(claim) {
		// Only a lease-holding reconciliation may write. A lease-free read
		// (the MCP judgment/snapshot path) still SEES the same deterministic
		// facts — they are a restatement of the immutable ledger, not a new
		// observation — it simply does not persist them.
		if err := r.st.AppendSituationFacts(ctx, storeSituationClaim(claim), derived); err != nil {
			return in, primaryIncidentID, fmt.Errorf("store: persist derived symptom state facts: %w", err)
		}
	}
	stored, err := r.st.SituationFacts(ctx, situationID)
	if err != nil {
		return in, primaryIncidentID, err
	}
	in.Facts = mergeFacts(factsForInputVersion(stored, claim.Situation.InputVersion), derived)

	if in.Judgments, err = r.st.SituationJudgments(ctx, situationID); err != nil {
		return in, primaryIncidentID, err
	}
	if in.Envelope, in.EnvelopeEvidenceRefs, err = r.latestEnvelopeEvaluation(ctx, situationID); err != nil {
		return in, primaryIncidentID, err
	}
	if in.L1, err = r.acuteFinding(ctx, incidents); err != nil {
		return in, primaryIncidentID, err
	}
	if in.CompletedEpisodes, err = r.completedEpisodes(ctx, incidents); err != nil {
		return in, primaryIncidentID, err
	}

	degraded, err := r.degradedDependencies(ctx)
	if err != nil {
		return in, primaryIncidentID, err
	}
	in.Limitations = dependencyLimitations(degraded)

	in.TerminalUncertainty = r.terminalUncertainty(ctx, claim, in.Deliveries, degraded)
	return in, primaryIncidentID, nil
}

// snapshotDeliveries projects immutable ledger rows onto the reduction's
// delivery view. StableSymptomID is source-scoped fingerprint identity: it
// must stay stable ACROSS episodes (source_episode_key deliberately does
// not — it carries the canonical start instant), because symptom identity is
// what judgment coverage and novelty are expressed against.
func (r *SituationRuntime) snapshotDeliveries(rows []situationDeliveryRow) []situation.Delivery {
	out := make([]situation.Delivery, 0, len(rows))
	for _, row := range rows {
		d := row.Delivery
		signature := ""
		if r.profileSignature != nil {
			signature = r.profileSignature(d)
		}
		out = append(out, situation.Delivery{
			ID:               d.ID,
			IncidentID:       row.IncidentID,
			StableSymptomID:  d.Source + ":" + d.Alert.Fingerprint,
			Source:           d.Source,
			ProfileSignature: signature,
			Status:           model.DeliveryStatus(d.Alert.Status),
			Severity:         d.Alert.Labels["severity"],
			SourceStartedAt:  d.SourceStartedAt,
			StartedAtBasis:   d.StartedAtBasis,
			ReceivedAt:       d.ReceivedAt,
			EvidenceRefs:     []string{"delivery:" + d.ID},
		})
	}
	return out
}

// deriveSymptomStateFacts restates each symptom's current lifecycle/severity
// from the immutable ledger as one confirmed store_read fact per symptom.
// Both the id and every field are deterministic per (situation, input
// version, symptom) — the observation instant is the delivery's own receipt,
// never wall clock — so a retry after a crash replays into the identical row
// rather than colliding with itself or duplicating evidence.
func deriveSymptomStateFacts(claim situation.Claim, deliveries []situation.Delivery) []observationmodel.Fact {
	latest := make(map[string]situation.Delivery, len(deliveries))
	for _, delivery := range deliveries {
		if delivery.StableSymptomID == "" {
			continue
		}
		prior, ok := latest[delivery.StableSymptomID]
		if !ok || delivery.ReceivedAt.After(prior.ReceivedAt) ||
			(delivery.ReceivedAt.Equal(prior.ReceivedAt) && delivery.ID > prior.ID) {
			latest[delivery.StableSymptomID] = delivery
		}
	}
	symptomIDs := make([]string, 0, len(latest))
	for id := range latest {
		symptomIDs = append(symptomIDs, id)
	}
	sort.Strings(symptomIDs)

	out := make([]observationmodel.Fact, 0, len(symptomIDs))
	for _, symptomID := range symptomIDs {
		delivery := latest[symptomID]
		value, err := json.Marshal(struct {
			Lifecycle model.DeliveryStatus `json:"lifecycle"`
			Severity  string               `json:"severity"`
		}{delivery.Status, strings.ToLower(strings.TrimSpace(delivery.Severity))})
		if err != nil {
			continue
		}
		refs := []string{"delivery:" + delivery.ID}
		out = append(out, observationmodel.Fact{
			ID:               symptomStateFactID(claim.Situation.ID, claim.Situation.InputVersion, symptomID),
			SituationID:      claim.Situation.ID,
			InputVersion:     claim.Situation.InputVersion,
			Kind:             "symptom_state",
			Subject:          symptomID,
			Value:            value,
			SourceCapability: observationmodel.CapabilityStoreRead,
			ObservedAt:       delivery.ReceivedAt.UTC(),
			Freshness:        observationmodel.FreshnessFresh,
			ResultStatus:     observationmodel.ResultStatusConfirmedValue,
			Digest:           factDigest(value, refs),
			EvidenceRefs:     refs,
			Material:         true,
		})
	}
	return out
}

func symptomStateFactID(situationID string, inputVersion int, symptomID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("symptom_state|%s|%d|%s", situationID, inputVersion, symptomID)))
	return "fact:symptom_state:" + hex.EncodeToString(sum[:16])
}

func factDigest(value json.RawMessage, refs []string) string {
	sum := sha256.Sum256([]byte(string(value) + "|" + strings.Join(refs, ",")))
	return hex.EncodeToString(sum[:])
}

// leaseFenced reports whether the claim carries the durable fencing identity
// every Situation write requires. A read-only caller legitimately has none.
func leaseFenced(claim situation.Claim) bool {
	return strings.TrimSpace(claim.ClaimOwner) != "" && claim.ClaimToken > 0
}

// mergeFacts unions persisted evidence with the deterministic evidence this
// load derived, keeping the persisted row when both carry the same id.
func mergeFacts(stored, derived []observationmodel.Fact) []observationmodel.Fact {
	seen := make(map[string]struct{}, len(stored))
	out := make([]observationmodel.Fact, 0, len(stored)+len(derived))
	for _, fact := range stored {
		seen[fact.ID] = struct{}{}
		out = append(out, fact)
	}
	for _, fact := range derived {
		if _, ok := seen[fact.ID]; ok {
			continue
		}
		out = append(out, fact)
	}
	return out
}

// factsForInputVersion keeps only the evidence belonging to the exact
// claimed input version: an older version's facts describe a different fact
// set and must never justify a decision about this one.
func factsForInputVersion(facts []observationmodel.Fact, inputVersion int) []observationmodel.Fact {
	out := make([]observationmodel.Fact, 0, len(facts))
	for _, fact := range facts {
		if fact.InputVersion == inputVersion {
			out = append(out, fact)
		}
	}
	return out
}

// latestEnvelopeEvaluation returns the Situation's most recent deterministic
// envelope evaluation and the evidence refs it rests on.
func (r *SituationRuntime) latestEnvelopeEvaluation(ctx context.Context, situationID string) (*model.EnvelopeEvaluation, []string, error) {
	evaluations, err := r.st.SituationEnvelopeEvaluations(ctx, situationID)
	if err != nil {
		return nil, nil, err
	}
	if len(evaluations) == 0 {
		return nil, nil, nil
	}
	latest := evaluations[len(evaluations)-1]
	for _, evaluation := range evaluations {
		if evaluation.CreatedAt.After(latest.CreatedAt) {
			latest = evaluation
		}
	}
	return &latest, append([]string(nil), latest.MatchedFields...), nil
}

// acuteFinding projects the durable L1 finding of the Situation's primary
// Incident. A finding is evidence only — D2 gives it no Attention or
// notification authority.
func (r *SituationRuntime) acuteFinding(ctx context.Context, incidents []Incident) (*situation.L1Output, error) {
	if len(incidents) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(incidents))
	for _, incident := range incidents {
		ids = append(ids, incident.ID)
	}
	states, err := r.st.AnalysisStates(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, incident := range incidents {
		state := states[incident.ID]
		if state.Status != situation.L1StatusComplete || strings.TrimSpace(incident.OutputJSON) == "" {
			continue
		}
		return &situation.L1Output{
			Status:          string(state.Status),
			Summary:         incident.Summary,
			RootCauseClass:  incident.RootCause,
			ConfidenceClass: confidenceClass(incident.Confidence),
			EvidenceRefs:    []string{"incident:" + incident.ID},
		}, nil
	}
	return nil, nil
}

// confidenceClass mirrors situation.NormalizeL1's banding so a stored
// finding reduces to the same material class an inline one would.
func confidenceClass(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return "high"
	case confidence >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

// completedEpisodes projects prior recurrence episodes of the member
// Incidents. Only a closed episode (one with a distinct occurrence row) is
// comparable duration evidence.
func (r *SituationRuntime) completedEpisodes(ctx context.Context, incidents []Incident) ([]situation.CompletedEpisode, error) {
	if len(incidents) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(incidents))
	for _, incident := range incidents {
		ids = append(ids, incident.ID)
	}
	stats, err := r.st.OccurrenceStatsByIncident(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("store: read situation occurrence stats: %w", err)
	}
	var out []situation.CompletedEpisode
	for _, incident := range incidents {
		stat, ok := stats[incident.ID]
		if !ok || stat.Episodes() <= 1 {
			continue
		}
		out = append(out, situation.CompletedEpisode{
			ID:              incident.ID,
			DurationSeconds: int64(stat.LastSeen.Sub(incident.FirstAlertAt) / time.Second),
			Comparable:      true,
			EvidenceRefs:    []string{"incident:" + incident.ID},
		})
	}
	return out, nil
}

// dependencyLimitations renders each degraded shared dependency as one
// honest Assessment limitation: unavailable evidence is never allowed to
// read as a healthy empty observation.
func dependencyLimitations(degraded []DependencyHealth) []model.Limitation {
	out := make([]model.Limitation, 0, len(degraded))
	for _, health := range degraded {
		out = append(out, model.Limitation{
			Code:   "dependency_degraded",
			Detail: fmt.Sprintf("%s is %s; its evidence is unavailable, not empty", health.Dependency, health.Status),
		})
	}
	return out
}

// terminalUncertainty performs the tier-aware lifecycle-deadline check that
// decides whether lifecycle truth has become unobservable. It is the real
// check the deterministic closed_unknown short-circuit trusts:
// CloseUnknown's own two-hour freshness floor is a last-resort structural
// guard, not this determination.
//
// Every input is durable, authoritative store state: the Situation's own
// persisted last_lifecycle_observed_at, the immutable delivery ledger's
// firing/resolved status, and the durable dependency-health rows. Nothing
// here is derived from in-memory runtime state, so the loader-trusted
// short-circuit stays honest across restarts.
func (r *SituationRuntime) terminalUncertainty(ctx context.Context, claim situation.Claim, deliveries []situation.Delivery, degraded []DependencyHealth) *situation.TerminalUncertainty {
	now := r.clock().UTC()
	observedAt := claim.Situation.LastLifecycleObservedAt
	for _, delivery := range deliveries {
		if delivery.ReceivedAt.After(observedAt) {
			observedAt = delivery.ReceivedAt
		}
	}
	if observedAt.IsZero() {
		observedAt = claim.Situation.FirstReceivedAt
	}

	deadline := situation.WidenLifecycleDeadline(r.policy.HorizonTier, r.profileHorizonTiers(ctx, deliveries)...)
	elapsed := now.Sub(observedAt)
	if elapsed < deadline {
		return nil
	}

	candidates := []model.TerminalReason{model.TerminalReasonObservationDeadline}
	if len(degraded) > 0 {
		candidates = append(candidates, model.TerminalReasonSourceUnavailable)
	}
	if hasUnresolvedDelivery(deliveries) {
		candidates = append(candidates, model.TerminalReasonResolutionMissing)
	}
	reason, ok := situation.SelectTerminalReason(candidates...)
	if !ok {
		return nil
	}
	refs := make([]string, 0, len(deliveries)+1)
	refs = append(refs, "situation:"+claim.Situation.ID+":last_lifecycle_observed_at")
	for _, delivery := range deliveries {
		refs = append(refs, "delivery:"+delivery.ID)
	}
	return &situation.TerminalUncertainty{
		DeadlineCrossed: true,
		Actionable:      true,
		Reason:          reason,
		EvidenceRefs:    refs,
	}
}

// profileHorizonTiers collects the advisory L0 horizon tiers covering the
// Situation's delivery signatures. They may only widen the deterministic
// deadline, never shorten it.
func (r *SituationRuntime) profileHorizonTiers(ctx context.Context, deliveries []situation.Delivery) []string {
	seen := make(map[string]struct{}, len(deliveries))
	var tiers []string
	for _, delivery := range deliveries {
		if delivery.ProfileSignature == "" {
			continue
		}
		if _, ok := seen[delivery.ProfileSignature]; ok {
			continue
		}
		seen[delivery.ProfileSignature] = struct{}{}
		history, err := r.st.SemanticProfile(ctx, delivery.ProfileSignature)
		if err != nil || history == nil {
			continue
		}
		for _, version := range history.Versions {
			if version.Version == history.CurrentVersion {
				tiers = append(tiers, version.Profile.HorizonTier)
				break
			}
		}
	}
	return tiers
}

func hasUnresolvedDelivery(deliveries []situation.Delivery) bool {
	for _, delivery := range deliveries {
		if delivery.Status == model.DeliveryStatusFiring {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// B+ gate state
// --------------------------------------------------------------------------

// AnalysisState reads the explicit acute-analysis gate for one Incident.
func (r *SituationRuntime) AnalysisState(ctx context.Context, incidentID string) (situation.AnalysisState, error) {
	states, err := r.st.AnalysisStates(ctx, []string{incidentID})
	if err != nil {
		return situation.AnalysisState{}, err
	}
	state := states[incidentID]
	out := situation.AnalysisState{
		IncidentID: state.IncidentID, Status: state.Status,
		DecisionReason: state.DecisionReason, UpdatedAt: state.UpdatedAt,
	}
	if state.LatestAttemptID != nil {
		out.LatestAttemptID = *state.LatestAttemptID
	}
	return out, nil
}

// SetAnalysisState persists the B+ gate decision for one Incident. An
// omitted finding is never ambiguous: every decision is written down.
func (r *SituationRuntime) SetAnalysisState(ctx context.Context, state situation.AnalysisState) error {
	if strings.TrimSpace(state.IncidentID) == "" || strings.TrimSpace(string(state.Status)) == "" {
		return errors.New("store: analysis state requires an incident id and status")
	}
	updatedAt := state.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = r.clock().UTC()
	}
	var latestAttemptID any
	if strings.TrimSpace(state.LatestAttemptID) != "" {
		latestAttemptID = state.LatestAttemptID
	}
	if _, err := r.st.db.ExecContext(ctx, `
		INSERT INTO incident_analysis_state (incident_id, status, decision_reason, latest_attempt_id, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(incident_id) DO UPDATE SET
			status = excluded.status,
			decision_reason = excluded.decision_reason,
			latest_attempt_id = COALESCE(excluded.latest_attempt_id, incident_analysis_state.latest_attempt_id),
			updated_at = excluded.updated_at`,
		state.IncidentID, string(state.Status), state.DecisionReason, latestAttemptID, canonicalTime(updatedAt)); err != nil {
		return fmt.Errorf("store: set incident analysis state: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Assessment history and commits
// --------------------------------------------------------------------------

// LastTrustedAssessment returns the covering decision the B+ gate consults
// and the full prior Assessment the L2 prompt receives. A degraded or
// insufficient prior Assessment is never trustworthy: it can describe what
// the controller knew, but it can never justify skipping fresh analysis.
func (r *SituationRuntime) LastTrustedAssessment(ctx context.Context, claim situation.Claim) (situation.TrustedAssessment, *model.Assessment, error) {
	var trusted situation.TrustedAssessment
	if err := r.st.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(sequence), 0) FROM situation_assessment_attempts WHERE situation_id = ?`, claim.Situation.ID).
		Scan(&trusted.Sequence); err != nil {
		return trusted, nil, fmt.Errorf("store: read latest assessment sequence: %w", err)
	}

	var factHash string
	var validated sql.NullString
	err := r.st.db.QueryRowContext(ctx, `
		SELECT fact_hash, validated_json FROM situation_assessment_attempts
		WHERE situation_id = ? AND status = 'authoritative'
		ORDER BY sequence DESC LIMIT 1`, claim.Situation.ID).Scan(&factHash, &validated)
	if errors.Is(err, sql.ErrNoRows) {
		return trusted, nil, nil
	}
	if err != nil {
		return trusted, nil, fmt.Errorf("store: read last authoritative assessment: %w", err)
	}
	if !validated.Valid {
		return trusted, nil, nil
	}
	var prior model.Assessment
	if err := json.Unmarshal([]byte(validated.String), &prior); err != nil {
		return trusted, nil, fmt.Errorf("store: decode last authoritative assessment: %w", err)
	}
	trusted.FactHash = factHash
	trusted.Trustworthy = prior.EvidenceQuality == model.EvidenceQualityComplete
	return trusted, &prior, nil
}

// AppendAssessmentAttempt records one attempt (proposed, rejected, failed, or
// stale) under the current fence.
func (r *SituationRuntime) AppendAssessmentAttempt(ctx context.Context, claim situation.Claim, attempt situation.AssessmentAttempt) error {
	stored, err := storeAssessmentAttempt(claim, attempt)
	if err != nil {
		return err
	}
	return r.st.AppendAssessmentAttempt(ctx, storeSituationClaim(claim), stored)
}

// CommitAuthoritative appends the authoritative attempt and applies the
// transition together with every notification intent it requires.
//
// The intents are planned here and handed to CommitSituationTransition so
// they commit in the SAME transaction as the transition: there is deliberately
// no path that commits a transition and then separately publishes it, because
// a crash in that window would silently drop a promised Slack effect with no
// durable record one was ever owed.
func (r *SituationRuntime) CommitAuthoritative(ctx context.Context, claim situation.Claim, attempt situation.AssessmentAttempt, tr model.Transition) error {
	stored, err := storeAssessmentAttempt(claim, attempt)
	if err != nil {
		return err
	}
	storedClaim := storeSituationClaim(claim)

	intents, err := r.planTransitionIntents(ctx, claim, tr)
	if err != nil {
		return err
	}
	if err := r.st.AppendAssessmentAttempt(ctx, storedClaim, stored); err != nil {
		if errors.Is(err, ErrSituationVersionConflict) {
			return situation.ErrStaleInput
		}
		return err
	}
	assessmentID := attempt.ID
	if err := r.st.CommitSituationTransition(ctx, storedClaim, tr, &assessmentID, intents); err != nil {
		if errors.Is(err, ErrSituationVersionConflict) {
			return situation.ErrStaleInput
		}
		return err
	}
	r.observeTransition(ctx, tr)
	return nil
}

// observeTransition reports one durably committed transition to the outward
// observer. It runs after the commit and never returns an error: the
// transition is already authoritative, and observability must not be able to
// undo or fail it.
func (r *SituationRuntime) observeTransition(ctx context.Context, tr model.Transition) {
	if r.observer == nil {
		return
	}
	sit, err := r.st.GetSituation(ctx, tr.SituationID)
	if err != nil {
		return
	}
	incidents, err := r.st.SituationMemberIncidents(ctx, tr.SituationID)
	if err != nil {
		return
	}
	ids := make([]string, 0, len(incidents))
	for _, incident := range incidents {
		ids = append(ids, incident.ID)
	}
	drill := false
	if flags, err := r.st.IncidentDrillFlags(ctx, ids); err == nil {
		for _, id := range ids {
			if flags[id] {
				drill = true
				break
			}
		}
	}
	r.observer.OnSituationTransition(ctx, sit, tr, ids, drill)
}

// planTransitionIntents resolves the durable publication context and runs
// the deterministic planner. The planner's output is the input to the atomic
// commit — never a separate publish call.
func (r *SituationRuntime) planTransitionIntents(ctx context.Context, claim situation.Claim, tr model.Transition) ([]model.NotificationIntent, error) {
	channel, messageTS, published, err := r.st.SituationRootCoordinates(ctx, claim.Situation.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	root := situation.RootCoordinates{Exists: published, Channel: channel, MessageTS: messageTS}
	if !root.Exists {
		// A still-undelivered root-create already reserves the Situation's one
		// root; treating it as absent would plan a second one.
		reserved, err := r.st.HasRootCreateIntent(ctx, claim.Situation.ID)
		if err != nil {
			return nil, err
		}
		root.Exists = reserved
	}

	prior, err := r.priorTransition(ctx, claim.Situation.ID)
	if err != nil {
		return nil, err
	}
	lastPoke, err := r.lastMainChannelPokeAt(ctx, claim.Situation.ID)
	if err != nil {
		return nil, err
	}
	recurrenceCount, recurrenceTrigger, err := r.recurrenceContext(ctx, claim.Situation.ID)
	if err != nil {
		return nil, err
	}

	planned := situation.PlanNotificationIntents(situation.PublishInput{
		Transition:            tr,
		PriorTransition:       prior,
		Root:                  root,
		MinSeverity:           r.policy.MinSeverity,
		RecoveryPending:       tr.Lifecycle == model.LifecycleRecoveryPending,
		RecurrenceCount:       recurrenceCount,
		RecurrenceTrigger:     recurrenceTrigger,
		RecurrenceMode:        r.policy.RecurrenceMode,
		LastMainChannelPokeAt: lastPoke,
		CooldownSeconds:       r.policy.RepageCooldownSeconds,
		Now:                   tr.CreatedAt.UTC(),
	})
	out := make([]model.NotificationIntent, 0, len(planned))
	for _, intent := range planned {
		prepared, err := r.withClientMessageID(intent)
		if err != nil {
			return nil, err
		}
		out = append(out, prepared)
	}
	return out, nil
}

// priorTransition rebuilds the Situation's previous committed transition
// from its previous authoritative attempt. The authoritative subsequence IS
// the transition history (D1: no separate transitions table).
func (r *SituationRuntime) priorTransition(ctx context.Context, situationID string) (*model.Transition, error) {
	var id, factHash string
	var inputVersion int
	var validated sql.NullString
	var createdAt string
	err := r.st.db.QueryRowContext(ctx, `
		SELECT id, input_version, fact_hash, validated_json, created_at
		FROM situation_assessment_attempts
		WHERE situation_id = ? AND status = 'authoritative'
		ORDER BY sequence DESC LIMIT 1`, situationID).Scan(&id, &inputVersion, &factHash, &validated, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read prior situation transition: %w", err)
	}
	if !validated.Valid {
		return nil, nil
	}
	var assessment model.Assessment
	if err := json.Unmarshal([]byte(validated.String), &assessment); err != nil {
		return nil, fmt.Errorf("store: decode prior situation transition: %w", err)
	}
	at, err := parseSituationTime("prior transition created_at", createdAt)
	if err != nil {
		return nil, err
	}
	return &model.Transition{
		ID: id, SituationID: situationID, InputVersion: inputVersion,
		Lifecycle: assessment.Lifecycle, Attention: assessment.Attention, Assessment: &assessment,
		ActionContract: assessment.ActionContract, CreatedAt: at,
	}, nil
}

// lastMainChannelPokeAt reads when this Situation last interrupted the main
// channel, so the re-page cooldown measures real elapsed operator noise.
func (r *SituationRuntime) lastMainChannelPokeAt(ctx context.Context, situationID string) (*time.Time, error) {
	var deliveredAt sql.NullString
	err := r.st.db.QueryRowContext(ctx, `
		SELECT MAX(delivered_at) FROM notification_intents
		WHERE situation_id = ? AND main_channel_poke = 1 AND status = 'delivered'`, situationID).Scan(&deliveredAt)
	if err != nil {
		return nil, fmt.Errorf("store: read last main channel poke: %w", err)
	}
	if !deliveredAt.Valid {
		return nil, nil
	}
	at, err := parseSituationTime("notification delivered_at", deliveredAt.String)
	if err != nil {
		return nil, err
	}
	return &at, nil
}

// recurrenceContext reports the Situation's exact-key episode count and the
// rung that fired its newest recurrence-collapse attach.
func (r *SituationRuntime) recurrenceContext(ctx context.Context, situationID string) (int, string, error) {
	var count int
	var trigger sql.NullString
	if err := r.st.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM incident_occurrences AS o
		JOIN situation_incidents AS si ON si.incident_id = o.incident_id
		WHERE si.situation_id = ?`, situationID).Scan(&count); err != nil {
		return 0, "", fmt.Errorf("store: count situation recurrence episodes: %w", err)
	}
	if count == 0 {
		return 0, "", nil
	}
	if err := r.st.db.QueryRowContext(ctx, `
		SELECT o.trigger_kind FROM incident_occurrences AS o
		JOIN situation_incidents AS si ON si.incident_id = o.incident_id
		WHERE si.situation_id = ?
		ORDER BY o.occurred_at DESC, o.id DESC LIMIT 1`, situationID).Scan(&trigger); err != nil {
		return 0, "", fmt.Errorf("store: read situation recurrence trigger: %w", err)
	}
	if !trigger.Valid || trigger.String == "none" {
		return count, "", nil
	}
	return count, trigger.String, nil
}

// --------------------------------------------------------------------------
// Scheduling
// --------------------------------------------------------------------------

// Reschedule pulls the next assessment forward without touching lifecycle or
// Attention — used after a stale commit reschedules the current input.
func (r *SituationRuntime) Reschedule(ctx context.Context, claim situation.Claim, at time.Time) error {
	now := r.clock().UTC()
	res, err := r.st.db.ExecContext(ctx, `
		UPDATE situations
		SET next_assessment_at = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		canonicalTime(at), canonicalTime(now), claim.Situation.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: reschedule situation: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count rescheduled situation: %w", err)
	}
	if changed != 1 {
		return ErrSituationLeaseLost
	}
	return nil
}

// Park preserves the still-safe prior Assessment and marks work parked for an
// unchanged input that exhausted its attempt budget. Exhaustion parks work; it
// never derives terminality.
func (r *SituationRuntime) Park(ctx context.Context, claim situation.Claim, retryAt time.Time, decisionReason string) error {
	now := r.clock().UTC()
	res, err := r.st.db.ExecContext(ctx, `
		UPDATE situations
		SET retry_at = ?, next_assessment_at = ?, last_error_class = ?,
		    lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE id = ? AND lease_owner = ? AND claim_token = ?`,
		canonicalTime(retryAt), canonicalTime(retryAt), decisionReason, canonicalTime(now),
		claim.Situation.ID, claim.ClaimOwner, claim.ClaimToken)
	if err != nil {
		return fmt.Errorf("store: park situation: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: count parked situation: %w", err)
	}
	if changed != 1 {
		return ErrSituationLeaseLost
	}
	return nil
}

// MarkDue unions one due reason and pulls next_assessment_at earlier. It is
// deliberately lease-free: the async L1 dispatch calls it after the
// reconciliation that started it has already released its claim.
func (r *SituationRuntime) MarkDue(ctx context.Context, situationID string, reason model.DueReason, at time.Time) error {
	if strings.TrimSpace(situationID) == "" || strings.TrimSpace(string(reason)) == "" {
		return errors.New("store: marking a situation due requires an id and reason")
	}
	now := r.clock().UTC()
	tx, err := r.st.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin mark situation due: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := querySituation(ctx, tx, `SELECT `+situationColumns+` FROM situations WHERE id = ?`, situationID)
	if err != nil {
		return err
	}
	if current.Lifecycle != model.LifecycleActive && current.Lifecycle != model.LifecycleRecoveryPending {
		// Terminal Situations never reopen.
		return tx.Commit()
	}
	reasons := situation.MergeDueReasons(current.DueReasons, reason)
	reasonsJSON, err := json.Marshal(reasons)
	if err != nil {
		return fmt.Errorf("store: marshal situation due reasons: %w", err)
	}
	next := situation.EarlierAssessmentAt(current.NextAssessmentAt, at)
	if _, err := tx.ExecContext(ctx, `
		UPDATE situations SET due_reasons_json = ?, next_assessment_at = ?, updated_at = ? WHERE id = ?`,
		string(reasonsJSON), canonicalTime(next), canonicalTime(now), situationID); err != nil {
		return fmt.Errorf("store: mark situation due: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit mark situation due: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Conversions
// --------------------------------------------------------------------------

func storeSituationClaim(claim situation.Claim) SituationClaim {
	return SituationClaim{Situation: claim.Situation, ClaimOwner: claim.ClaimOwner, ClaimToken: claim.ClaimToken}
}

func storeAssessmentAttempt(claim situation.Claim, attempt situation.AssessmentAttempt) (AssessmentAttempt, error) {
	adjustments, err := json.Marshal(attempt.ValidationAdjustments)
	if err != nil {
		return AssessmentAttempt{}, fmt.Errorf("store: marshal validation adjustments: %w", err)
	}
	if len(attempt.ValidationAdjustments) == 0 {
		adjustments = nil
	}
	return AssessmentAttempt{
		ID: attempt.ID, SituationID: claim.Situation.ID, Sequence: attempt.Sequence,
		InputVersion: attempt.InputVersion, FactHash: attempt.FactHash,
		Actor: AssessmentActor(attempt.Actor), Status: AssessmentStatus(attempt.Status),
		TriggerReasons: attempt.TriggerReasons, SnapshotDigest: attempt.SnapshotDigest,
		Proposal: attempt.Proposal, Validated: attempt.Validated,
		ValidationAdjustments: adjustments, ModelUsage: attempt.ModelUsage,
		CreatedAt: attempt.CreatedAt, CompletedAt: attempt.CompletedAt,
	}, nil
}
