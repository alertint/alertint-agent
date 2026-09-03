// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Task 7: the AcuteAnalyzer/AfterCommitter boundary between this skill and
// internal/situation.TriageWorker. See internal/situation/triage_worker.go
// for the full ownership-boundary contract this file implements.
// ----------------------------------------------------------------------

// ErrCleanSkip aliases situation.ErrCleanSkip for ergonomic use inside this
// package's own callers and tests, without requiring every call site to
// import internal/situation just for one sentinel. It is defined in
// internal/situation (not here) so internal/situation/triage_worker.go can
// recognize it with errors.Is without importing this package back — this
// package already imports internal/situation for AcuteResult/
// TriageAttemptClaim/AcuteAnalyzer, so importing it back here would cycle.
var ErrCleanSkip = situation.ErrCleanSkip

// Closed post-commit memory operation codes AfterCommit interprets — see
// situation.MemoryUpdate's own doc comment.
const (
	memoryOpIncrementRefuteMarks = "increment_refute_marks"
	memoryOpClearRefuteMarks     = "clear_refute_marks"
)

// Analyze loads the incident and its current member alerts, runs the full
// Acute Triage analysis (rules, evidence, LLM, optional verification round,
// deterministic caps), and returns every durable AcuteResult field a
// completion needs — with no durable Incident/Finding write, no role write,
// no memory mark, and no outward notifier call. It returns the typed
// ErrCleanSkip, never a zero AcuteResult with a nil error, when there is
// nothing to analyze (no member alerts, or fewer than the configured
// minimum).
//
// It DOES call the configured audit sink for its own non-terminal
// action-trail entries (analysis_started, per-source enrichment digests,
// verification planned/executed — all fired from inside analyzeCore/
// analysis/verifyAndRejudge, unchanged from before this task's refactor).
// These are diagnostic trail rows describing analysis mechanics, not
// "terminal audit state": the terminal incident.analyzed row (and the
// memory-recall audit row that would accompany a memory mark) are computed
// here but held in the returned result's PostCommit.AuditRecords, appended
// only by AfterCommit once the store has actually committed a success.
//
// Fixed (Task 7 fix round, Finding #1 — see the Task 7 report's fix
// addendum for the full investigation): Analyze now loads member content
// through s.st.GetAlertDeliveries(claim.MemberDeliveryIDs) — the bounded,
// immutable per-delivery Alert snapshots frozen at claim time — never
// GetIncidentAlerts' current, mutable alerts/incident_alerts projection.
// This closes the re-fire divergence the prior version's own digest-fence
// "backstop" argument missed: a claimed ready/processing Incident's
// fingerprint re-firing correlates to a DIFFERENT (new) Incident once the
// claimed Incident has left "collecting" — so the claimed Incident's OWN
// membership/incident-input digests never change (the fence never fires),
// even though the SHARED alerts row (keyed by fingerprint, mutated in place
// by AcceptDeliveries' own ON CONFLICT) does. dedupeFrozenAlerts collapses
// the frozen per-delivery set back down to one entry per member Alert (the
// same shape GetIncidentAlerts has always produced), using the latest
// ReceivedAt among ONLY the frozen delivery set — never a later mutation
// outside it.
//
// Fixed (Task 7 fix round, round-2 finding against round 1's own Finding #1
// fix above): an EMPTY claim.MemberDeliveryIDs is no longer treated as
// automatic proof of zero member alerts — see loadFrozenClaimAlerts' own doc
// comment for why that conflated a genuinely membership-less Incident with a
// legacy/pre-delivery-ledger Incident that still has real members, and
// silently, terminally clean-skipped the latter with a misleading reason.
func (s *Skill) Analyze(ctx context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
	inc, err := s.st.GetIncidentByID(ctx, claim.IncidentID)
	if err != nil {
		return situation.AcuteResult{}, fmt.Errorf("acutetriage: analyze: load incident: %w", err)
	}
	if inc == nil {
		return situation.AcuteResult{}, fmt.Errorf("acutetriage: analyze: incident %s: %w", claim.IncidentID, store.ErrNotFound)
	}

	alerts, err := s.loadFrozenClaimAlerts(ctx, claim)
	if err != nil {
		return situation.AcuteResult{}, classifyAnalyzeError(err)
	}
	return s.analyzeFromAlerts(ctx, *inc, alerts)
}

// MinimumMemberAlerts implements situation.MinimumMemberAlertsPolicy: the
// member-alert count below which this skill has nothing to analyze
// (Config.MinAlerts; a lone first alert still produces a Finding by
// default). TriageWorker reads it once at construction and resolves
// ineligibility BEFORE claiming an attempt, so a clean skip consumes no
// Triage attempt; analyzeFromAlerts applies the same value as defense in
// depth for whatever reaches Analyze anyway.
func (s *Skill) MinimumMemberAlerts() int {
	if s == nil || s.cfg.MinAlerts <= 0 {
		return 1
	}
	return s.cfg.MinAlerts
}

// analyzeFromAlerts is Analyze's own shared core: the "no member alerts, or
// fewer than the configured minimum -> ErrCleanSkip; else run analyzeCore
// and assemble AcuteResult" logic, factored out so Run (skill.go) — which
// has no frozen claim at all and instead loads the Incident's CURRENT
// member alerts directly via GetIncidentAlerts, exactly as it always has —
// can share this exact logic against its own differently-sourced alerts
// slice. Analyze itself is the only caller that reaches this via frozen,
// claim-scoped content; Run intentionally stays on current-state loading
// (it is a direct-invocation compatibility path outside the durable
// claim/lease mechanism entirely — see Run's own doc comment — so there is
// nothing for it to freeze against).
func (s *Skill) analyzeFromAlerts(ctx context.Context, inc store.Incident, alerts []store.Alert) (situation.AcuteResult, error) {
	if len(alerts) == 0 {
		s.logger.Warn("acutetriage: incident has no member alerts; skipping", "incident_id", inc.ID)
		return situation.AcuteResult{}, ErrCleanSkip
	}
	minAlerts := s.MinimumMemberAlerts()
	if len(alerts) < minAlerts {
		s.logger.Info("triage skipped",
			"incident", inc.ID, "alerts", len(alerts), "min_required", minAlerts, "group", inc.GroupKey)
		return situation.AcuteResult{}, ErrCleanSkip
	}

	ta, err := s.analyzeCore(ctx, inc, alerts, false, "", inc.FirstAlertAt, "", nil)
	if err != nil {
		return situation.AcuteResult{}, classifyAnalyzeError(err)
	}

	result := situation.AcuteResult{
		IncidentID:         inc.ID,
		EvidencePackDigest: ta.evidencePackDigest,
		OutputJSON:         append(json.RawMessage(nil), ta.finalRaw...),
		AnalysisName:       ta.resp.AnalysisName,
		// Summary mirrors the pre-Task-7 persistFunc convention exactly:
		// SaveIncidentOutput/ReplaceIncidentOutput's own "summary" parameter
		// has always been fed resp.AnalysisName (not a separate free-text
		// summary field the model produces) — see the Task 7 report.
		Summary:        ta.resp.AnalysisName,
		RootCause:      ta.resp.OverallIssue,
		Confidence:     ta.resp.Confidence,
		EnrichmentJSON: ta.enrichmentJSON,
		AlertRoles:     computeAlertRoles(alerts, ta.resp.Alerts, ta.ar.shortCircuit),
	}
	result.PostCommit = s.buildPostCommit(ctx, inc, alerts, ta)
	return result, nil
}

// loadFrozenClaimAlerts loads exactly the bounded, immutable member content
// claim.MemberDeliveryIDs froze at claim time — s.st.GetAlertDeliveries,
// never GetIncidentAlerts' current mutable projection — and collapses it
// back down to one entry per member Alert via dedupeFrozenAlerts.
//
// An empty claim.MemberDeliveryIDs is ambiguous by itself: memberDeliveryIDsTx
// (internal/store/triage_controller.go) freezes it from incident_alert_
// deliveries alone, which is empty both for an Incident that genuinely has
// zero member alerts AND for an Incident that predates the delivery ledger
// (every Incident before migration 0013) or was otherwise reconstructed via
// UnrepresentedOperationalIncidents/ReconstructSituation with incident_alerts
// rows but no incident_alert_deliveries rows (see that file's own doc
// comment: "It never synthesizes an Alert delivery for an old row"). Task 7
// fix round, Finding introduced by round 1's own Finding #1 fix: silently
// treating the second case the same as the first terminally clean-skips a
// real Incident with a misleading "below the minimum member alert count"
// reason.
//
// So an empty claim.MemberDeliveryIDs falls back to loadLegacyClaimAlerts,
// which asks GetIncidentAlerts (the pre-Task-7, current-state read) whether
// the Incident actually has members despite the empty frozen delivery set.
// Every current ingestion path (attachCorrelatedDeliveryTx) inserts
// incident_alerts and incident_alert_deliveries together, in the same
// transaction — so incident_alerts rows with no incident_alert_deliveries
// counterpart can only be pre-ledger/legacy rows, never a currently-active
// Incident's membership racing this claim. Only when GetIncidentAlerts ALSO
// returns nothing is this genuinely a zero-member Incident, and the result
// (nil, nil) still reaches analyzeFromAlerts' own clean-skip check exactly
// as before.
func (s *Skill) loadFrozenClaimAlerts(ctx context.Context, claim situation.TriageAttemptClaim) ([]store.Alert, error) {
	if len(claim.MemberDeliveryIDs) == 0 {
		return s.loadLegacyClaimAlerts(ctx, claim)
	}
	deliveries, err := s.st.GetAlertDeliveries(ctx, claim.MemberDeliveryIDs)
	if err != nil {
		return nil, fmt.Errorf("acutetriage: analyze: load frozen member deliveries: %w", err)
	}
	return dedupeFrozenAlerts(deliveries), nil
}

// loadLegacyClaimAlerts is loadFrozenClaimAlerts' fallback for a claim whose
// MemberDeliveryIDs came back empty: it reads the Incident's CURRENT member
// alerts via GetIncidentAlerts (the same read Run/skill.go has always used,
// and everything used before Task 7's frozen-claim mechanism existed at
// all), so a legacy/pre-ledger Incident with real incident_alerts rows still
// gets analyzed instead of silently, terminally clean-skipped. This is
// narrower than it looks: it only ever runs for the bounded legacy
// population the delivery ledger has no coverage for at all (see
// loadFrozenClaimAlerts' own doc comment for why a currently-active
// Incident can never reach here with real members) — every other Incident
// still goes through the frozen, race-proof delivery-ledger path Finding #1
// added. A genuinely membership-less Incident (every member Alert somehow
// lost its delivery link, or simply never had one) returns (nil, nil) here
// exactly like GetIncidentAlerts always has, so the existing clean-skip
// behavior for that case is unchanged.
func (s *Skill) loadLegacyClaimAlerts(ctx context.Context, claim situation.TriageAttemptClaim) ([]store.Alert, error) {
	alerts, err := s.st.GetIncidentAlerts(ctx, claim.IncidentID)
	if err != nil {
		return nil, fmt.Errorf("acutetriage: analyze: load legacy incident alerts (empty frozen delivery set): %w", err)
	}
	return alerts, nil
}

// dedupeFrozenAlerts collapses one AlertDelivery per Alert.ID. A claimed
// attempt's MemberDeliveryIDs is a bounded set of DELIVERY identities, not
// Alert identities: the same Alert can have re-fired more than once while
// its Incident was still collecting (each re-fire is a fresh alert_deliveries
// row sharing the same alert_id), producing more than one frozen delivery
// for the same underlying alert before any claim ever froze it. Analyze's
// rules/evidence/prompt code has always operated on one entry per member
// Alert (GetIncidentAlerts' own contract — every downstream call in this
// package's analyzeCore chain assumes that shape, e.g. len(alerts) driving
// the min-alert-count/prompt-template decision), so this reduces the frozen
// delivery set back down to it: for each Alert ID, the delivery with the
// latest ReceivedAt among the FROZEN set wins (the most current state the
// claim itself actually saw — never a later, unfrozen mutation outside that
// set), ties broken by delivery ID for determinism; the output preserves
// each Alert's first-seen order, mirroring GetIncidentAlerts' own "in the
// order they were added" contract.
func dedupeFrozenAlerts(deliveries []store.AlertDelivery) []store.Alert {
	if len(deliveries) == 0 {
		return nil
	}
	type chosen struct {
		alert      store.Alert
		receivedAt time.Time
		deliveryID string
	}
	order := make([]string, 0, len(deliveries))
	best := make(map[string]chosen, len(deliveries))
	for _, d := range deliveries {
		id := d.Alert.ID
		cur, ok := best[id]
		if !ok {
			order = append(order, id)
		}
		if !ok || d.ReceivedAt.After(cur.receivedAt) ||
			(d.ReceivedAt.Equal(cur.receivedAt) && d.ID > cur.deliveryID) {
			best[id] = chosen{alert: d.Alert, receivedAt: d.ReceivedAt, deliveryID: d.ID}
		}
	}
	out := make([]store.Alert, len(order))
	for i, id := range order {
		out[i] = best[id].alert
	}
	return out
}

// AfterCommit performs best-effort compatibility memory/notifier/audit work
// for one AcuteResult, after the store's own completion transaction has
// already committed a success. Every sub-step is independently best-effort
// (mirroring the pre-Task-7 pipeline's own treatment of roles/memory/notify
// as never-fails-the-triage side effects): a failure in one step is logged
// and does not prevent the others from running. The aggregated error is
// returned so a caller MAY log/observe it, but it must never be treated as
// grounds to redo the attempt — the durable Finding already committed.
func (s *Skill) AfterCommit(ctx context.Context, result situation.AcuteResult) error {
	var errs []error

	for alertID, role := range result.AlertRoles {
		if err := s.st.SetAlertRole(ctx, result.IncidentID, alertID, role); err != nil {
			s.logger.Warn("acutetriage: after-commit: set alert role failed",
				"incident_id", result.IncidentID, "alert_id", alertID, "role", role, "err", err)
			errs = append(errs, err)
		}
	}

	for _, u := range result.PostCommit.MemoryUpdates {
		if err := s.applyPostCommitMemoryUpdate(ctx, u); err != nil {
			s.logger.Warn("acutetriage: after-commit: memory update failed",
				"incident_id", u.IncidentID, "operation", u.Operation, "err", err)
			errs = append(errs, err)
		}
	}

	if s.notifier != nil {
		if err := s.notifyFromPostCommit(ctx, result); err != nil {
			s.logger.Warn("acutetriage: after-commit: notify failed", "incident_id", result.IncidentID, "err", err)
			errs = append(errs, err)
		}
	}

	if s.auditor != nil {
		for _, rec := range result.PostCommit.AuditRecords {
			if err := s.auditor.Append(ctx, rec.Actor, rec.Kind, rec.Payload); err != nil {
				s.logger.Warn("acutetriage: after-commit: audit append failed",
					"incident_id", result.IncidentID, "kind", rec.Kind, "err", err)
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

// OnTriageExhausted implements situation.ExhaustionNotifier: TriageWorker's
// hook for a genuine attempt-schedule exhaustion (the final consecutive
// failed attempt), called only after the store's own exhaust write — AND
// TriageWorker's own incident.triage_exhausted audit append — have already
// happened (internal/situation/triage_worker.go's completeFailure/
// notifyExhaustion). Best-effort, exactly like every other AfterCommit-
// adjacent side effect: a failure here is logged, never treated as grounds
// to redo or re-notify the already durably exhausted attempt.
//
// Task 9 fix round 2: this method does NOT audit. It used to also append
// its own incident.triage_exhausted row here, which either double-emitted
// the event (when TriageWorker's own append was unconditional) or, after an
// intermediate fix made TriageWorker's append fallback-only, became the
// SOLE surviving row in every real deployment (which always configures this
// notifier) — and that row was missing situation_id/attempt_id/
// attempt_number/input_version, because this method's own signature
// (incidentID, code, detail — no attempt/situation identity at all) never
// receives them. TriageWorker holds the full identity via its
// TriageAttemptClaim and is now the row's single, unconditional owner; this
// method is left as a pure notification hook — currently the only remaining
// behavior is the notify.TriageFailureSink call below. s.notifier here
// reaches an operator only if it is (or contains, via notify.Multi) a sink
// implementing notify.TriageFailureSink; GroupKey/AlertCount are left
// zero-valued (TriageAttemptClaim carries neither) — a reasonable minimal
// implementation of the interface Task 7 commits to, not a claim of full
// parity with the old event's richer payload.
func (s *Skill) OnTriageExhausted(ctx context.Context, incidentID, code, detail string) error {
	if s.notifier == nil {
		return nil
	}
	sink, ok := s.notifier.(notify.TriageFailureSink)
	if !ok {
		return nil
	}
	ev := notify.TriageExhaustedEvent{IncidentID: incidentID, Error: code + ": " + detail}
	if err := sink.OnTriageExhausted(ctx, ev); err != nil {
		s.logger.Warn("acutetriage: triage exhausted notify failed", "incident_id", incidentID, "err", err)
		return err
	}
	return nil
}

func (s *Skill) applyPostCommitMemoryUpdate(ctx context.Context, u situation.MemoryUpdate) error {
	switch u.Operation {
	case memoryOpIncrementRefuteMarks:
		_, err := s.st.IncrementRefuteMarks(ctx, u.IncidentID)
		return err
	case memoryOpClearRefuteMarks:
		return s.st.ClearRefuteMarks(ctx, u.IncidentID)
	default:
		return fmt.Errorf("acutetriage: unknown post-commit memory operation %q", u.Operation)
	}
}

// notifyFromPostCommit rebuilds notify.Finding from the bounded JSON Analyze
// derived (everything computable without an outward call: name, root cause,
// correlation findings, severity, evidence summary, History/Steering) and
// fills in the three fields that only make sense at actual commit time —
// OutputJSON (from the AcuteResult itself, never re-derived), AnalyzedAt
// (now), and Status (a fresh resolvedStatusLabel read) — before calling the
// notifier exactly once.
func (s *Skill) notifyFromPostCommit(ctx context.Context, result situation.AcuteResult) error {
	var f notify.Finding
	if len(result.PostCommit.CompatibilityFindingJSON) > 0 {
		if err := json.Unmarshal(result.PostCommit.CompatibilityFindingJSON, &f); err != nil {
			return fmt.Errorf("acutetriage: unmarshal compatibility finding: %w", err)
		}
	} else {
		f.IncidentID = result.IncidentID
	}
	f.OutputJSON = result.OutputJSON
	f.AnalyzedAt = time.Now().UTC()
	f.Status = s.resolvedStatusLabel(ctx, result.IncidentID)
	return s.notifier.Notify(ctx, f)
}

// buildPostCommit assembles PostCommitData: the compatibility Finding JSON
// AfterCommit will later decode to call the notifier, the derived memory
// mark actions, and the sanitized audit records — everything Analyze can
// compute now but must not itself apply or send.
func (s *Skill) buildPostCommit(ctx context.Context, inc store.Incident, alerts []store.Alert, ta triageAnalysis) situation.PostCommitData {
	f := notify.Finding{
		IncidentID:                 inc.ID,
		GroupKey:                   inc.GroupKey,
		AnalysisName:               ta.resp.AnalysisName,
		OverallIssue:               ta.resp.OverallIssue,
		CorrelationFindings:        ta.resp.CorrelationFindings,
		Severity:                   ta.resp.Severity,
		Confidence:                 ta.resp.Confidence,
		AlertCount:                 inc.AlertCount,
		FirstAlertAt:               inc.FirstAlertAt,
		Drill:                      isDrill(alerts),
		Evidence:                   buildEvidenceSummary(ta.decision.ShortCircuit, ta.ar.metrics, ta.ar.logs, ta.ar.changes, ta.ar.sentry, ta.ar.zabbix),
		Unverified:                 ta.ver != nil && ta.ver.Outcome == verifyOutcomeDegraded,
		VerificationInvalidQueries: invalidQueryCount(ta.ver),
	}
	if ta.ver != nil {
		f.DegradationReason = ta.ver.DegradationReason
	}
	// Recurrence is deliberately left nil: Analyze only ever runs a first
	// (never re-judged) triage — the Plan 2 gated schedule's claim/complete
	// boundary has no re-judgment path (Rejudge stays on the pre-Plan-2
	// pipeline, untouched by this task).
	s.attachHistorySteering(ctx, inc, ta.ar, ta.ver, &f)

	findingJSON, err := json.Marshal(f)
	if err != nil {
		// f is this package's own closed DTO built entirely from bounded,
		// already-marshaled-once-before fields (notify.Finding's own JSON
		// tags already back its use elsewhere) — a marshal failure here is
		// a programming-time invariant violation, not a runtime condition.
		// Log and ship an empty compatibility Finding rather than fail the
		// whole attempt over a notify-only payload.
		s.logger.Error("acutetriage: marshal compatibility finding failed", "incident_id", inc.ID, "err", err)
		findingJSON = nil
	}

	return situation.PostCommitData{
		CompatibilityFindingJSON: findingJSON,
		MemoryUpdates:            deriveMemoryUpdates(ta.ar.memory, ta.resp.MemoryVerdict),
		AuditRecords:             buildPostCommitAuditRecords(inc, ta),
	}
}

// buildPostCommitAuditRecords mirrors the pre-Task-7 pipeline's own terminal
// audit trail exactly: one incident.analyzed row (analysis_name/confidence,
// verification_outcome when a round ran, steering fields when a correction
// was governing), and — when a memory section was rendered — one
// incident.memory_recalled row, matching recordMemoryRecall's payload
// shape.
func buildPostCommitAuditRecords(inc store.Incident, ta triageAnalysis) []situation.AuditRecord {
	var records []situation.AuditRecord

	analyzed := map[string]any{
		"incident_id":   inc.ID,
		"analysis_name": ta.resp.AnalysisName,
		"confidence":    ta.resp.Confidence,
	}
	if ta.ver != nil {
		analyzed["verification_outcome"] = ta.ver.Outcome
	}
	steeringAuditFields(analyzed, ta.ar.memory, ta.ver)
	if b, err := json.Marshal(analyzed); err == nil {
		records = append(records, situation.AuditRecord{Actor: "skill:acute-triage", Kind: "incident.analyzed", Payload: b})
	}

	if rec := memoryRecallAuditRecord(inc.ID, ta.ar.memory, ta.resp.MemoryVerdict); rec != nil {
		records = append(records, *rec)
	}
	return records
}

// memoryRecallAuditRecord mirrors recordMemoryRecall's own audit payload
// exactly (skills/acutetriage/memory.go) — fires whenever a memory section
// was rendered (memory != nil), independent of whether memory.Strong is set
// (the mark-routing MemoryUpdate below requires memory.Strong; the audit
// trail entry does not).
func memoryRecallAuditRecord(incidentID string, memory *MemoryEnrichment, verdict string) *situation.AuditRecord {
	if memory == nil {
		return nil
	}
	effective, note := verdict, ""
	switch {
	case verdict == "":
		effective, note = "silent", "absent"
	case !validMemoryVerdicts[verdict]:
		effective, note = "silent", "invalid"
	}
	payload := map[string]any{
		"incident_id":  incidentID,
		"rung":         memory.Rung,
		"folded_count": memory.Episodes,
		"verdict":      effective,
	}
	if note != "" {
		payload["verdict_note"] = note
	}
	if memory.Strong != nil {
		payload["recalled"] = memory.Strong.IncidentID
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return &situation.AuditRecord{Actor: "skill:acute-triage", Kind: "incident.memory_recalled", Payload: b}
}

// deriveMemoryUpdates mirrors recordMemoryRecall's own mark-routing exactly
// (skills/acutetriage/memory.go): refutes increments the recalled prior's
// contradiction marks (demoting at the threshold), confirms clears them.
// Both require memory.Strong (the folded exact-key recall) — a weak-only or
// operator-only memory section never routes a mark, matching
// recordMemoryRecall's own `if memory.Strong != nil` gate.
func deriveMemoryUpdates(memory *MemoryEnrichment, verdict string) []situation.MemoryUpdate {
	if memory == nil || memory.Strong == nil {
		return nil
	}
	effective := verdict
	if effective == "" || !validMemoryVerdicts[effective] {
		effective = "silent"
	}
	switch effective {
	case "refutes":
		return []situation.MemoryUpdate{{IncidentID: memory.Strong.IncidentID, Operation: memoryOpIncrementRefuteMarks}}
	case "confirms":
		return []situation.MemoryUpdate{{IncidentID: memory.Strong.IncidentID, Operation: memoryOpClearRefuteMarks}}
	default:
		return nil
	}
}

// computeAlertRoles mirrors the pre-Task-7 pipeline's own itemized/defaulted
// role assignment exactly (skill.go's inline loop + defaultUnitemizedRoles),
// but as a pure computation rather than two separate store writes: itemized
// alerts (the model's own per-alert call) always win; every other member
// alert defaults to "correlated" unless the finding was a rule short-circuit
// (whose synthesized response already itemizes every member, per
// shortCircuitResponse). AfterCommit applies every entry with an
// unconditional SetAlertRole — safe here (unlike defaultUnitemizedRoles'
// own use of SetAlertRoleIfUnset for a re-judgment) because Analyze/
// AfterCommit only ever run a FIRST triage: there is no prior role on this
// Incident to downgrade. See the Task 7 report.
func computeAlertRoles(alerts []store.Alert, itemized []alertOutput, shortCircuit bool) map[string]string {
	roles := make(map[string]string, len(alerts))
	for _, ao := range itemized {
		roles[ao.AlertID] = ao.RoleInIncident
	}
	if !shortCircuit {
		for _, a := range alerts {
			if _, ok := roles[a.ID]; !ok {
				roles[a.ID] = defaultUnitemizedRole
			}
		}
	}
	return roles
}

// evidencePackDigestOf hashes the marshaled evidence pack Analyze built for
// this attempt — "sha256:<hex>", the same digest convention
// internal/store's own canonicalDigest uses for Task 6's attempt ledger.
func evidencePackDigestOf(packJSON []byte) string {
	sum := sha256.Sum256(packJSON)
	return "sha256:" + hex.EncodeToString(sum[:])
}
