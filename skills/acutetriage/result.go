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
// Known gap (flagged, not silently patched — see the Task 7 report for the
// full investigation): claim.MemberDeliveryIDs freezes delivery identities
// from the NEW internal/situation ledger (alert_deliveries/
// incident_alert_deliveries, Task 4/6), but this method loads Alert data via
// the EXISTING GetIncidentAlerts(claim.IncidentID) — the legacy alerts/
// incident_alerts tables the whole Acute Triage pipeline has always read.
// There is no store method to load Alert records scoped to a specific
// bounded delivery/alert id set, and this task's Files list does not
// authorize adding one to internal/store. In practice both tables are
// written together by the same correlation write path, so this rarely
// diverges; when it does (a race between claim time and this read), the
// store's own CompleteIncidentTriageAttempt digest fence — not this method
// — is what actually protects durable state: a membership drift in that
// window surfaces as a stale_membership/stale_incident_input completion,
// never a corrupted Finding.
func (s *Skill) Analyze(ctx context.Context, claim situation.TriageAttemptClaim) (situation.AcuteResult, error) {
	inc, err := s.st.GetIncidentByID(ctx, claim.IncidentID)
	if err != nil {
		return situation.AcuteResult{}, fmt.Errorf("acutetriage: analyze: load incident: %w", err)
	}
	if inc == nil {
		return situation.AcuteResult{}, fmt.Errorf("acutetriage: analyze: incident %s: %w", claim.IncidentID, store.ErrNotFound)
	}

	alerts, err := s.st.GetIncidentAlerts(ctx, inc.ID)
	if err != nil {
		return situation.AcuteResult{}, fmt.Errorf("acutetriage: analyze: load alerts: %w", err)
	}
	if len(alerts) == 0 {
		s.logger.Warn("acutetriage: incident has no member alerts; skipping", "incident_id", inc.ID)
		return situation.AcuteResult{}, ErrCleanSkip
	}
	minAlerts := s.cfg.MinAlerts
	if minAlerts <= 0 {
		minAlerts = 1 // Default: a lone first alert still produces a finding.
	}
	if len(alerts) < minAlerts {
		s.logger.Info("triage skipped",
			"incident", inc.ID, "alerts", len(alerts), "min_required", minAlerts, "group", inc.GroupKey)
		return situation.AcuteResult{}, ErrCleanSkip
	}

	ta, err := s.analyzeCore(ctx, *inc, alerts, false, "", inc.FirstAlertAt, "", nil)
	if err != nil {
		return situation.AcuteResult{}, err
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
	result.PostCommit = s.buildPostCommit(ctx, *inc, alerts, ta)
	return result, nil
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
