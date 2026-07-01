// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/notify"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
)

// LLMClient is the interface the skill uses to call the model. The real
// implementation is anthropic.Client; tests inject a fake. Complete returns a
// llm.Completion (raw JSON plus model/token/latency usage) so the skill can emit
// its own "llm responded" action-trail line — the incident-aware caller owns
// that line, not the read-only client (ADR 0004).
type LLMClient interface {
	Complete(ctx context.Context, system, user string, requiredKeys []string) (llm.Completion, error)
}

// Config holds skill tunables.
type Config struct {
	// WindowSeconds is forwarded into the evidence pack for context.
	WindowSeconds int
	// MinAlerts is the minimum number of alerts required to trigger LLM analysis.
	// Incidents with fewer alerts are logged but not analyzed.
	MinAlerts int
	// Prometheus is an optional read-only client used to enrich the LLM prompt
	// with live metric values at incident time. nil = no metric enrichment.
	Prometheus *promclient.Client
	// Rules is the rule engine. It selects the analysis prompt template
	// (storm / single_alert / correlated) and can short-circuit the LLM
	// for known-issue rules. nil = built-in correlated prompt only.
	Rules *rules.Engine
	// LogSource is an optional read-only log backend used to enrich the LLM
	// prompt with recent log lines at incident time. nil = no log enrichment.
	LogSource logs.Source
	// LogParams carries the generic enrichment tunables (window, timeout, line
	// limit) from the logs config section.
	LogParams LogParams
	// ChangeParams carries the change-enrichment tunables (enabled, window,
	// max_events) from the changes.enrichment config section.
	ChangeParams ChangeParams
	// Sentry is an optional read-only Sentry Error source used to enrich the
	// LLM prompt with the distilled issue section at incident time. nil = no
	// Sentry enrichment (the consumer owns the field it reads; serve wiring
	// assigns it). Pass a TRUE nil interface when unconfigured to avoid the
	// typed-nil trap.
	Sentry SentryReader
	// SentryParams carries the Error-source tunables (enabled, lookback,
	// max_issues, fetch timeout, message toggle) from the sentry.issues section.
	SentryParams SentryParams
}

// Skill orchestrates the full acute-triage pipeline for a single ready
// incident: load → build evidence → call LLM → persist → notify → audit.
type Skill struct {
	cfg      Config
	st       *store.Store
	llm      LLMClient
	auditor  *audit.Auditor
	notifier notify.Notifier
	logger   *slog.Logger
}

// New constructs a Skill. notifier may be nil (notifications skipped).
func New(cfg Config, st *store.Store, llmClient LLMClient, auditor *audit.Auditor, notifier notify.Notifier, logger *slog.Logger) *Skill {
	if logger == nil {
		logger = slog.Default()
	}
	return &Skill{
		cfg:      cfg,
		st:       st,
		llm:      llmClient,
		auditor:  auditor,
		notifier: notifier,
		logger:   logger,
	}
}

// llmResponse is the expected shape of the model's JSON output.
type llmResponse struct {
	AnalysisName        string        `json:"analysis_name"`
	OverallIssue        string        `json:"overall_issue"`
	CorrelationFindings []string      `json:"correlation_findings"`
	Severity            string        `json:"severity"`
	Confidence          float64       `json:"confidence"`
	Alerts              []alertOutput `json:"alerts"`
}

type alertOutput struct {
	AlertID        string `json:"alert_id"`
	RoleInIncident string `json:"role_in_incident"`
}

// Run executes the full triage pipeline for the given incident.
// It is safe to call from the IncidentSink goroutine.
func (s *Skill) Run(ctx context.Context, inc store.Incident) error {
	start := time.Now()
	s.logger.Info("triage started", "incident", inc.ID, "alerts", inc.AlertCount)

	// 1. Load member alerts.
	alerts, err := s.st.GetIncidentAlerts(ctx, inc.ID)
	if err != nil {
		return fmt.Errorf("acutetriage: load alerts: %w", err)
	}
	if len(alerts) == 0 {
		s.logger.Warn("acutetriage: incident has no member alerts; skipping", "incident_id", inc.ID)
		return nil
	}

	// Check minimum alert threshold.
	minAlerts := s.cfg.MinAlerts
	if minAlerts <= 0 {
		minAlerts = 1 // Default: a lone first alert still produces a finding
	}
	if len(alerts) < minAlerts {
		s.logger.Info("triage skipped",
			"incident", inc.ID,
			"alerts", len(alerts),
			"min_required", minAlerts,
			"group", inc.GroupKey,
		)
		return nil
	}

	// 2. Evaluate the rule engine: it may pick a specialized analysis
	// template or short-circuit the LLM entirely for known issues.
	decision := s.cfg.Rules.EvaluateIncident(alerts)
	if decision.Rule != nil {
		s.logger.Info("rule matched",
			"incident", inc.ID,
			"rule", decision.Rule.ID,
			"short_circuit", decision.ShortCircuit,
			"suppress", decision.Suppress,
		)
	}

	// 3. Build evidence pack and enrich with live Prometheus metrics.
	pack := BuildEvidencePack(inc, alerts, s.cfg.WindowSeconds)
	packJSON, err := json.Marshal(pack)
	if err != nil {
		return fmt.Errorf("acutetriage: marshal evidence pack: %w", err)
	}

	// 4. Audit: incident analysis started.
	if s.auditor != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analysis_started", map[string]any{
			"incident_id": inc.ID,
			"alert_count": len(alerts),
		})
	}

	// 5. Produce the analysis: from the matched rule (short-circuit) or
	// from the LLM with the pack-selected system prompt. enrichment is the
	// log snapshot the LLM saw (nil on the short-circuit path).
	raw, metrics, enrichment, changes, sentry, err := s.analysis(ctx, inc, alerts, decision, pack, packJSON)
	if err != nil {
		return err
	}

	// 6. Parse response.
	var resp llmResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("acutetriage: parse llm response: %w", err)
	}
	clampConfidence(&resp.Confidence)
	s.applyEvidenceCap(&resp, decision, metrics, enrichment, changes, sentry, inc.ID)

	// 6. Persist output, including the log-enrichment snapshot so the evidence
	// pack can replay exactly what the model saw (empty on the short-circuit /
	// logs-disabled path → stored NULL).
	outputJSON := string(raw)
	sources := map[string]any{}
	if enrichment != nil {
		sources["logs"] = enrichment
	}
	if changes != nil {
		sources["changes"] = changes
	}
	if sentry != nil {
		// Already distilled + toggle-applied in FetchSentry (KTD2/KTD8), so the
		// at-rest envelope never holds a raw frame or untoggled PII.
		sources["sentry"] = sentry
	}
	enrichmentJSON := marshalEnrichments(sources, s.logger, inc.ID)
	if err := s.st.SaveIncidentOutput(ctx,
		inc.ID, outputJSON,
		resp.AnalysisName, resp.OverallIssue,
		resp.Confidence, enrichmentJSON,
	); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("acutetriage: incident no longer in ready/processing state", "incident_id", inc.ID)
			return nil
		}
		return fmt.Errorf("acutetriage: save output: %w", err)
	}

	// 7. Update per-alert roles.
	for _, ao := range resp.Alerts {
		if err := s.st.SetAlertRole(ctx, inc.ID, ao.AlertID, ao.RoleInIncident); err != nil {
			s.logger.Warn("acutetriage: set alert role failed",
				"incident_id", inc.ID,
				"alert_id", ao.AlertID,
				"role", ao.RoleInIncident,
				"err", err,
			)
		}
	}

	// 8. Check if all alerts are resolved to determine incident status.
	incidentStatus := "ongoing"
	if incAlerts, err := s.st.GetIncidentAlerts(ctx, inc.ID); err == nil {
		allResolved := len(incAlerts) > 0
		for _, a := range incAlerts {
			if a.Status != "resolved" {
				allResolved = false
				break
			}
		}
		if allResolved {
			incidentStatus = "resolved"
			s.logger.Info("incident resolved", "incident", inc.ID, "alerts", len(incAlerts))
		}
	}

	// 9. Notify.
	if s.notifier != nil {
		f := notify.Finding{
			IncidentID:          inc.ID,
			GroupKey:            inc.GroupKey,
			AnalysisName:        resp.AnalysisName,
			OverallIssue:        resp.OverallIssue,
			CorrelationFindings: resp.CorrelationFindings,
			Severity:            resp.Severity,
			Confidence:          resp.Confidence,
			AlertCount:          inc.AlertCount,
			FirstAlertAt:        inc.FirstAlertAt,
			AnalyzedAt:          time.Now().UTC(),
			OutputJSON:          raw,
			Status:              incidentStatus,
		}
		// Multi owns the per-sink notify outcome line(s): a quiet "notified" on
		// success, a "notify partial"/"notify failed" summary plus one "notify
		// sink failed" detail line per failing sink. The aggregated error it
		// returns is already surfaced there, so we don't re-log it here.
		_ = s.notifier.Notify(ctx, f)
	}

	// 9. Audit: incident analyzed.
	if s.auditor != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analyzed", map[string]any{
			"incident_id":   inc.ID,
			"analysis_name": resp.AnalysisName,
			"confidence":    resp.Confidence,
		})
	}

	// 10. Audit: enrichment digest (when logs were attempted). A digest only —
	// source, query, and line count — never the log text, so the hash-chained
	// payload stays small.
	if s.auditor != nil && enrichment != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.enriched", map[string]any{
			"incident_id": inc.ID,
			"source":      enrichment.Source,
			"query":       enrichment.Query,
			"line_count":  len(enrichment.Lines),
		})
	}

	// Changes digest (when change enrichment was attempted): a count + matched
	// labels only, never change titles — keeps the hash-chained payload small.
	if s.auditor != nil && changes != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.changes_enriched", map[string]any{
			"incident_id":    inc.ID,
			"matched_labels": changes.MatchedLabels,
			"change_count":   len(changes.Changes),
		})
	}

	// Sentry digest (when the Error source was attempted): scope + issue count +
	// the reconciliation verdict (a fixed enum tag and an integer count) only —
	// never exception text, culprit, message, or file:line — keeps the hash-chained
	// payload small and PII-free (R16/KTD6). The digest fires for EVERY non-nil
	// enrichment, including the degraded / unknown-project paths where the verdict
	// is nil, so tag/count are read only when Reconciliation is present (a naive
	// deref would panic the triage goroutine on a routine rate-limit or 404).
	if s.auditor != nil && sentry != nil {
		tag, corroborating := reconciliationDigestFields(sentry)
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.sentry_enriched", map[string]any{
			"incident_id":   inc.ID,
			"project":       sentry.Project,
			"environment":   sentry.Environment,
			"issue_count":   len(sentry.Issues),
			"tag":           tag,
			"corroborating": corroborating,
		})
	}

	ruleID := "none"
	if decision.Rule != nil {
		ruleID = decision.Rule.ID
	}
	s.logger.Info("triage done",
		"incident", inc.ID,
		"severity", resp.Severity,
		"alerts", len(alerts),
		"rule", ruleID,
		"dur", time.Since(start),
	)
	return nil
}

// analysis produces the raw finding JSON, either synthesized from a
// matched known-issue rule (short-circuit, no LLM call) or from the LLM
// with the pack-selected system prompt. On the LLM path it also returns the
// metric and log-enrichment snapshots (nil on the short-circuit path) so the
// caller can persist exactly what the model saw and judge the evidence basis
// for the deterministic confidence cap.
func (s *Skill) analysis(ctx context.Context, inc store.Incident, alerts []store.Alert, decision rules.Decision, pack EvidencePack, packJSON []byte) (json.RawMessage, []MetricSnapshot, *LogEnrichment, *ChangeEnrichment, *SentryEnrichment, error) {
	if decision.ShortCircuit {
		raw, err := shortCircuitResponse(decision, alerts)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("acutetriage: short-circuit response: %w", err)
		}
		if s.auditor != nil {
			_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.short_circuited", map[string]any{
				"incident_id": inc.ID,
				"rule_id":     decision.Rule.ID,
			})
		}
		return raw, nil, nil, nil, nil, nil
	}

	metrics := FetchMetrics(ctx, s.cfg.Prometheus, alerts, inc.FirstAlertAt)
	// Best-effort log enrichment: never blocks or fails triage. end=now so a
	// still-firing incident captures the freshest lines around analysis time.
	enrichment := FetchLogs(ctx, s.cfg.LogSource, s.cfg.LogParams, alerts, inc.FirstAlertAt, time.Now().UTC(), inc.ID, s.logger)
	// Change enrichment reads local SQLite — reliable mid-incident, no timeout.
	changes := FetchChanges(ctx, s.st, s.cfg.ChangeParams, alerts, inc.FirstAlertAt, time.Now().UTC(), inc.ID, s.logger)
	// Sentry Error source: a bounded 1+K query-at-triage, best-effort, never blocks.
	sentry := FetchSentry(ctx, s.cfg.Sentry, s.cfg.SentryParams, alerts, inc.FirstAlertAt, time.Now().UTC(), inc.ID, s.logger)
	// Zero-LLM cross-source verdict, computed downstream of the rule engine at the
	// triage seam (KTD5/R3): sets sentry.Reconciliation in place on a conclusive
	// look, inert (no-op) when sentry is nil or the query was inconclusive.
	reconcile(sentry)
	userPrompt := UserPrompt(pack, string(packJSON), metrics, enrichment, changes, sentry)
	comp, err := s.llm.Complete(ctx, s.systemPrompt(decision, len(alerts)), userPrompt, RequiredKeys)
	if err != nil {
		s.logger.Error("llm failed", "incident", inc.ID, "err", err)
		if s.auditor != nil {
			_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analysis_failed", map[string]any{
				"incident_id": inc.ID,
				"error":       err.Error(),
			})
		}
		return nil, metrics, enrichment, changes, sentry, fmt.Errorf("acutetriage: llm: %w", err)
	}
	// Action-trail success line, sibling to "llm failed" above: emitted by the
	// incident-aware caller so it carries the incident ID and the usage the
	// client already computed for the audit log.
	s.logger.Info("llm responded",
		"model", comp.Model,
		"dur", comp.Latency,
		"tokens_in", comp.InputTokens,
		"tokens_out", comp.OutputTokens,
		"incident", inc.ID,
	)
	return comp.Raw, metrics, enrichment, changes, sentry, nil
}

// systemPrompt picks the analysis prompt: the rule-selected template when
// one matched, otherwise single_alert/correlated from the pack by alert
// count, falling back to the built-in prompt when no engine is wired.
func (s *Skill) systemPrompt(decision rules.Decision, alertCount int) string {
	name := decision.TemplateName
	if name == "" {
		if alertCount == 1 {
			name = "single_alert"
		} else {
			name = "correlated"
		}
	}
	if s.cfg.Rules != nil {
		if t, ok := s.cfg.Rules.Template(name); ok {
			return t
		}
		s.logger.Warn("acutetriage: prompt template not found in any pack; using built-in", "template", name)
	}
	return SystemPrompt
}

// shortCircuitResponse synthesizes the analysis JSON from a known-issue
// rule without calling the LLM. The shape matches llmResponse so the rest
// of the pipeline (persist, roles, notify) is identical.
func shortCircuitResponse(d rules.Decision, alerts []store.Alert) (json.RawMessage, error) {
	name := d.Rule.Description
	if name == "" {
		name = d.Rule.ID
	}
	severity := d.Rule.Then.Severity
	if severity == "" {
		severity = "medium"
	}
	findings := append([]string{"Matched known-issue rule " + d.Rule.ID}, d.References...)
	out := llmResponse{
		AnalysisName:        name,
		OverallIssue:        d.RootCauseHint,
		CorrelationFindings: findings,
		Severity:            severity,
		Confidence:          1.0,
		Alerts:              make([]alertOutput, 0, len(alerts)),
	}
	for _, a := range alerts {
		out.Alerts = append(out.Alerts, alertOutput{AlertID: a.ID, RoleInIncident: "correlated"})
	}
	return json.Marshal(out)
}

// marshalEnrichments serializes the keyed multi-source enrichment envelope for
// persistence: {"logs": {...}, "changes": {...}}. Callers add only non-nil
// sources. Returns "" when there is nothing to persist (all sources absent) or
// on a marshal error — both store SQL NULL, so the evidence pack omits the
// section. A marshal failure is logged but never blocks triage.
func marshalEnrichments(sources map[string]any, logger *slog.Logger, incidentID string) string {
	if len(sources) == 0 {
		return ""
	}
	b, err := json.Marshal(sources)
	if err != nil {
		logger.Warn("acutetriage: marshal enrichment envelope failed", "incident_id", incidentID, "err", err)
		return ""
	}
	return string(b)
}

// applyEvidenceCap is the deterministic calibration backstop: the prompt-side
// rule (renderEvidenceBasis) asks the model to keep annotations-only confidence
// at or below maxMetadataOnlyConfidence; this guarantees it regardless of model
// compliance. Short-circuit findings are exempt — they carry rule evidence, not
// model judgment. The persisted output_json keeps the model's original number;
// the incident row and every notification carry the capped one.
func (s *Skill) applyEvidenceCap(resp *llmResponse, decision rules.Decision, metrics []MetricSnapshot, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment, incidentID string) {
	if decision.ShortCircuit || hasLiveEvidence(metrics, logs, changes, sentry) ||
		resp.Confidence <= maxMetadataOnlyConfidence {
		return
	}
	s.logger.Info("confidence capped: annotations-only evidence basis",
		"incident", incidentID,
		"model_confidence", resp.Confidence,
		"capped_to", maxMetadataOnlyConfidence,
	)
	resp.Confidence = maxMetadataOnlyConfidence
}

func clampConfidence(c *float64) {
	if *c < 0 {
		*c = 0
	}
	if *c > 1 {
		*c = 1
	}
}
