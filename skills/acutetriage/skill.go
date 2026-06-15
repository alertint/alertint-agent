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
	"github.com/alertint/alertint-agent/internal/notify"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
)

// LLMClient is the interface the skill uses to call the model. The real
// implementation is llm.Client; tests inject a fake.
type LLMClient interface {
	Complete(ctx context.Context, system, user string, requiredKeys []string) (json.RawMessage, error)
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
	s.logger.Info("acutetriage: starting", "incident_id", inc.ID, "alert_count", inc.AlertCount)

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
		minAlerts = 2 // Default: require at least 2 alerts
	}
	if len(alerts) < minAlerts {
		s.logger.Info("acutetriage: skipping analysis - insufficient alerts",
			"incident_id", inc.ID,
			"alert_count", len(alerts),
			"min_required", minAlerts,
			"group_key", inc.GroupKey,
		)
		return nil
	}

	// 2. Evaluate the rule engine: it may pick a specialized analysis
	// template or short-circuit the LLM entirely for known issues.
	decision := s.cfg.Rules.EvaluateIncident(alerts)
	if decision.Rule != nil {
		s.logger.Info("acutetriage: rule matched",
			"incident_id", inc.ID,
			"rule_id", decision.Rule.ID,
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
	// from the LLM with the pack-selected system prompt.
	raw, err := s.analysis(ctx, inc, alerts, decision, pack, packJSON)
	if err != nil {
		return err
	}

	// 6. Parse response.
	var resp llmResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("acutetriage: parse llm response: %w", err)
	}
	clampConfidence(&resp.Confidence)

	// 6. Persist output.
	outputJSON := string(raw)
	if err := s.st.SaveIncidentOutput(ctx,
		inc.ID, outputJSON,
		resp.AnalysisName, resp.OverallIssue,
		resp.Confidence,
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
			s.logger.Info("acutetriage: incident resolved - all alerts recovered", "incident_id", inc.ID, "alert_count", len(incAlerts))
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
		if notifyErr := s.notifier.Notify(ctx, f); notifyErr != nil {
			s.logger.Warn("acutetriage: notify failed", "incident_id", inc.ID, "err", notifyErr)
		}
	}

	// 9. Audit: incident analyzed.
	if s.auditor != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analyzed", map[string]any{
			"incident_id":   inc.ID,
			"analysis_name": resp.AnalysisName,
			"confidence":    resp.Confidence,
		})
	}

	s.logger.Info("acutetriage: done",
		"incident_id", inc.ID,
		"analysis_name", resp.AnalysisName,
		"confidence", resp.Confidence,
	)
	return nil
}

// analysis produces the raw finding JSON, either synthesized from a
// matched known-issue rule (short-circuit, no LLM call) or from the LLM
// with the pack-selected system prompt.
func (s *Skill) analysis(ctx context.Context, inc store.Incident, alerts []store.Alert, decision rules.Decision, pack EvidencePack, packJSON []byte) (json.RawMessage, error) {
	if decision.ShortCircuit {
		raw, err := shortCircuitResponse(decision, alerts)
		if err != nil {
			return nil, fmt.Errorf("acutetriage: short-circuit response: %w", err)
		}
		if s.auditor != nil {
			_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.short_circuited", map[string]any{
				"incident_id": inc.ID,
				"rule_id":     decision.Rule.ID,
			})
		}
		return raw, nil
	}

	metrics := FetchMetrics(ctx, s.cfg.Prometheus, alerts, inc.FirstAlertAt)
	userPrompt := UserPrompt(pack, string(packJSON), metrics)
	raw, err := s.llm.Complete(ctx, s.systemPrompt(decision, len(alerts)), userPrompt, RequiredKeys)
	if err != nil {
		s.logger.Error("acutetriage: llm failed", "incident_id", inc.ID, "err", err)
		if s.auditor != nil {
			_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analysis_failed", map[string]any{
				"incident_id": inc.ID,
				"error":       err.Error(),
			})
		}
		return nil, fmt.Errorf("acutetriage: llm: %w", err)
	}
	return raw, nil
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

func clampConfidence(c *float64) {
	if *c < 0 {
		*c = 0
	}
	if *c > 1 {
		*c = 1
	}
}
