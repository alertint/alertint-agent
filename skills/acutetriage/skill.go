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
	"github.com/alertint/alertint-agent/internal/llm"
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
	Complete(ctx context.Context, system string, prompt llm.Prompt, requiredKeys []string) (llm.Completion, error)
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
	// Memory is the read-only recall surface (the store) used to inject prior
	// findings for a recurring key. nil = no recall (the consumer owns the field
	// it reads; serve wiring assigns *store.Store). Pass a TRUE nil interface
	// when unconfigured to avoid the typed-nil trap.
	Memory MemoryReader
	// MemoryParams carries the recall tunables (lookback) from the memory config
	// section. Recall is deterministic and default-on; there is no enable knob.
	MemoryParams MemoryParams
	// Classifier is the optional second (Haiku) LLM client for the M3 shadow
	// classifier — a small fuzzy "same underlying condition?" match on rung-3a
	// weak-signal recalls. nil disables it entirely (the serve wiring passes nil
	// unless the mode is shadow or on). Reuses the triage key + auditor.
	Classifier LLMClient
	// ClassifierMode is "off" | "shadow" | "on". Even with a Classifier wired,
	// "off" (or empty) makes no call — the belt to the nil client (AE7). "shadow"
	// audits the verdict while the recall render stays deterministic; "on" lets a
	// matched verdict tag the recall render.
	ClassifierMode string
	// ClassifierTimeout is the hard wall-clock cap on one classifier call. It is
	// applied as a context deadline in maybeClassify because the shared Anthropic
	// client retries 429/529 with backoff, so the per-request HTTP timeout alone
	// would not bound the total time the call sits on the triage-critical path.
	ClassifierTimeout time.Duration
	// MetricParams carries the metric-enrichment tunables (fetch deadline) from
	// the prometheus config section. Prometheus above is the client; this is the
	// single-deadline budget for the multi-scope fetch.
	MetricParams MetricParams
	// Verification carries the falsification-round tunables (ADR-0021/0022). When
	// Enabled, a non-short-circuit triage runs a floor + model-proposed
	// verification round after the draft verdict and re-judges it in a second LLM
	// call. The zero value (Enabled=false) is the kill switch: one call, no round,
	// prompt byte-identical to the pre-feature triage.
	Verification VerificationParams
	// PromptCaching marks whether the wired LLM provider supports
	// client-side prompt caching (anthropic: yes; openai-compatible: no —
	// SGLang/vLLM prefix-cache server-side instead). Gates both the
	// CachePrefix breakpoint marking and the cache-engagement WARN: on a
	// provider without client-side caching a zero cache read is normal,
	// and per-incident WARNs would teach operators to ignore a surface
	// whose principle is "silence is unambiguous".
	PromptCaching bool
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
	// MemoryVerdict is the model's confirms|refutes|silent judgment on the
	// recalled root cause. Soft-required: it is NOT in RequiredKeys (a missing
	// bookkeeping key must not abort a good triage), so absent/invalid is treated
	// as silent post-parse. Present only when a memory section was rendered.
	MemoryVerdict string `json:"memory_verdict,omitempty"`
}

type alertOutput struct {
	AlertID        string `json:"alert_id"`
	RoleInIncident string `json:"role_in_incident"`
}

// persistFunc writes a finding to an incident. SaveIncidentOutput (initial
// triage) and ReplaceIncidentOutput (re-judgment) share this signature, which
// is what lets Run and Rejudge reuse one pipeline.
type persistFunc func(ctx context.Context, incidentID, outputJSON, summary, rootCause string, confidence float64, enrichmentJSON string) error

// pipelineParams carry what differs between an initial triage and a
// re-judgment: the evidence-span anchor, the persist target, and (for a
// re-judgment) the recurrence prompt context and its trigger.
type pipelineParams struct {
	rejudge    bool
	trigger    string
	spanStart  time.Time
	recurrence string
	persist    persistFunc

	// recurrenceEpisodes / recurrenceLastSeen carry the live occurrence summary
	// so the Slack card shows "recurred ×N · last HH:MM" on a re-judgment edit.
	// Zero on an initial triage.
	recurrenceEpisodes int
	recurrenceLastSeen time.Time
}

// Run executes the full triage pipeline for a newly-ready incident.
// It is safe to call from the IncidentSink goroutine.
func (s *Skill) Run(ctx context.Context, inc store.Incident) error {
	s.logger.Info("triage started", "incident", inc.ID, "alerts", inc.AlertCount)

	alerts, err := s.st.GetIncidentAlerts(ctx, inc.ID)
	if err != nil {
		return fmt.Errorf("acutetriage: load alerts: %w", err)
	}
	if len(alerts) == 0 {
		s.logger.Warn("acutetriage: incident has no member alerts; skipping", "incident_id", inc.ID)
		return nil
	}

	// Minimum-alert threshold gates the initial triage only (a re-judgment
	// re-analyzes an incident that already cleared it).
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

	return s.pipeline(ctx, inc, alerts, pipelineParams{
		spanStart: inc.FirstAlertAt,
		persist:   s.st.SaveIncidentOutput,
	})
}

// Rejudge re-runs the full triage pipeline for an already-judged incident and
// replaces its finding in place (via ReplaceIncidentOutput), keeping the status
// untouched. It carries a recurrence context (occurrence count, cadence, span,
// annotation trajectory) into the prompt so the model judges the recurrence with
// its history, and anchors the evidence span on the first occurrence. A failure
// before persist leaves the prior finding standing and last_judged_at unreset —
// the correlator's next attach re-evaluates the trigger (bounded retry).
func (s *Skill) Rejudge(ctx context.Context, inc store.Incident, trigger string) error {
	s.logger.Info("re-judgment started", "incident", inc.ID, "trigger", trigger)

	alerts, err := s.st.GetIncidentAlerts(ctx, inc.ID)
	if err != nil {
		return fmt.Errorf("acutetriage: rejudge load alerts: %w", err)
	}
	if len(alerts) == 0 {
		s.logger.Warn("acutetriage: re-judgment incident has no member alerts; skipping", "incident_id", inc.ID)
		return nil
	}

	spanStart, recurrence, stats := s.buildRecurrenceContext(ctx, inc, trigger)
	return s.pipeline(ctx, inc, alerts, pipelineParams{
		rejudge:            true,
		trigger:            trigger,
		spanStart:          spanStart,
		recurrence:         recurrence,
		persist:            s.st.ReplaceIncidentOutput,
		recurrenceEpisodes: stats.Episodes(),
		recurrenceLastSeen: stats.LastSeen,
	})
}

// pipeline is the shared triage core: rules → evidence → LLM → persist → notify
// → audit. p selects the initial-triage vs re-judgment differences.
func (s *Skill) pipeline(ctx context.Context, inc store.Incident, alerts []store.Alert, p pipelineParams) error {
	start := time.Now()

	// Evaluate the rule engine: it may pick a specialized analysis template or
	// short-circuit the LLM entirely for known issues (correct and consistent on
	// a re-judgment too — a known-issue rule replacing an LLM finding).
	decision := s.cfg.Rules.EvaluateIncident(alerts)
	if decision.Rule != nil {
		s.logger.Info("rule matched",
			"incident", inc.ID,
			"rule", decision.Rule.ID,
			"short_circuit", decision.ShortCircuit,
			"suppress", decision.Suppress,
		)
	}

	pack := BuildEvidencePack(inc, alerts, s.cfg.WindowSeconds)
	packJSON, err := json.Marshal(pack)
	if err != nil {
		return fmt.Errorf("acutetriage: marshal evidence pack: %w", err)
	}

	if s.auditor != nil {
		started := map[string]any{"incident_id": inc.ID, "alert_count": len(alerts)}
		if p.rejudge {
			started["trigger"] = p.trigger
		}
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analysis_started", started)
	}

	// Produce the analysis: from the matched rule (short-circuit) or from the LLM
	// with the pack-selected system prompt, the span-anchored enrichments, and
	// (on a re-judgment) the recurrence context prepended.
	ar, err := s.analysis(ctx, inc, alerts, decision, pack, packJSON, p.spanStart, p.recurrence)
	if err != nil {
		return err
	}

	var resp llmResponse
	if err := json.Unmarshal(ar.raw, &resp); err != nil {
		return fmt.Errorf("acutetriage: parse llm response: %w", err)
	}
	clampConfidence(&resp.Confidence)

	// Verification round (ADR-0021/0022): after the draft verdict, run the floor +
	// model-proposed queries and re-judge in a second LLM call whose response
	// becomes the final finding. Skipped on the short-circuit path (rule evidence,
	// not model judgment) and when disabled (the kill switch — one call, no round).
	// A verification failure NEVER fails a triage the draft could otherwise ship:
	// verifyAndRejudge falls back to the draft on any call-2 error.
	finalRaw := ar.raw
	var ver *VerificationEnrichment
	if s.cfg.Verification.Enabled && !ar.shortCircuit {
		finalRaw, resp, ver = s.verifyAndRejudge(ctx, inc, alerts, ar, resp)
	}
	// applyEvidenceCap sees the verification enrichment; live verification PromQL
	// evidence lifts the annotations-only basis just like live metrics/logs do
	// (the call-1 prompt-side directive was rendered before the round existed, so
	// it passed nil — only this deterministic post-call cap sees verification).
	s.applyEvidenceCap(&resp, decision, ar.metrics, ar.logs, ar.changes, ar.sentry, ver, inc.ID)

	// Persist output, including the log-enrichment snapshot so the evidence pack
	// can replay exactly what the model saw (empty on the short-circuit /
	// logs-disabled path → stored NULL). On a verification round this is call 2's
	// finding (or the draft when call 2 was lost).
	outputJSON := string(finalRaw)
	enrichmentJSON := marshalEnrichments(enrichmentSources(ar, ver), s.logger, inc.ID)
	if err := p.persist(ctx,
		inc.ID, outputJSON,
		resp.AnalysisName, resp.OverallIssue,
		resp.Confidence, enrichmentJSON,
	); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("acutetriage: incident not in a persistable state; finding dropped",
				"incident_id", inc.ID, "rejudge", p.rejudge)
			return nil
		}
		return fmt.Errorf("acutetriage: save output: %w", err)
	}

	// Update per-alert roles.
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

	// Bounded itemization: the prompts ask the model to itemize at most
	// maxItemizedAlerts members (Task 2's templates); every member it omits
	// gets the neutral default role deterministically, so a storm-sized
	// incident still exposes a role on every alert over MCP. Skipped on the
	// short-circuit path — a rule finding carries no model itemization and
	// its members keep NULL roles, as before this change.
	if !ar.shortCircuit {
		s.defaultUnitemizedRoles(ctx, inc.ID, alerts, resp.Alerts)
	}

	// Memory bookkeeping (M2): maintain the contradiction-decay marks from the
	// model's verdict, reset on a replacement, and audit the recall. Best-effort —
	// a bookkeeping failure never fails a triage that already persisted its finding.
	s.applyMemoryBookkeeping(ctx, inc, ar.memory, resp.MemoryVerdict, p.rejudge)

	// Check if all alerts are resolved to determine the finding's status label.
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

	// Notify. On a re-judgment the finding flows the same gate — the Slack
	// notifier threads the reply on the existing card, or posts a new one if none.
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
			OutputJSON:          finalRaw,
			Status:              incidentStatus,
			Drill:               isDrill(alerts),
			Evidence:            buildEvidenceSummary(decision.ShortCircuit, ar.metrics, ar.logs, ar.changes, ar.sentry),
			// A degraded round (floor unfetchable, or call 2 lost) shipped without a
			// full falsification pass — card renderers surface a caveat off this.
			Unverified: ver != nil && ver.Outcome == verifyOutcomeDegraded,
		}
		if p.rejudge && p.recurrenceEpisodes > 1 && !p.recurrenceLastSeen.IsZero() {
			f.Recurrence = &notify.Recurrence{Episodes: p.recurrenceEpisodes, LastSeen: p.recurrenceLastSeen}
		}
		// Multi owns the per-sink notify outcome line(s): a quiet "notified" on
		// success, a "notify partial"/"notify failed" summary plus one "notify
		// sink failed" detail line per failing sink. The aggregated error it
		// returns is already surfaced there, so we don't re-log it here.
		_ = s.notifier.Notify(ctx, f)
	}

	// Audit: incident analyzed (carrying the trigger on a re-judgment and the
	// verification outcome — R11 — when the round ran; omitted entirely on the
	// short-circuit / disabled path rather than persisted as an empty string).
	if s.auditor != nil {
		analyzed := map[string]any{
			"incident_id":   inc.ID,
			"analysis_name": resp.AnalysisName,
			"confidence":    resp.Confidence,
		}
		if p.rejudge {
			analyzed["trigger"] = p.trigger
		}
		if ver != nil {
			analyzed["verification_outcome"] = ver.Outcome
		}
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analyzed", analyzed)
	}

	s.auditEnrichmentDigests(ctx, inc.ID, ar.metrics, ar.logs, ar.changes, ar.sentry)

	ruleID := "none"
	if decision.Rule != nil {
		ruleID = decision.Rule.ID
	}
	s.logger.Info("triage done",
		"incident", inc.ID,
		"severity", resp.Severity,
		"alerts", len(alerts),
		"rule", ruleID,
		"rejudge", p.rejudge,
		"dur", time.Since(start),
	)
	return nil
}

// auditEnrichmentDigests appends one hash-chained digest row per attempted
// enrichment source — metrics, logs, changes, Sentry. Each digest carries only
// counts/identifiers (selector, query, matched labels, reconciliation tag),
// never raw evidence text or metric values, keeping the payload small and
// PII-free (R4/R16/KTD6). A source contributes a row only when it was
// attempted (non-nil); a nil auditor makes every call a no-op.
func (s *Skill) auditEnrichmentDigests(ctx context.Context, incidentID string, metrics *MetricEnrichment, enrichment *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment) {
	if s.auditor == nil {
		return
	}
	if metrics != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.metrics_enriched", map[string]any{
			"incident_id":    incidentID,
			"selector":       metrics.Selector,
			"snapshot_count": len(metrics.Snapshots),
			"outcome":        string(metrics.Outcome),
		})
	}
	if enrichment != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.enriched", map[string]any{
			"incident_id": incidentID,
			"source":      enrichment.Source,
			"query":       enrichment.Query,
			"line_count":  len(enrichment.Lines),
		})
	}
	if changes != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.changes_enriched", map[string]any{
			"incident_id":    incidentID,
			"matched_labels": changes.MatchedLabels,
			"change_count":   len(changes.Changes),
		})
	}
	// Sentry fires for EVERY non-nil enrichment, including the degraded /
	// unknown-project paths where the verdict is nil, so tag/count are read only
	// when Reconciliation is present (a naive deref would panic the triage
	// goroutine on a routine rate-limit or 404).
	if sentry != nil {
		tag, corroborating := reconciliationDigestFields(sentry)
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.sentry_enriched", map[string]any{
			"incident_id":   incidentID,
			"project":       sentry.Project,
			"environment":   sentry.Environment,
			"issue_count":   len(sentry.Issues),
			"tag":           tag,
			"corroborating": corroborating,
		})
	}
}

// analysisResult carries everything the first analysis pass produced: the raw
// finding JSON, each enrichment snapshot (nil on the short-circuit path), and —
// for the LLM path — the exact system/user prompts sent, kept so the
// verification round can build the call-2 continuation on a byte-identical
// prefix. shortCircuit is true when the finding came from a matched known-issue
// rule (no LLM call, no verification).
type analysisResult struct {
	raw          json.RawMessage
	metrics      *MetricEnrichment
	logs         *LogEnrichment
	changes      *ChangeEnrichment
	sentry       *SentryEnrichment
	memory       *MemoryEnrichment
	system, user string // prompts, kept for the call-2 continuation
	shortCircuit bool
}

// analysis produces the raw finding JSON, either synthesized from a
// matched known-issue rule (short-circuit, no LLM call) or from the LLM
// with the pack-selected system prompt. On the LLM path it also returns the
// metric and log-enrichment snapshots (nil on the short-circuit path) so the
// caller can persist exactly what the model saw and judge the evidence basis
// for the deterministic confidence cap.
func (s *Skill) analysis(ctx context.Context, inc store.Incident, alerts []store.Alert, decision rules.Decision, pack EvidencePack, packJSON []byte, spanStart time.Time, recurrence string) (analysisResult, error) {
	if decision.ShortCircuit {
		raw, err := shortCircuitResponse(decision, alerts)
		if err != nil {
			return analysisResult{}, fmt.Errorf("acutetriage: short-circuit response: %w", err)
		}
		if s.auditor != nil {
			_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.short_circuited", map[string]any{
				"incident_id": inc.ID,
				"rule_id":     decision.Rule.ID,
			})
		}
		return analysisResult{raw: raw, shortCircuit: true}, nil
	}

	// spanStart anchors the enrichment window on the collapse span: the original
	// first_alert_at for an initial triage, the first occurrence for a
	// re-judgment (so metrics/logs cover the recurrence, not a stale window).
	// Prometheus is a concrete *promclient.Client (nil when disabled); promQuerier
	// yields a TRUE nil interface so FetchMetrics's nil check is not defeated by a
	// typed-nil. The verification round builds its querier the same way.
	metrics := FetchMetrics(ctx, s.promQuerier(), s.cfg.MetricParams, alerts, spanStart, inc.ID, s.logger)
	// Best-effort log enrichment: never blocks or fails triage. end=now so a
	// still-firing incident captures the freshest lines around analysis time.
	enrichment := FetchLogs(ctx, s.cfg.LogSource, s.cfg.LogParams, alerts, spanStart, time.Now().UTC(), inc.ID, s.logger)
	// Change enrichment reads local SQLite — reliable mid-incident, no timeout.
	changes := FetchChanges(ctx, s.st, s.cfg.ChangeParams, alerts, spanStart, time.Now().UTC(), inc.ID, s.logger)
	// Sentry Error source: a bounded 1+K query-at-triage, best-effort, never blocks.
	sentry := FetchSentry(ctx, s.cfg.Sentry, s.cfg.SentryParams, alerts, spanStart, time.Now().UTC(), inc.ID, s.logger)
	// Zero-LLM cross-source verdict, computed downstream of the rule engine at the
	// triage seam (KTD5/R3): sets sentry.Reconciliation in place on a conclusive
	// look, inert (no-op) when sentry is nil or the query was inconclusive.
	reconcile(sentry)
	// Recall prior findings for this key (rung-2 exact + rung-3a prefilter). A
	// local store read, best-effort: a miss/err yields nil and the prompt is
	// byte-identical to a non-memory triage. Never passed to hasLiveEvidence or
	// the confidence cap — memory is context, never live evidence (R18).
	memory := FetchMemory(ctx, s.cfg.Memory, s.cfg.MemoryParams, inc, isDrill(alerts), time.Now().UTC())
	// Disposition-lite: when a recalled finding carries corroborating Sentry issue
	// ids, one bounded status read renders the regression/known-tolerated
	// transition. Best-effort, fail-safe — never blocks the recall.
	applyDisposition(ctx, s.cfg.Sentry, s.cfg.SentryParams, memory)
	// Shadow classifier (M3): judge the top rung-3a weak candidate. Runs before the
	// prompt is rendered so an `on`-mode match both tags what the model sees and is
	// captured by persist-as-rendered; in `shadow` mode it only audits and leaves
	// the render byte-identical. A no-op when disabled or there are no candidates.
	s.maybeClassify(ctx, inc, memory)
	userPrompt := UserPrompt(pack, string(packJSON), metrics, enrichment, changes, sentry, memory, s.cfg.Verification)
	// On a re-judgment, prepend the deterministic recurrence context so the model
	// judges the recurrence with its history rather than as a first-time event.
	if recurrence != "" {
		userPrompt = recurrence + "\n\n" + userPrompt
	}
	system := s.systemPrompt(decision, len(alerts))
	comp, err := s.llm.Complete(ctx, system, llm.Prompt{
		Prefix:      userPrompt,
		CachePrefix: s.cfg.Verification.Enabled && s.cfg.PromptCaching,
	}, RequiredKeys)
	if err != nil {
		s.logger.Error("llm failed", "incident", inc.ID, "err", err)
		if s.auditor != nil {
			_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analysis_failed", map[string]any{
				"incident_id": inc.ID,
				"error":       err.Error(),
			})
		}
		return analysisResult{}, fmt.Errorf("acutetriage: llm: %w", err)
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
	return analysisResult{
		raw:     comp.Raw,
		metrics: metrics,
		logs:    enrichment,
		changes: changes,
		sentry:  sentry,
		memory:  memory,
		system:  system,
		user:    userPrompt,
	}, nil
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

// enrichmentSources collects the non-nil enrichment snapshots into the keyed
// envelope map persisted under enrichment_json. Each value is already the
// redaction-safe, persist-as-rendered form its producer emitted: FetchSentry
// distilled + toggle-applied the Sentry section (KTD2/KTD8, never a raw frame or
// untoggled PII); memoryView allowlisted the recall (only distilled prior-finding
// refs, never whole findings or raw labels_json, ADR-0001); verifyAndRejudge
// carries the executed round byte-identical to what call 2 saw (R8).
func enrichmentSources(ar analysisResult, ver *VerificationEnrichment) map[string]any {
	sources := map[string]any{}
	if ar.metrics != nil {
		sources["metrics"] = ar.metrics
	}
	if ar.logs != nil {
		sources["logs"] = ar.logs
	}
	if ar.changes != nil {
		sources["changes"] = ar.changes
	}
	if ar.sentry != nil {
		sources["sentry"] = ar.sentry
	}
	if ar.memory != nil {
		sources["memory"] = ar.memory
	}
	if ver != nil {
		sources["verification"] = ver
	}
	return sources
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
// at or below MaxMetadataOnlyConfidence; this guarantees it regardless of model
// compliance. Short-circuit findings are exempt — they carry rule evidence, not
// model judgment. The persisted output_json keeps the model's original number;
// the incident row and every notification carry the capped one.
func (s *Skill) applyEvidenceCap(resp *llmResponse, decision rules.Decision, metrics *MetricEnrichment, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment, ver *VerificationEnrichment, incidentID string) {
	if decision.ShortCircuit || !annotationsOnlyBasis(metrics, logs, changes, sentry, ver) ||
		resp.Confidence <= MaxMetadataOnlyConfidence {
		return
	}
	s.logger.Info("confidence capped: annotations-only evidence basis",
		"incident", incidentID,
		"model_confidence", resp.Confidence,
		"capped_to", MaxMetadataOnlyConfidence,
	)
	resp.Confidence = MaxMetadataOnlyConfidence
}

func clampConfidence(c *float64) {
	if *c < 0 {
		*c = 0
	}
	if *c > 1 {
		*c = 1
	}
}

// promQuerier returns the configured Prometheus client as a true-nil-safe
// metricQuerier: a nil *prometheus.Client yields a nil interface (not a typed
// nil), so the downstream nil checks in FetchMetrics and the verification runner
// hold. Both the analysis fetch and the verification round build their querier
// through here so they observe the same client (or the same true nil).
func (s *Skill) promQuerier() metricQuerier {
	var mq metricQuerier
	if s.cfg.Prometheus != nil {
		mq = s.cfg.Prometheus
	}
	return mq
}

// verifyAndRejudge runs one verification round on a non-short-circuit draft and
// re-judges it in a second LLM call (ADR-0021/0022). It returns the finding that
// should ship: on success, call 2's raw JSON + parsed response + the executed
// round; on ANY call-2 failure (LLM error, malformed JSON), the DRAFT unchanged
// with its memory verdict cleared, so a lost re-judge never fails a triage the
// draft could otherwise ship (the never-fails invariant) and never moves memory
// marks on stale grounds (R16). resp is the draft (already clamped).
func (s *Skill) verifyAndRejudge(ctx context.Context, inc store.Incident, alerts []store.Alert, ar analysisResult, resp llmResponse) (json.RawMessage, llmResponse, *VerificationEnrichment) {
	draft := DraftRef{RootCause: resp.OverallIssue, Confidence: resp.Confidence}
	modelQ := parseVerificationPlan(ar.raw, s.cfg.Verification.MaxQueries, s.logger, inc.ID)
	s.auditVerificationPlanned(ctx, inc, alerts, modelQ)

	// The runner shares the SAME true-nil-safe querier the analysis fetch used, and
	// the store as the incidents_in_window state reader. It never errors: a query's
	// own failure lands in its Outcome/Result, never aborting the round (R2).
	round := runVerification(ctx, s.promQuerier(), s.st, s.cfg.Verification, inc, alerts, draft, modelQ, time.Now().UTC(), s.logger)

	// Call 2: the byte-identical call-1 prefix + the draft + the computed round +
	// the (moved) memory-verdict request. On any failure the draft stands.
	comp, err := s.llm.Complete(ctx, ar.system, llm.Prompt{
		Prefix:      ar.user,
		Suffix:      callTwoContinuation(ar.raw, round, ar.memory),
		CachePrefix: s.cfg.PromptCaching,
	}, RequiredKeys)
	if err != nil {
		s.logger.Warn("acutetriage: verification re-judge failed; draft stands", "incident", inc.ID, "err", err)
		return s.degradedDraft(ctx, inc.ID, ar.raw, round, resp)
	}
	// Cache-engagement probe: call 2 always marks the shared prefix, so a zero
	// cache read means the prefix is below the model's cacheable floor (benign,
	// permanent on small models) or the prefix drifted (a regression). The two
	// are indistinguishable here, so this stays a per-pair WARN — never
	// once-then-quiet — and floors are asserted nowhere (they drift per release).
	if s.cfg.PromptCaching && comp.CacheReadInputTokens == 0 {
		s.logger.Warn("acutetriage: verification call 2 read no cached prefix (prefix below the model's cacheable floor, or prefix drift)",
			"incident", inc.ID, "model", comp.Model, "prefix_chars", len(ar.user))
	}
	var resp2 llmResponse
	if err := json.Unmarshal(comp.Raw, &resp2); err != nil {
		// A malformed re-judge must not fail a triage that has a valid draft.
		s.logger.Warn("acutetriage: verification re-judge returned malformed JSON; draft stands", "incident", inc.ID, "err", err)
		return s.degradedDraft(ctx, inc.ID, ar.raw, round, resp)
	}
	clampConfidence(&resp2.Confidence)

	// Clamp rail (R15): a re-judge that leans on unfetched evidence must not raise
	// confidence above the draft — the missing checks could have refuted it.
	clamped := false
	if anyUnfetched(round) && resp2.Confidence > draft.Confidence {
		s.logger.Info("acutetriage: verification clamp: unfetched evidence, holding re-judged confidence at draft",
			"incident", inc.ID, "draft_confidence", draft.Confidence, "rejudged_confidence", resp2.Confidence)
		resp2.Confidence = draft.Confidence
		clamped = true
	}

	// Outcome: degraded when the floor could not fetch (the promised minimum did
	// not run); otherwise revised vs supported by whether the root-cause string
	// changed — crude but deterministic (no fuzzy diff on model prose).
	outcome := verifyOutcomeSupported
	switch {
	case !floorFetched(round):
		outcome = verifyOutcomeDegraded
	case resp2.OverallIssue != resp.OverallIssue:
		outcome = verifyOutcomeRevised
	}
	if outcome == verifyOutcomeDegraded {
		// R16: a degraded round (the promised floor minimum did not run) must
		// produce no verdict, even though call 2 itself succeeded and parsed
		// fine — otherwise a floor-failed-but-call-2-succeeded round would let
		// call 2's memory_verdict move contradiction marks on stale grounds.
		// The existing soft-required handling treats an empty verdict as
		// silent, so this is additive: it clears a field, it never fails the
		// triage or the round.
		resp2.MemoryVerdict = ""
	}
	s.auditVerificationExecuted(ctx, inc.ID, outcome, round, clamped)

	return comp.Raw, resp2, &VerificationEnrichment{Outcome: outcome, Rounds: []VerificationRound{*round}}
}

// degradedDraft is the shared call-2-failure return: the draft ships as final —
// its ORIGINAL bytes preserved (draftRaw, so the persisted output_json is the
// model's exact draft, verification-plan key and all) with its parsed verdict's
// memory mark cleared (R16 — a lost call 2 moves no marks), outcome degraded, and
// the executed round preserved for the envelope. It emits the
// verification_executed audit so every planned round has a matching executed row.
func (s *Skill) degradedDraft(ctx context.Context, incidentID string, draftRaw json.RawMessage, round *VerificationRound, draft llmResponse) (json.RawMessage, llmResponse, *VerificationEnrichment) {
	draft.MemoryVerdict = ""
	s.auditVerificationExecuted(ctx, incidentID, verifyOutcomeDegraded, round, false)
	return draftRaw, draft, &VerificationEnrichment{Outcome: verifyOutcomeDegraded, Rounds: []VerificationRound{*round}}
}

// auditVerificationPlanned records the plan before it runs: the model/floor query
// counts and each query's kind/source/why — never a metric value (R4/KTD6).
func (s *Skill) auditVerificationPlanned(ctx context.Context, inc store.Incident, alerts []store.Alert, modelQ []VerificationQuery) {
	if s.auditor == nil {
		return
	}
	plan := append(floorPlan(alerts), modelQ...)
	qs := make([]map[string]string, 0, len(plan))
	for _, q := range plan {
		qs = append(qs, map[string]string{"kind": q.Kind, "source": q.Source, "why": q.Why})
	}
	_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.verification_planned", map[string]any{
		"incident_id":       inc.ID,
		"model_query_count": len(modelQ),
		"floor_query_count": 2,
		"queries":           qs,
	})
}

// auditVerificationExecuted records the round result: outcome, fetched/failed
// query counts (an empty answer counts as fetched — "asked, nothing there"), and
// whether the confidence clamp fired. No metric values.
func (s *Skill) auditVerificationExecuted(ctx context.Context, incidentID, outcome string, round *VerificationRound, clamped bool) {
	if s.auditor == nil {
		return
	}
	var fetched, failed int
	for _, q := range round.Queries {
		switch q.Outcome {
		case OutcomeFetched, OutcomeEmpty:
			fetched++
		case OutcomeFailed, OutcomeDegraded:
			failed++
		case OutcomeNoSelector:
			// Metric-enrichment-only outcome; never set on a verification query.
		}
	}
	_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.verification_executed", map[string]any{
		"incident_id": incidentID,
		"outcome":     outcome,
		"fetched":     fetched,
		"failed":      failed,
		"clamped":     clamped,
	})
}

// defaultUnitemizedRole is what an alert omitted from the model's capped
// alerts array is recorded as. The prompt rule (packs/baseline/templates/*,
// SystemPrompt) tells the model omission means exactly this, so omission is
// itself the model's judgment — never an unknown.
const defaultUnitemizedRole = "correlated"

// defaultUnitemizedRoles writes defaultUnitemizedRole for every member alert
// absent from the model's itemized alerts array. Uses SetAlertRoleIfUnset, not
// SetAlertRole: on a re-judgment, the current call's (independently capped)
// itemization omitting an alert is not a fresh "correlated" verdict, so it
// must never downgrade a role a PRIOR call explicitly assigned (e.g.
// "primary") — only NULL or already-"correlated" rows are written. Best-effort
// per alert (a single failed write logs and moves on, mirroring the itemized
// loop above); the total defaulted count is logged so the cap is never silent.
func (s *Skill) defaultUnitemizedRoles(ctx context.Context, incidentID string, members []store.Alert, itemized []alertOutput) {
	seen := make(map[string]struct{}, len(itemized))
	for _, ao := range itemized {
		seen[ao.AlertID] = struct{}{}
	}
	defaulted := 0
	for _, a := range members {
		if _, ok := seen[a.ID]; ok {
			continue
		}
		if err := s.st.SetAlertRoleIfUnset(ctx, incidentID, a.ID, defaultUnitemizedRole); err != nil {
			s.logger.Warn("acutetriage: default alert role failed",
				"incident_id", incidentID, "alert_id", a.ID, "err", err)
			continue
		}
		defaulted++
	}
	if defaulted > 0 {
		s.logger.Info("acutetriage: defaulted roles for un-itemized alerts",
			"incident_id", incidentID, "count", defaulted, "role", defaultUnitemizedRole)
	}
}

// isDrill reports whether any member alert carries the Drill-alert marker
// (ADR-0013). Any-not-all: a mixed incident stays flagged so a synthetic
// card never passes as fully real.
func isDrill(alerts []store.Alert) bool {
	for _, a := range alerts {
		if a.Labels[store.DrillMarkerLabel] == store.DrillMarkerValue {
			return true
		}
	}
	return false
}
