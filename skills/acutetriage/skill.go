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
	"github.com/alertint/alertint-agent/internal/llmhealth"
	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/notify"
	promclient "github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
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
	// Zabbix is the optional read-only Zabbix Source used to assemble the
	// Zabbix context at incident time. nil = no Zabbix enrichment. Pass a TRUE
	// nil interface when unconfigured to avoid the typed-nil trap.
	Zabbix ZabbixReader
	// ZabbixParams carries the zabbix.api tunables (timeout, host label, flap window).
	ZabbixParams ZabbixParams
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
	// Health, when non-nil, receives one final outcome per LLM call (transport,
	// schema, and typed-decode included) so installation-level LLM dependency
	// health reflects real inference. nil = no observation (tests, offline tools).
	Health *llmhealth.Tracker
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
	// OperatorRuling is the model's raw operator_ruling reply (ADR-0029),
	// captured as untyped JSON rather than a typed *modelRuling: a shape
	// mismatch (e.g. a bare string instead of the documented
	// {"ruling":...,"basis":...} object — plausibly the single most likely
	// real-world malformation) must never fail the unmarshal of the WHOLE
	// call-2 response, which would route a valid revised verdict through the
	// malformed-JSON/degraded path over one bad bookkeeping key. Soft-required
	// like memory_verdict: the lenient decode into modelRuling happens
	// entirely downstream, in verifyAndRejudge's ruling block — absent/
	// unparseable/invalid all collapse to the same "absent" record there, the
	// deterministic backstop clamps instead of failing triage.
	OperatorRuling json.RawMessage `json:"operator_ruling,omitempty"`
}

// modelRuling is the model's raw operator_ruling reply — shaped exactly like
// callTwoContinuation's demand, before it is validated into an
// OperatorRulingRecord.
type modelRuling struct {
	Ruling string `json:"ruling"`
	Basis  string `json:"basis"`
}

// validOperatorRulings is the closed enum for the soft-required
// operator_ruling — a ruling outside this set is treated the same as absent.
var validOperatorRulings = map[string]bool{"supported": true, "contradicted": true, "unverifiable": true}

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

	// replay, when non-nil, turns this run into a hermetic grading replay
	// (capture D8 stage 2): enrichment comes from the frozen envelope,
	// verification runs against the snapshot executor, and every side effect —
	// role writes, memory bookkeeping, the resolved-status probe — is skipped.
	// The auditor and notifier are already nil on the replaying Skill copy
	// (replayIncidentWith strips them), so pipeline/analysis audit and notify
	// guards need no extra branches.
	replay *replayRun
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
	ar, err := s.analysis(ctx, inc, alerts, decision, pack, packJSON, p.spanStart, p.recurrence, p.replay)
	if err != nil {
		return err
	}

	// ar.health.Finish persists with its own bounded context.Background() by
	// design: a triage_draft observation must never be dropped because ctx
	// was canceled between the LLM call returning and the decode finishing.
	var resp llmResponse
	if err := json.Unmarshal(ar.raw, &resp); err != nil {
		// One reason-bearing error for both consumers: the tracker observes
		// it, and the Correlator classifies the very same error for its
		// durable triage code — so /health and the retry row can never
		// disagree about why this attempt failed.
		malformed := fmt.Errorf("%w: %v", llmhealth.ErrResponseMalformed, err)
		ar.health.Finish(malformed) //nolint:contextcheck
		return fmt.Errorf("acutetriage: parse llm response: %w", malformed)
	}
	ar.health.Finish(nil) //nolint:contextcheck
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
		finalRaw, resp, ver = s.verifyAndRejudge(ctx, inc, alerts, ar, resp, p)
	}
	// applyEvidenceCap sees the verification enrichment; live verification PromQL
	// evidence lifts the annotations-only basis just like live metrics/logs do
	// (the call-1 prompt-side directive was rendered before the round existed, so
	// it passed nil — only this deterministic post-call cap sees verification).
	s.applyEvidenceCap(&resp, decision, ar.metrics, ar.logs, ar.changes, ar.sentry, ar.zabbix, ver, inc.ID)
	s.applySteeringCap(&resp, governingOf(ar.memory), ver, inc.ID)

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

	// Update per-alert roles. Skipped during a hermetic replay (p.replay != nil):
	// grading must persist nothing beyond the capture already written.
	if p.replay == nil {
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
	}

	// Memory bookkeeping (M2): maintain the contradiction-decay marks from the
	// model's verdict, reset on a replacement, and audit the recall. Best-effort —
	// a bookkeeping failure never fails a triage that already persisted its finding.
	// Skipped during replay: grading must move no marks on stale/replayed grounds.
	if p.replay == nil {
		s.applyMemoryBookkeeping(ctx, inc, ar.memory, resp.MemoryVerdict, p.rejudge)
	}

	// Notify. On a re-judgment the finding flows the same gate — the Slack
	// notifier threads the reply on the existing card, or posts a new one if none.
	// nil during replay (replayIncidentWith strips it), so this whole block —
	// including the resolution ownership claim — is a no-op there.
	incidentStatus, ownsNotification := "", false
	if s.notifier != nil {
		incidentStatus, ownsNotification = s.notificationStatus(ctx, inc.ID, inc.Status, p.rejudge)
	}
	if ownsNotification {
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
			Evidence:            buildEvidenceSummary(decision.ShortCircuit, ar.metrics, ar.logs, ar.changes, ar.sentry, ar.zabbix),
			// A degraded round (floor unfetchable, or call 2 lost) shipped without a
			// full falsification pass — card renderers surface a caveat off this.
			Unverified: ver != nil && ver.Outcome == verifyOutcomeDegraded,
			// VerificationInvalidQueries counts locally-invalid/backend-rejected
			// queries across every round — independent of Unverified, which only
			// reflects connector/round-level degradation.
			VerificationInvalidQueries: invalidQueryCount(ver),
		}
		if ver != nil {
			f.DegradationReason = ver.DegradationReason
		}
		if p.rejudge && p.recurrenceEpisodes > 1 && !p.recurrenceLastSeen.IsZero() {
			f.Recurrence = &notify.Recurrence{Episodes: p.recurrenceEpisodes, LastSeen: p.recurrenceLastSeen}
		}
		s.attachHistorySteering(ctx, inc, ar, ver, &f)
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
		steeringAuditFields(analyzed, ar.memory, ver)
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analyzed", analyzed)
	}

	s.auditEnrichmentDigests(ctx, inc.ID, ar.metrics, ar.logs, ar.changes, ar.sentry, ar.zabbix)

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

// attachHistorySteering populates f.History and f.Steering (Task 9, R13/D9,
// ADR-0029): the producer-computed payload behind the Slack history block and
// the ruling line — notifiers stay I/O-free renderers, this is the read.
// History is always attempted (tri-state honest — nil only when there's no
// store to read at all). Steering is set only when a governing correction is
// steering: from the verification round's own ruling when one ran, or
// directly as "unverifiable" when verification is disabled entirely and
// nothing ran to test it (that's distinct from a round that ran and the model
// left the ruling "absent" — call 2's own soft-parse default, remapped to the
// "unruled" wire value).
func (s *Skill) attachHistorySteering(ctx context.Context, inc store.Incident, ar analysisResult, ver *VerificationEnrichment, f *notify.Finding) {
	epi, first := 0, time.Time{}
	if ar.memory != nil {
		epi, first = ar.memory.Episodes, ar.memory.FirstSeen
	}
	lookback := s.cfg.MemoryParams.LookbackDays
	if lookback <= 0 {
		lookback = 90
	}
	f.History = BuildHistory(ctx, s.st, inc.GroupKey, inc.ID, f.Drill, epi, first, lookback, time.Now().UTC())

	if ver != nil && ver.OperatorRuling != nil {
		r := ver.OperatorRuling
		ruling, basis := r.Ruling, r.Basis
		if ruling == "absent" {
			ruling = "unruled"
		}
		// Presentation parity with the Task 8 backstop: an unbacked
		// supported/contradicted had no effect (the clamp treated it as
		// absent), so the card must not present the model's conclusion as a
		// tested outcome — "contradicted by absence of evidence" on a card is
		// exactly the epistemic error the ruling vocabulary exists to prevent.
		// The wire value "untested" renders the deterministic fact (the
		// correction's named evidence never fetched; confidence capped) and
		// drops the model's basis, which asserts a conclusion the machinery
		// rejected. The enrichment record keeps the raw ruling — this remap
		// is card/stdout payload only.
		if (ruling == "supported" || ruling == "contradicted") && !r.Backed {
			ruling, basis = "untested", ""
		}
		f.Steering = &notify.Steering{Ruling: ruling, Basis: basis, VerdictDate: r.VerdictDate}
		return
	}
	if g := governingOf(ar.memory); g != nil && g.Steers {
		// verification disabled: steering active, nothing ran (R5)
		f.Steering = &notify.Steering{Ruling: "unverifiable", VerdictDate: g.Date}
	}
}

// notificationStatus returns the finding status and whether this pipeline owns
// the notification. Initial triage must claim the same analyzed -> resolved
// transition as the correlator before publishing a resolved finding; losing
// that CAS means another path owns the resolution notification. A re-judgment
// also claims the transition when a recurrence reopened the incident, but an
// ErrNotFound still publishes its replacement finding because a re-judgment of
// an incident that was already resolved remains valid.
func (s *Skill) notificationStatus(ctx context.Context, incidentID, startingStatus string, rejudge bool) (string, bool) {
	incAlerts, err := s.st.GetIncidentAlerts(ctx, incidentID)
	if err != nil || len(incAlerts) == 0 {
		return "ongoing", true
	}
	for _, a := range incAlerts {
		if a.Status != "resolved" {
			return "ongoing", true
		}
	}
	if err := s.st.MarkIncidentResolved(ctx, incidentID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if rejudge && startingStatus == "resolved" {
				return "resolved", true
			}
			s.logger.Info("incident resolution notification already claimed", "incident", incidentID)
			return "", false
		}
		s.logger.Warn("acutetriage: claim incident resolution failed; notifying as ongoing",
			"incident_id", incidentID,
			"err", err,
		)
		return "ongoing", true
	}
	s.logger.Info("incident resolved", "incident", incidentID, "alerts", len(incAlerts))
	return "resolved", true
}

// auditEnrichmentDigests appends one hash-chained digest row per attempted
// enrichment source — metrics, logs, changes, Sentry, Zabbix. Each digest
// carries only counts/identifiers (selector, query, matched labels,
// reconciliation tag), never raw evidence text or metric values, keeping the
// payload small and PII-free (R4/R16/KTD6). A source contributes a row only
// when it was attempted (non-nil); a nil auditor makes every call a no-op.
func (s *Skill) auditEnrichmentDigests(ctx context.Context, incidentID string, metrics *MetricEnrichment, enrichment *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment, zabbix *ZabbixContext) {
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
	if zabbix != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.zabbix_enriched", map[string]any{
			"incident_id": incidentID,
			"outcome":     string(zabbix.Outcome),
			"entry_count": zabbixEntryCount(zabbix),
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
	raw     json.RawMessage
	metrics *MetricEnrichment
	logs    *LogEnrichment
	changes *ChangeEnrichment
	sentry  *SentryEnrichment
	zabbix  *ZabbixContext
	// zabbixSeed carries FetchZabbixContext's raw per-host Topology fetch
	// forward to the verification round (verifyAndRejudge), which seeds its
	// zabbixVerifier's cache from it — avoids a redundant HostContext RPC for
	// a host this same triage invocation already resolved moments earlier.
	// Never persisted (only ar.zabbix's redacted view is); nil on the replay
	// path (no live fetch to seed from).
	zabbixSeed   map[string]zabbix.Topology
	memory       *MemoryEnrichment
	system, user string // prompts, kept for the call-2 continuation
	shortCircuit bool
	// health is the open triage_draft observation Call 1 started (nil on the
	// short-circuit path, or when Config.Health is nil). pipeline finishes it
	// once the typed decode either succeeds or fails.
	health *llmhealth.Observation
}

// analysis produces the raw finding JSON, either synthesized from a
// matched known-issue rule (short-circuit, no LLM call) or from the LLM
// with the pack-selected system prompt. On the LLM path it also returns the
// metric and log-enrichment snapshots (nil on the short-circuit path) so the
// caller can persist exactly what the model saw and judge the evidence basis
// for the deterministic confidence cap.
func (s *Skill) analysis(ctx context.Context, inc store.Incident, alerts []store.Alert, decision rules.Decision, pack EvidencePack, packJSON []byte, spanStart time.Time, recurrence string, replay *replayRun) (analysisResult, error) {
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
	var (
		metrics    *MetricEnrichment
		enrichment *LogEnrichment
		changes    *ChangeEnrichment
		sentry     *SentryEnrichment
		zbx        *ZabbixContext
		zbxSeed    map[string]zabbix.Topology
		memory     *MemoryEnrichment
	)
	if replay != nil {
		// Frozen inputs (persist-as-rendered envelope): no live fetch, no
		// reconcile/disposition/classifier — the sections replay exactly as the
		// original triage saw them; memory replays as-of-incident-time, so a
		// just-captured correction never grades its own capture green. No live
		// HostContext fetch happened, so there is nothing to seed (zbxSeed
		// stays nil) — the replayed verification round is a snapshot executor
		// anyway, never a live zabbixVerifier.
		metrics = replay.frozen.Metrics
		enrichment = replay.frozen.Logs
		changes = replay.frozen.Changes
		sentry = replay.frozen.Sentry
		zbx = replay.frozen.Zabbix
		memory = replay.frozen.Memory
	} else {
		metrics = FetchMetrics(ctx, s.promQuerier(), s.cfg.MetricParams, alerts, spanStart, inc.ID, s.logger)
		// Best-effort log enrichment: never blocks or fails triage. end=now so a
		// still-firing incident captures the freshest lines around analysis time.
		enrichment = FetchLogs(ctx, s.cfg.LogSource, s.cfg.LogParams, alerts, spanStart, time.Now().UTC(), inc.ID, s.logger)
		// Change enrichment reads local SQLite — reliable mid-incident, no timeout.
		changes = FetchChanges(ctx, s.st, s.cfg.ChangeParams, alerts, spanStart, time.Now().UTC(), inc.ID, s.logger)
		// Sentry Error source: a bounded 1+K query-at-triage, best-effort, never blocks.
		sentry = FetchSentry(ctx, s.cfg.Sentry, s.cfg.SentryParams, alerts, spanStart, time.Now().UTC(), inc.ID, s.logger)
		// Zabbix context: three bounded classes fanned out under one timeout,
		// best-effort, never blocks. nil client (source disabled) → nil context.
		zbx, zbxSeed = FetchZabbixContext(ctx, s.cfg.Zabbix, s.cfg.ZabbixParams, alerts, time.Now().UTC(), inc.ID, s.logger)
		// Zero-LLM cross-source verdict, computed downstream of the rule engine at the
		// triage seam (KTD5/R3): sets sentry.Reconciliation in place on a conclusive
		// look, inert (no-op) when sentry is nil or the query was inconclusive.
		reconcile(sentry)
		// Recall prior findings for this key (rung-2 exact + rung-3a prefilter). A
		// local store read, best-effort: a miss/err yields nil and the prompt is
		// byte-identical to a non-memory triage. Never passed to hasLiveEvidence or
		// the confidence cap — memory is context, never live evidence (R18).
		memory = FetchMemory(ctx, s.cfg.Memory, s.cfg.MemoryParams, inc, isDrill(alerts), time.Now().UTC())
		// Disposition-lite: when a recalled finding carries corroborating Sentry issue
		// ids, one bounded status read renders the regression/known-tolerated
		// transition. Best-effort, fail-safe — never blocks the recall.
		applyDisposition(ctx, s.cfg.Sentry, s.cfg.SentryParams, memory)
		// Shadow classifier (M3): judge the top rung-3a weak candidate. Runs before the
		// prompt is rendered so an `on`-mode match both tags what the model sees and is
		// captured by persist-as-rendered; in `shadow` mode it only audits and leaves
		// the render byte-identical. A no-op when disabled or there are no candidates.
		s.maybeClassify(ctx, inc, memory)
	}
	userPrompt := UserPrompt(pack, string(packJSON), metrics, enrichment, changes, sentry, zbx, memory, s.verifyParams())
	// On a re-judgment, prepend the deterministic recurrence context so the model
	// judges the recurrence with its history rather than as a first-time event.
	if recurrence != "" {
		userPrompt = recurrence + "\n\n" + userPrompt
	}
	system := s.systemPrompt(decision, len(alerts))
	obs := s.cfg.Health.Begin(llmhealth.CapabilityTriageDraft, inc.ID)
	comp, err := s.llm.Complete(ctx, system, llm.Prompt{
		Prefix:      userPrompt,
		CachePrefix: s.cfg.Verification.Enabled && s.cfg.PromptCaching,
	}, RequiredKeys)
	if err != nil {
		// obs.Finish persists with its own bounded context.Background() by
		// design: a triage_draft observation must never be dropped because
		// ctx was canceled.
		obs.Finish(err) //nolint:contextcheck
		s.logger.Error("llm failed", "incident", inc.ID, "err", err)
		if s.auditor != nil {
			_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.analysis_failed", map[string]any{
				"incident_id": inc.ID,
				"error":       err.Error(),
			})
		}
		// Marked LLM-origin so the Correlator can trust an ambiguous
		// stdlib-shaped reason (timeout/network/canceled) for its durable
		// capability-aware triage code instead of guessing where it came from.
		return analysisResult{}, fmt.Errorf("acutetriage: llm: %w", llmhealth.MarkLLMOrigin(err))
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
		raw:        comp.Raw,
		metrics:    metrics,
		logs:       enrichment,
		changes:    changes,
		sentry:     sentry,
		zabbix:     zbx,
		zabbixSeed: zbxSeed,
		memory:     memory,
		system:     system,
		user:       userPrompt,
		health:     obs,
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
	if ar.zabbix != nil {
		sources["zabbix"] = ar.zabbix
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
func (s *Skill) applyEvidenceCap(resp *llmResponse, decision rules.Decision, metrics *MetricEnrichment, logs *LogEnrichment, changes *ChangeEnrichment, sentry *SentryEnrichment, zabbix *ZabbixContext, ver *VerificationEnrichment, incidentID string) {
	if decision.ShortCircuit || !annotationsOnlyBasis(metrics, logs, changes, sentry, zabbix, ver) ||
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

// applySteeringCap is the R4 backstop — one predicate: steering was active and
// no fetched-query-backed ruling of supported or contradicted exists ⇒ the
// finding's confidence is clamped to MaxMetadataOnlyConfidence. Covers
// model-reported unverifiable, ruling absent, unbacked rulings, the degraded
// round, and verification-off. A backed contradicted/supported never clamps
// (scenario B keeps the model's own confidence). Deterministic: runs after
// the LLM, independent of prompt compliance.
func (s *Skill) applySteeringCap(resp *llmResponse, g *GoverningVerdict, ver *VerificationEnrichment, incidentID string) {
	if g == nil || !g.Steers || resp.Confidence <= MaxMetadataOnlyConfidence {
		return
	}
	if ver != nil && ver.OperatorRuling != nil {
		r := ver.OperatorRuling
		if (r.Ruling == "supported" || r.Ruling == "contradicted") && r.Backed {
			return
		}
	}
	s.logger.Info("confidence capped: operator correction not ruled out by fetched evidence",
		"incident", incidentID, "model_confidence", resp.Confidence, "capped_to", MaxMetadataOnlyConfidence)
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

// verifyParams stamps the presence flags onto the configured verification
// tunables: which floor sources exist on this install (ADR-0034) and hence
// which query kinds the plan instruction may offer the model.
func (s *Skill) verifyParams() VerificationParams {
	vp := s.cfg.Verification
	vp.HasPromQL = s.cfg.Prometheus != nil
	vp.HasZabbix = s.cfg.Zabbix != nil
	return vp
}

// verifyAndRejudge runs one verification round on a non-short-circuit draft and
// re-judges it in a second LLM call (ADR-0021/0022). It returns the finding that
// should ship: on success, call 2's raw JSON + parsed response + the executed
// round; on ANY call-2 failure (LLM error, malformed JSON), the DRAFT unchanged
// with its memory verdict cleared, so a lost re-judge never fails a triage the
// draft could otherwise ship (the never-fails invariant) and never moves memory
// marks on stale grounds (R16). resp is the draft (already clamped).
func (s *Skill) verifyAndRejudge(ctx context.Context, inc store.Incident, alerts []store.Alert, ar analysisResult, resp llmResponse, p pipelineParams) (json.RawMessage, llmResponse, *VerificationEnrichment) {
	draft := DraftRef{RootCause: resp.OverallIssue, Confidence: resp.Confidence}
	vp := s.verifyParams()
	floor := composeFloor(vp, s.cfg.ZabbixParams.HostLabel, alerts)
	modelQ := parseVerificationPlan(ar.raw, vp, s.logger, inc.ID)
	// One bounded batch repair of the model's own invalid PromQL, before
	// anything else sees the plan (ADR-0043): the audit row below, the round,
	// and the re-judge must all describe the EFFECTIVE plan — a repaired query
	// as it will actually run, a still-broken one already marked invalid and
	// excluded from execution — not the model's unchecked draft of it. Exactly
	// one call, only when something is actually invalid, and never a second
	// one; the stats it returns ride their own count-only audit row.
	modelQ, _ = s.repairModelPromQL(ctx, inc.ID, modelQ)

	// The governing verdict's operator-sourced steering queries (ADR-0029) ride
	// the same round, between the floor and the model's own proposals.
	// ar.memory is nil on paths that skip memory fetch entirely (e.g. no store
	// configured) — buildSteeringQueries is nil-safe on a nil governing verdict.
	// Computed BEFORE auditVerificationPlanned so the "planned" audit row
	// matches the round that actually executes (same three tiers, same order).
	var governing *GoverningVerdict
	if ar.memory != nil {
		governing = ar.memory.Governing
	}
	operatorQ := buildSteeringQueries(governing)
	s.auditVerificationPlanned(ctx, inc, floor, operatorQ, modelQ)

	// The runner shares the SAME true-nil-safe querier the analysis fetch used, and
	// the store as the incidents_in_window state reader. It never errors: a query's
	// own failure lands in its Outcome/Result, never aborting the round (R2).
	// During replay, queries are served from the frozen snapshot instead — no
	// live data-source call is ever made. Frozen memory carries Governing, so
	// operatorQ rebuilds identically on replay and the snapshot executor serves
	// each query by kind+expr — no snapshot-format change.
	var round *VerificationRound
	if p.replay != nil {
		round = runVerificationWith(ctx, p.replay.exec, vp, floor, draft, operatorQ, modelQ, time.Now().UTC())
	} else {
		round = runVerification(ctx, s.promQuerier(), s.cfg.Zabbix, s.st, vp, inc, floor, draft, operatorQ, modelQ, time.Now().UTC(), s.logger, ar.zabbixSeed)
	}

	// Call 2: the byte-identical call-1 prefix + the draft + the computed round +
	// the (moved) memory-verdict request. On any failure the draft stands.
	obs := s.cfg.Health.Begin(llmhealth.CapabilityVerificationRejudge, inc.ID)
	comp, err := s.llm.Complete(ctx, ar.system, llm.Prompt{
		Prefix:      ar.user,
		Suffix:      callTwoContinuation(ar.raw, round, ar.memory),
		CachePrefix: s.cfg.PromptCaching,
	}, RequiredKeys)
	if err != nil {
		// obs.Finish persists with its own bounded context.Background() by
		// design: a verification_rejudge observation must never be dropped
		// because ctx was canceled.
		obs.Finish(err) //nolint:contextcheck
		s.logger.Warn("acutetriage: verification re-judge failed; draft stands", "incident", inc.ID, "err", err)
		g := governingOf(ar.memory)
		if g != nil && g.Steers {
			s.logger.Error("acutetriage: steering: operator correction went unruled — verification call 2 failed; "+
				"finding ships capped and the card says the check did not complete (check your LLM setup)",
				"incident", inc.ID, "verdict_version", g.Version, "err", err)
		}
		return s.degradedDraft(ctx, inc.ID, ar.raw, round, resp, g, DegradationLLMCallFailed)
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
		obs.Finish(fmt.Errorf("%w: %v", llmhealth.ErrResponseMalformed, err)) //nolint:contextcheck
		s.logger.Warn("acutetriage: verification re-judge returned malformed JSON; draft stands", "incident", inc.ID, "err", err)
		g := governingOf(ar.memory)
		if g != nil && g.Steers {
			s.logger.Error("acutetriage: steering: operator correction went unruled — verification call 2 failed; "+
				"finding ships capped and the card says the check did not complete (check your LLM setup)",
				"incident", inc.ID, "verdict_version", g.Version, "err", err)
		}
		return s.degradedDraft(ctx, inc.ID, ar.raw, round, resp, g, DegradationLLMResponseInvalid)
	}
	obs.Finish(nil) //nolint:contextcheck // persists with its own bounded context.Background() by design
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

	// The ruling contract (ADR-0029): when a correction is steering, call 2 was
	// asked (callTwoContinuation) to add an operator_ruling key judging the
	// fetched operator-sourced evidence. Soft-parsed exactly like memory_verdict
	// above — a missing or invalid ruling never fails triage, it defaults to
	// "absent" and a WARN notes it (the deterministic confidence backstop,
	// Task 8, clamps off this record). Backed reports whether any operator
	// query actually fetched data, independent of what the model claims.
	var ruling *OperatorRulingRecord
	if g := governingOf(ar.memory); g != nil && g.Steers {
		ruling = &OperatorRulingRecord{
			Ruling: "absent", Backed: operatorEvidenceFetched(g, round),
			VerdictID: g.VerdictID, VerdictVersion: g.Version, VerdictDate: g.Date,
		}
		var r modelRuling
		if len(resp2.OperatorRuling) > 0 && json.Unmarshal(resp2.OperatorRuling, &r) == nil && validOperatorRulings[r.Ruling] {
			ruling.Ruling = r.Ruling
			ruling.Basis = capText(flattenRecalled(r.Basis), 300)
		} else {
			s.logger.Warn("acutetriage: steering: model omitted or mangled operator_ruling; treated as absent (clamp applies)",
				"incident", inc.ID, "verdict_version", g.Version)
		}
	}
	s.auditVerificationExecuted(ctx, inc.ID, outcome, round, clamped)

	degradationReason := ""
	if outcome == verifyOutcomeDegraded {
		degradationReason = DegradationVerificationSourceUnavailable
	}
	return comp.Raw, resp2, &VerificationEnrichment{Outcome: outcome, Rounds: []VerificationRound{*round}, OperatorRuling: ruling, DegradationReason: degradationReason}
}

// degradedDraft is the shared call-2-failure return: the draft ships as final —
// its ORIGINAL bytes preserved (draftRaw, so the persisted output_json is the
// model's exact draft, verification-plan key and all) with its parsed verdict's
// memory mark cleared (R16 — a lost call 2 moves no marks), outcome degraded, and
// the executed round preserved for the envelope. It emits the
// verification_executed audit so every planned round has a matching executed row.
// g is the governing correction (nil when none/not steering) — a lost call 2
// means the correction went unruled, recorded as such rather than silently
// dropped (the caller already logged the ERROR naming the failure).
func (s *Skill) degradedDraft(ctx context.Context, incidentID string, draftRaw json.RawMessage,
	round *VerificationRound, draft llmResponse, g *GoverningVerdict, reason string) (json.RawMessage, llmResponse, *VerificationEnrichment) {
	draft.MemoryVerdict = ""
	var ruling *OperatorRulingRecord
	if g != nil && g.Steers {
		ruling = &OperatorRulingRecord{Ruling: "unruled", Backed: operatorEvidenceFetched(g, round),
			VerdictID: g.VerdictID, VerdictVersion: g.Version, VerdictDate: g.Date}
	}
	s.auditVerificationExecuted(ctx, incidentID, verifyOutcomeDegraded, round, false)
	return draftRaw, draft, &VerificationEnrichment{Outcome: verifyOutcomeDegraded, Rounds: []VerificationRound{*round}, OperatorRuling: ruling, DegradationReason: reason}
}

// auditVerificationPlanned records the plan before it runs: the floor/operator/
// model query counts and each query's kind/source/why — never a metric value
// (R4/KTD6). The plan is assembled in the SAME floor→operator→model order the
// round itself uses (runVerificationWith), so this audit row's query list
// matches the executed round query-for-query — operatorQ (the governing
// verdict's steering queries, ADR-0029) must never be omitted here even though
// it is exempt from MaxQueries, or the "planned" and "executed" audit rows
// would silently disagree in count. floor is the SAME pre-composed slice
// (composeFloor, ADR-0034) the caller passes into runVerification/
// runVerificationWith, so this audit row never recomputes — and can never
// drift from — what actually executes.
func (s *Skill) auditVerificationPlanned(ctx context.Context, inc store.Incident, floor, operatorQ, modelQ []VerificationQuery) {
	if s.auditor == nil {
		return
	}
	plan := make([]VerificationQuery, 0, len(floor)+len(operatorQ)+len(modelQ))
	plan = append(plan, floor...)
	plan = append(plan, operatorQ...)
	plan = append(plan, modelQ...)
	qs := make([]map[string]string, 0, len(plan))
	for _, q := range plan {
		qs = append(qs, map[string]string{"kind": q.Kind, "source": q.Source, "why": q.Why})
	}
	_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.verification_planned", map[string]any{
		"incident_id":          inc.ID,
		"model_query_count":    len(modelQ),
		"operator_query_count": len(operatorQ),
		"floor_query_count":    len(floor),
		"queries":              qs,
	})
}

// auditVerificationExecuted records the round result: outcome,
// fetched/failed/invalid query counts (an empty answer counts as fetched —
// "asked, nothing there"; invalid is counted separately from failed since it
// is a model-quality signal, never a backend outage, and was never executed
// against the backend), and whether the confidence clamp fired. No
// expressions, no metric values.
func (s *Skill) auditVerificationExecuted(ctx context.Context, incidentID, outcome string, round *VerificationRound, clamped bool) {
	if s.auditor == nil {
		return
	}
	var fetched, failed, invalid int
	for _, q := range round.Queries {
		switch q.Outcome {
		case OutcomeFetched, OutcomeEmpty:
			fetched++
		case OutcomeFailed, OutcomeDegraded:
			failed++
		case OutcomeInvalid:
			invalid++
		case OutcomeNoSelector:
			// Metric-enrichment-only outcome; never set on a verification query.
		}
	}
	_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.verification_executed", map[string]any{
		"incident_id": incidentID,
		"outcome":     outcome,
		"fetched":     fetched,
		"failed":      failed,
		"invalid":     invalid,
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
