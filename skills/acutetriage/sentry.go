// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
)

// SentryReader is the narrow read surface FetchSentry needs from the Sentry
// client — the two U1 methods only. The fetcher depends on this interface (not
// *sentry.Client) so tests inject a fake with no HTTP, mirroring the poller's
// releaseSource idiom. nil = the Error source is not configured.
type SentryReader interface {
	ListIssues(ctx context.Context, project, env string, start, end time.Time, query string) ([]sentry.Issue, error)
	LatestEvent(ctx context.Context, issueID string) (sentry.IssueEvent, error)
}

// SentryParams carries the Error-source tunables from config (sentry.issues),
// already resolved to plain values (IncludeMessage flattened from the *bool
// toggle). Enabled gates the whole fetch independently of whether a client
// exists, so a releases-only deployment (client present, issues off) never
// queries (KTD7).
type SentryParams struct {
	Enabled             bool
	LookbackMinutes     int
	MaxIssues           int
	FetchTimeoutSeconds int
	IncludeMessage      bool
}

// SentryIssueView is one distilled, rendered-and-persisted issue. It is a strict
// allowlist of benign fields — issue id, exception type, culprit, file:line,
// level, blast radius, NEW flag — plus the optional exception message. Local
// variables, request bodies, breadcrumbs, and user/context entries are NEVER
// mapped here: the privacy boundary is the SHAPE of this struct, not a downstream
// filter (KTD8/R13). Message is included only when IncludeMessage is on (R14), so
// the toggle strips it from all three persisted surfaces at once. ID is the stable
// Sentry issue id — an opaque identifier, safe by shape (no redaction gate); it is
// persist-only and never rendered into the prompt (KTD3).
type SentryIssueView struct {
	ID            string `json:"id,omitempty"`
	ExceptionType string `json:"exception_type"`
	Culprit       string `json:"culprit,omitempty"`
	FileLine      string `json:"file_line,omitempty"`
	Level         string `json:"level,omitempty"`
	UserCount     int    `json:"user_count"`
	RatePerMin    string `json:"rate_per_min,omitempty"`
	New           bool   `json:"new"`
	Message       string `json:"message,omitempty"`
}

// SentryOutcome is the structured result of one FetchSentry query — the
// machine-readable marker the reconciliation verdict reads instead of parsing the
// free-text Note (KTD1). A conclusive look (issues returned OR a genuine
// zero/all-chronic result) is "ok"; an unresolved project slug is
// "unknown_project"; a rate-limit/timeout/API error after the bounded retry is
// "degraded". The empty zero-value is fail-safe: a FetchSentry path that forgets
// to set Outcome yields no verdict, never a wrong one. Only "ok" produces a tag.
type SentryOutcome string

const (
	outcomeOK             SentryOutcome = "ok"
	outcomeUnknownProject SentryOutcome = "unknown_project"
	outcomeDegraded       SentryOutcome = "degraded"
)

// SentryEnrichment is the distilled Sentry Error-source context attached to a
// triage prompt and persisted under the "sentry" envelope key (R10). The same
// value is both rendered into the prompt and stored, so the evidence pack
// replays exactly what the LLM saw. Mirrors LogEnrichment / ChangeEnrichment.
type SentryEnrichment struct {
	Project     string            `json:"project"`
	Environment string            `json:"environment,omitempty"`
	Start       time.Time         `json:"start"`
	End         time.Time         `json:"end"`
	Issues      []SentryIssueView `json:"issues,omitempty"`
	MoreCount   int               `json:"more_count,omitempty"` // matches beyond the top-K cap (R8)
	Note        string            `json:"note,omitempty"`       // zero-match / unknown-project / degraded
	Outcome     SentryOutcome     `json:"outcome,omitempty"`    // structured fetch result (KTD1)

	// Reconciliation is the zero-LLM cross-source verdict (matched / infra-only),
	// computed at the triage seam by reconcile() and set only on a conclusive look
	// (Outcome == ok). nil on degraded/unknown/disabled — which is exactly what
	// gates the headline off (R6) and keeps the disabled path byte-identical (R7).
	Reconciliation *Reconciliation `json:"reconciliation,omitempty"`

	// corroboratingIDs and chronicInWindow are the FULL pre-cap novelty breakdown,
	// captured before the MaxIssues render truncation so the verdict counts the true
	// match set, never the rendered top-K (KTD2/KTD4). Unexported in-process carries
	// from FetchSentry to reconcile, which copies them onto the persisted
	// Reconciliation verdict (the single source the headline renders from).
	corroboratingIDs []string // new-in-window issue ids (firstSeen ∈ W)
	chronicInWindow  int      // in-window non-NEW (chronic) issue count
}

// Reconciliation is the persisted cross-source verdict and the single source the
// headline renders from. Tag is "matched" (≥1 corroborating error) or "infra-only"
// (the source looked, found no new error). CorroboratingIssueIDs is the FULL
// new-in-window id set for a matched tag — forward-investment for chunk 02's MCP
// tools and the deferred incident-memory feature (KTD2/KTD3). ChronicCount is the
// FULL pre-cap in-window chronic count, persisted so the infra-only headline and an
// evidence-pack replay reconstruct identically (ADR-0001 fidelity). Opaque ids +
// integer counts; no PII.
type Reconciliation struct {
	Tag                   string   `json:"tag"`
	CorroboratingIssueIDs []string `json:"corroborating_issue_ids,omitempty"`
	ChronicCount          int      `json:"chronic_count,omitempty"`
}

const (
	tagMatched   = "matched"
	tagInfraOnly = "infra-only"
)

// FetchSentry runs the bounded query-at-triage Error source for one incident: it
// derives a project(+env) scope from conventional labels, queries issues active
// in W = [first − lookback, now], ranks NEW-first then by blast radius, distills
// the top K into view-models (one LatestEvent each for the deepest in-app
// file:line), and returns the section. The whole 1+K is bounded by ONE
// FetchTimeoutSeconds deadline, so worst-case added latency is one timeout, not
// 1+K× (R3/R12).
//
// Visibility over silence, mirroring FetchChanges/FetchLogs: it returns nil ONLY
// when the Error source never looked — disabled, unconfigured (r == nil), or no
// derivable project scope (R2). Whenever it queries it returns non-nil — with
// Issues, or with Issues empty and a Note (zero-match negative signal R11,
// unknown-project R11/KTD3, or degraded R12) — so the operator and the LLM can
// tell "looked, found nothing / project unknown / backend failed" from "never
// looked". It never blocks or fails triage. incidentID rides every outcome line
// (ADR-0004).
func FetchSentry(ctx context.Context, r SentryReader, params SentryParams, alerts []store.Alert, first, last time.Time, incidentID string, logger *slog.Logger) *SentryEnrichment {
	if !params.Enabled || r == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	shared := sharedLabels(alerts)
	project, env := sentryScope(shared)
	if project == "" {
		// No derivable project: an evidence gap, never a guessed unscoped query
		// (R2/AE4). Distinct from the disabled/unconfigured nil above — log why.
		logger.Info("sentry skipped: no project scope",
			"shared_labels", formatLabels(shared), "incident", incidentID)
		return nil
	}

	start := first.Add(-time.Duration(params.LookbackMinutes) * time.Minute)
	end := last
	scope := scopeLabel(project, env)

	// One bounded deadline for the whole 1+K fetch (distinct from the per-request
	// timeout), so a single slow LatestEvent can't starve the rest (KTD/P2).
	ctx, cancel := context.WithTimeout(ctx, time.Duration(params.FetchTimeoutSeconds)*time.Second)
	defer cancel()

	issues, err := r.ListIssues(ctx, project, env, start, end, "")
	if err != nil {
		// Unknown project slug (the most common misconfiguration) surfaces as the
		// zero-match negative signal, NOT the rate-limited degraded path (KTD3).
		var apiErr *sentry.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			note := "no Sentry project " + project + " (label value did not match a Sentry project slug)"
			logger.Warn("sentry fetched", "outcome", "unknown_project", "scope", scope, "incident", incidentID)
			return &SentryEnrichment{Project: project, Environment: env, Start: start, End: end, Note: note, Outcome: outcomeUnknownProject}
		}
		note := degradedNote(err)
		logger.Warn("sentry fetched", "outcome", "degraded", "scope", scope, "err", err, "incident", incidentID)
		return &SentryEnrichment{Project: project, Environment: env, Start: start, End: end, Note: note, Outcome: outcomeDegraded}
	}

	// Defensive in-window activity filter: the API scopes by start/end, but keep
	// only issues actually seen within W (lastSeen ≥ start) so a fake/looser
	// backend can't surface a stale issue (R4).
	active := issues[:0]
	for _, iss := range issues {
		if iss.LastSeen.Before(start) {
			continue
		}
		active = append(active, iss)
	}
	if len(active) == 0 {
		// Looked, found nothing active — itself evidence the incident is likely
		// not application-code-driven (R11/AE2).
		note := "no Sentry issues for " + scope + " in window"
		logger.Info("sentry fetched", "issues", 0, "scope", scope, "incident", incidentID)
		return &SentryEnrichment{Project: project, Environment: env, Start: start, End: end, Note: note, Outcome: outcomeOK}
	}

	windowMinutes := end.Sub(start).Minutes()
	rankIssues(active, start, end)

	// Capture the FULL new-in-window corroborating id set and chronic count over
	// the whole active match set, BEFORE the MaxIssues truncation below — so the
	// verdict (U2) and headline (U3) reflect the true counts, never the rendered
	// top-K (KTD2/KTD4). The truncation that follows caps only the rendered Issues.
	corroboratingIDs := make([]string, 0, len(active))
	chronicInWindow := 0
	for _, iss := range active {
		if inWindow(iss.FirstSeen, start, end) {
			corroboratingIDs = append(corroboratingIDs, iss.ID)
		} else {
			chronicInWindow++
		}
	}

	more := 0
	if len(active) > params.MaxIssues {
		more = len(active) - params.MaxIssues
		active = active[:params.MaxIssues]
	}

	views := make([]SentryIssueView, 0, len(active))
	for _, iss := range active {
		views = append(views, distill(ctx, r, iss, start, end, windowMinutes, params.IncludeMessage, incidentID, logger))
	}

	logger.Info("sentry fetched",
		"issues", len(views), "more", more, "scope", scope,
		"window", fmt.Sprintf("%dm", params.LookbackMinutes), "incident", incidentID)
	return &SentryEnrichment{
		Project: project, Environment: env, Start: start, End: end,
		Issues: views, MoreCount: more, Outcome: outcomeOK,
		corroboratingIDs: corroboratingIDs, chronicInWindow: chronicInWindow,
	}
}

// reconcile sets the zero-LLM cross-source verdict on the enrichment, in place at
// the triage seam (KTD5) — never in the rule engine (R3). It is a pure read of the
// structured Outcome marker plus the FULL pre-cap new-in-window set FetchSentry
// captured: a conclusive look with ≥1 corroborating error → matched (carrying the
// full id set R2/R4); a conclusive look with none (genuine zero or all-chronic) →
// infra-only. It leaves Reconciliation nil on any inconclusive/absent look
// (degraded, unknown-project) or a nil enrichment (disabled / no scope), which
// gates the headline off (R6) and keeps the disabled path byte-identical (R7).
func reconcile(e *SentryEnrichment) {
	if e == nil || e.Outcome != outcomeOK {
		return
	}
	if len(e.corroboratingIDs) > 0 {
		// Copy the carry slice so the persisted verdict owns its backing array — a
		// future in-package append to corroboratingIDs cannot then mutate the
		// at-rest CorroboratingIssueIDs.
		ids := append([]string(nil), e.corroboratingIDs...)
		e.Reconciliation = &Reconciliation{Tag: tagMatched, CorroboratingIssueIDs: ids, ChronicCount: e.chronicInWindow}
		return
	}
	e.Reconciliation = &Reconciliation{Tag: tagInfraOnly, ChronicCount: e.chronicInWindow}
}

// reconciliationDigestFields reads the PII-free verdict fields for the audit digest
// (KTD6), defaulting to empty/zero on an inconclusive look (Reconciliation nil) so
// the digest never derefs a nil verdict — the digest fires for every non-nil
// enrichment, including the degraded / unknown-project paths.
func reconciliationDigestFields(e *SentryEnrichment) (tag string, corroborating int) {
	if e.Reconciliation != nil {
		return e.Reconciliation.Tag, len(e.Reconciliation.CorroboratingIssueIDs)
	}
	return "", 0
}

// distill turns one ranked issue into the allowlist view-model. It makes the
// second call of the 1+K budget (LatestEvent) for the deepest in-app file:line;
// on any error (incl. the shared deadline) it falls back to the issue culprit and
// records WHY in the action trail, so a timeout-driven file:line loss is visible
// rather than masquerading as a vendored trace (P2). The exception type comes
// from metadata.type, never the PII-bearing title (KTD8); the message is mapped
// only when includeMessage is on (R14).
func distill(ctx context.Context, r SentryReader, iss sentry.Issue, start, end time.Time, windowMinutes float64, includeMessage bool, incidentID string, logger *slog.Logger) SentryIssueView {
	v := SentryIssueView{
		ID:            iss.ID,
		ExceptionType: exceptionType(iss, includeMessage),
		Culprit:       iss.Culprit,
		Level:         iss.Level,
		UserCount:     iss.UserCount,
		RatePerMin:    ratePerMin(iss.EventCount(), windowMinutes),
		New:           inWindow(iss.FirstSeen, start, end),
	}
	if includeMessage {
		v.Message = iss.Metadata.Value
	}

	ev, err := r.LatestEvent(ctx, iss.ID)
	if err != nil {
		logger.Warn("sentry frame fetch failed; using culprit",
			"issue", iss.ID, "err", err, "incident", incidentID)
		return v // FileLine stays empty → renderer falls back to culprit
	}
	if file, line, ok := sentry.DeepestInAppFrame(ev); ok {
		v.FileLine = fmt.Sprintf("%s:%d", file, line)
	}
	return v
}

// exceptionType sources the rendered type from metadata.type (PII-safe). When
// metadata.type is absent it falls back to the issue title ONLY if the message
// toggle is on: Sentry's title is "{type}: {value}" and embeds the exception
// value (often PII), so surfacing it while include_message is off would leak the
// value the toggle is meant to strip from all three persisted surfaces — the
// prompt, at-rest SQLite, and the evidence-pack MCP (KTD8/R14). With the toggle
// off and no structured type, render a neutral placeholder instead of the raw
// title.
func exceptionType(iss sentry.Issue, includeMessage bool) string {
	if iss.Metadata.Type != "" {
		return iss.Metadata.Type
	}
	if includeMessage {
		return iss.Title
	}
	return "unknown"
}

// rankIssues orders the in-window match set NEW-first (firstSeen ∈ W → a prime
// root-cause candidate), then by blast radius — affected users, then severity
// level, then event count — so the top-K cap keeps the highest-signal issues,
// never the API's default ordering (R8/KTD5).
func rankIssues(issues []sentry.Issue, start, end time.Time) {
	sort.SliceStable(issues, func(i, j int) bool {
		ni, nj := inWindow(issues[i].FirstSeen, start, end), inWindow(issues[j].FirstSeen, start, end)
		if ni != nj {
			return ni // NEW before chronic
		}
		if issues[i].UserCount != issues[j].UserCount {
			return issues[i].UserCount > issues[j].UserCount
		}
		if li, lj := levelRank(issues[i].Level), levelRank(issues[j].Level); li != lj {
			return li > lj
		}
		return issues[i].EventCount() > issues[j].EventCount()
	})
}

// levelRank maps a Sentry severity level to a sortable rank (higher = worse).
func levelRank(level string) int {
	switch level {
	case "fatal":
		return 5
	case "error":
		return 4
	case "warning":
		return 3
	case "info":
		return 2
	case "debug":
		return 1
	default:
		return 0
	}
}

// inWindow reports whether t falls within [start, end] inclusive — the shared W
// used for both membership and the NEW-vs-chronic novelty flag (R4/R7).
func inWindow(t, start, end time.Time) bool {
	return !t.Before(start) && !t.After(end)
}

// ratePerMin formats the in-window event rate (count ÷ window-duration). It
// fails soft to "" (omitted) when the count or window is unusable, so the rate
// never renders misleadingly. NOTE: count is taken as window-scoped per the
// start/end query (KTD4); the exact window-scoping of Sentry's count field is
// flagged for a live-API probe — if it proves lifetime-scoped, this is a coarse
// upper bound and the omit-on-zero keeps it from lying outright.
func ratePerMin(count int, windowMinutes float64) string {
	if count <= 0 || windowMinutes <= 0 {
		return ""
	}
	r := float64(count) / windowMinutes
	if r < 1 {
		return "<1/min"
	}
	return fmt.Sprintf("%.0f/min", r)
}

// degradedNote phrases the R12 degraded outcome, distinguishing a rate-limit
// (the bounded-retry exhaustion the operator can wait out) from other failures.
func degradedNote(err error) string {
	var apiErr *sentry.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests {
		return "Sentry query unavailable (rate-limited)"
	}
	return "Sentry query unavailable (" + err.Error() + ")"
}

// sentryScope derives the query scope from the incident's shared labels:
// project-required from the first of service/project/app/job, environment
// optional from environment/env (R2). An empty project means no derivable scope
// (the caller omits the section). It takes the pre-computed shared-label map so
// the caller reuses it for the no-scope log line, never walking the intersection
// twice.
func sentryScope(shared map[string]string) (project, env string) {
	for _, k := range []string{"service", "project", "app", "job"} {
		if v := shared[k]; v != "" {
			project = v
			break
		}
	}
	for _, k := range []string{"environment", "env"} {
		if v := shared[k]; v != "" {
			env = v
			break
		}
	}
	return project, env
}

// scopeLabel formats a project(+env) scope as the human-readable string used in
// log lines, note text, and the prompt section header — one definition so all
// three surfaces render the scope identically.
func scopeLabel(project, env string) string {
	if env == "" {
		return "project=" + project
	}
	return "project=" + project + " env=" + env
}
