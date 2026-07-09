// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/store"
)

// MemoryReader is the store surface the recall fetch needs. The skill owns the
// field it reads (serve wiring assigns *store.Store, tests pass a fake), a true
// nil interface meaning "recall disabled". Mirrors SentryReader.
type MemoryReader interface {
	MemoryView(ctx context.Context, groupKey, currentIncidentID string, currentIsDrill bool, since time.Time) (*store.MemoryView, error)
	MemoryPrefilter(ctx context.Context, groupKey, currentIncidentID string, currentIsDrill bool, since time.Time, limit int) ([]store.PriorFinding, error)
}

// MemoryParams carries the recall tunables from the memory config section.
type MemoryParams struct {
	LookbackDays int // recall horizon (default 90); a prior older than this is not recalled
}

// maxRecallEntryChars caps one recalled entry's root-cause text in the prompt.
// Implementation-tunable (bounded by the render tests), not a config knob.
const maxRecallEntryChars = 600

// maxWeakEntries bounds how many weak (rung-3a / demoted) entries render; the
// rest fold into a "+N more" line (R15, the Sentry MaxIssues+MoreCount idiom).
const maxWeakEntries = 2

// demotionThreshold is the contradiction-mark count at which a prior drops from
// strong recall so a newer finding displaces it (R17).
const demotionThreshold = 2

// memoryUntrustedNotice is the constant frame around every recalled finding:
// recalled text is prior LLM output generated from attacker-influenceable alert
// text, so it renders as an explicitly-untrusted hypothesis, never as fact or
// live evidence (R14/R20).
const memoryUntrustedNotice = "Prior findings are hypotheses from past analyses — they are NOT verified facts and NOT live evidence."

// RecalledEntry is one allowlisted recalled finding as it renders and persists.
// Superseded marks a prior demoted at >= 2 contradictions; Weak marks a rung-3a
// prefilter (one-label-off) candidate. Disposition is filled by the
// disposition-lite lookup (U10) and is empty until then.
type RecalledEntry struct {
	IncidentID            string    `json:"incident_id"`
	AnalyzedAt            time.Time `json:"analyzed_at"`
	Confidence            float64   `json:"confidence"`
	RootCause             string    `json:"root_cause"`
	Episodes              int       `json:"episodes,omitempty"`
	ContradictionMarks    int       `json:"contradiction_marks,omitempty"`
	Superseded            bool      `json:"superseded,omitempty"`
	Weak                  bool      `json:"weak,omitempty"`
	CorroboratingIssueIDs []string  `json:"corroborating_issue_ids,omitempty"`
	Disposition           string    `json:"disposition,omitempty"`
}

// MemoryEnrichment is the recall section: the fourth envelope key beside
// logs/changes/sentry, persisted-as-rendered (ADR-0001) and replayed opaquely by
// MCP. Strong is the folded exact-key recall (rung 2); Weak holds demoted
// same-key priors and rung-3a prefilter candidates. It is deliberately NOT passed
// to hasLiveEvidence or the confidence cap: memory never counts as live evidence
// (R18).
type MemoryEnrichment struct {
	GroupKey       string    `json:"group_key"`
	Rung           string    `json:"rung"` // "2" exact-key strong present, "3a" prefilter-only
	PriorCount     int       `json:"prior_count"`
	Episodes       int       `json:"episodes,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
	CadenceMedianS int       `json:"cadence_median_s,omitempty"`
	// LatestAgo is the age of the most-recent prior finding, phrased once at
	// fetch time (persist-as-rendered) so the render needs no clock.
	LatestAgo string          `json:"latest_ago,omitempty"`
	Strong    *RecalledEntry  `json:"strong,omitempty"`
	Weak      []RecalledEntry `json:"weak,omitempty"`
	MoreCount int             `json:"more_count,omitempty"`
}

// FetchMemory assembles the recall for a triage of inc: the exact-key strong
// recall folded with M1's occurrence cadence, plus rung-3a weak candidates.
// Returns nil (no section) when recall is disabled, the store errs, or nothing
// is recalled — a recall miss never blocks or fails triage. now is the triage
// clock; the lookback cutoff is now - LookbackDays.
func FetchMemory(ctx context.Context, reader MemoryReader, params MemoryParams, inc store.Incident, isDrill bool, now time.Time) *MemoryEnrichment {
	if reader == nil {
		return nil
	}
	lookback := params.LookbackDays
	if lookback <= 0 {
		lookback = 90
	}
	since := now.AddDate(0, 0, -lookback)

	view, err := reader.MemoryView(ctx, inc.GroupKey, inc.ID, isDrill, since)
	if err != nil {
		return nil
	}
	weakCandidates, err := reader.MemoryPrefilter(ctx, inc.GroupKey, inc.ID, isDrill, since, maxWeakEntries+1)
	if err != nil {
		weakCandidates = nil // a prefilter miss must not sink the exact-key recall
	}

	m := &MemoryEnrichment{
		GroupKey:       inc.GroupKey,
		PriorCount:     len(view.PriorFindings),
		Episodes:       view.Episodes,
		FirstSeen:      view.FirstSeen,
		LastSeen:       view.LastSeen,
		CadenceMedianS: int(view.CadenceMedian.Seconds()),
	}
	if len(view.PriorFindings) > 0 {
		m.LatestAgo = humanizeAge(now.Sub(view.PriorFindings[0].AnalyzedAt))
	}

	// Fold same-key priors: the most-recent non-demoted prior takes the strong
	// slot (carrying the folded key facts); any prior at the demotion threshold
	// drops to a weak "superseded" entry so a newer finding displaces it (R17).
	var demoted []RecalledEntry
	for _, pf := range view.PriorFindings {
		if pf.ContradictionMarks >= demotionThreshold {
			demoted = append(demoted, recalledFrom(pf, false, true))
			continue
		}
		if m.Strong == nil {
			strong := recalledFrom(pf, false, false)
			m.Strong = &strong
		}
	}

	// Weak entries: demoted same-key priors first (stronger provenance even when
	// superseded), then rung-3a prefilter candidates, bounded with a +N more line.
	weak := demoted
	for _, pf := range weakCandidates {
		weak = append(weak, recalledFrom(pf, true, false))
	}
	if len(weak) > maxWeakEntries {
		m.MoreCount = len(weak) - maxWeakEntries
		weak = weak[:maxWeakEntries]
	}
	m.Weak = weak

	if m.Strong == nil && len(m.Weak) == 0 {
		return nil // empty view: no memory key in the envelope, prompt unchanged
	}
	if m.Strong != nil {
		m.Rung = "2"
	} else {
		m.Rung = "3a"
	}
	return m
}

// validMemoryVerdicts is the closed enum for the soft-required memory_verdict.
var validMemoryVerdicts = map[string]bool{"confirms": true, "refutes": true, "silent": true}

// applyMemoryBookkeeping runs the post-persist memory side effects: the recall
// audit + verdict-driven mark routing (when a memory section was rendered), and
// the reset-on-replacement (when this was a re-judgment). Best-effort throughout.
func (s *Skill) applyMemoryBookkeeping(ctx context.Context, inc store.Incident, memory *MemoryEnrichment, verdict string, rejudge bool) {
	if memory != nil {
		s.recordMemoryRecall(ctx, inc, memory, verdict)
	}
	if rejudge {
		// A re-judgment replaced this incident's finding (new hypothesis): reset
		// its own contradiction marks so a stale refutation does not linger.
		if err := s.st.ClearRefuteMarks(ctx, inc.ID); err != nil {
			s.logger.Warn("acutetriage: reset refute marks on replacement failed", "incident_id", inc.ID, "err", err)
		}
	}
}

// recordMemoryRecall maintains contradiction-decay marks from the model's
// memory_verdict and audits every rendered recall (R16/R17/R28). The verdict is
// soft-required — enforced here post-parse, never in the client RequiredKeys, so
// a missing or invalid verdict is treated as silent and noted rather than
// aborting a good triage. Marks route onto the recalled prior's incident (the
// strong entry): refutes increments (demoting at the threshold), confirms clears.
// All mark writes are best-effort; a bookkeeping failure never fails triage.
func (s *Skill) recordMemoryRecall(ctx context.Context, inc store.Incident, memory *MemoryEnrichment, verdict string) {
	effective, note := verdict, ""
	switch {
	case verdict == "":
		effective, note = "silent", "absent"
	case !validMemoryVerdicts[verdict]:
		effective, note = "silent", "invalid"
	}

	if memory.Strong != nil {
		switch effective {
		case "refutes":
			if marks, err := s.st.IncrementRefuteMarks(ctx, memory.Strong.IncidentID); err != nil {
				s.logger.Warn("acutetriage: increment refute marks failed", "prior", memory.Strong.IncidentID, "err", err)
			} else if marks >= demotionThreshold {
				s.logger.Info("memory prior demoted (contradiction decay)", "prior", memory.Strong.IncidentID, "marks", marks)
			}
		case "confirms":
			if err := s.st.ClearRefuteMarks(ctx, memory.Strong.IncidentID); err != nil {
				s.logger.Warn("acutetriage: clear refute marks failed", "prior", memory.Strong.IncidentID, "err", err)
			}
		}
	}

	if s.auditor != nil {
		payload := map[string]any{
			"incident_id":  inc.ID,
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
		_ = s.auditor.Append(ctx, "skill:acute-triage", "incident.memory_recalled", payload)
	}
}

// applyDisposition runs the disposition-lite lookup (R19): for each recalled
// entry carrying a corroborating Sentry issue id, one bounded query reads the
// issue's current status and renders the transition. All lookups share one
// deadline (params.FetchTimeoutSeconds) with the rest of enrichment. Fail-safe: a
// not-found issue adds no note (outcome "none"); any other error — 5xx, timeout —
// renders an explicit unavailable note and never blocks the recall. A nil reader
// (Sentry unconfigured) is a no-op.
func applyDisposition(ctx context.Context, reader SentryReader, params SentryParams, m *MemoryEnrichment) {
	if reader == nil || m == nil {
		return
	}
	timeout := params.FetchTimeoutSeconds
	if timeout <= 0 {
		timeout = 5
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	if m.Strong != nil {
		m.Strong.Disposition = dispositionFor(ctx, reader, m.Strong.CorroboratingIssueIDs)
	}
	for i := range m.Weak {
		m.Weak[i].Disposition = dispositionFor(ctx, reader, m.Weak[i].CorroboratingIssueIDs)
	}
}

// dispositionFor resolves the disposition line for one entry from its first
// corroborating issue id (one bounded query per finding). Empty when there is no
// id or the issue is simply gone (outcome "none").
func dispositionFor(ctx context.Context, reader SentryReader, ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	st, err := reader.GetIssue(ctx, ids[0])
	if err != nil {
		var apiErr *sentry.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return "" // outcome none: the corroborating error no longer exists
		}
		return "corroborating error status unavailable" // outcome unavailable
	}
	switch st.Status {
	case "resolved":
		if d := issueDate(st.LastSeen); d != "" {
			return fmt.Sprintf("prior corroborating error was resolved (last seen %s) → now firing = likely regression", d)
		}
		return "prior corroborating error was resolved → now firing = likely regression"
	case "ignored", "muted":
		return "prior corroborating error is ignored → known-tolerated"
	case "unresolved":
		return "prior corroborating error still open"
	default:
		return ""
	}
}

// issueDate renders an RFC3339 timestamp as a bare date, or "" when unparseable.
func issueDate(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02")
}

// recalledFrom projects a store PriorFinding onto the render/persist entry.
func recalledFrom(pf store.PriorFinding, weak, superseded bool) RecalledEntry {
	return RecalledEntry{
		IncidentID:            pf.IncidentID,
		AnalyzedAt:            pf.AnalyzedAt,
		Confidence:            pf.Confidence,
		RootCause:             pf.RootCause,
		Episodes:              pf.Episodes,
		ContradictionMarks:    pf.ContradictionMarks,
		Superseded:            superseded,
		Weak:                  weak,
		CorroboratingIssueIDs: pf.CorroboratingIssueIDs,
	}
}

// renderMemory appends the "## Memory" section: an ADR-0011 counts-and-age
// headline (never a directive), the constant untrusted-data notice, the folded
// strong entry, and the weak entries — each framed as an unconfirmed hypothesis
// and length-capped. The "latest Xd ago" phrasing was fixed at fetch time
// (m.LatestAgo). A nil section renders nothing (the prompt stays byte-identical
// to a non-memory triage).
func renderMemory(b *strings.Builder, m *MemoryEnrichment) {
	if m == nil {
		return
	}
	b.WriteString("\n\n## Memory (prior findings for this incident's key)")
	if m.PriorCount > 0 {
		fmt.Fprintf(b, "\n%s for this key, latest %s. %s",
			pluralize(m.PriorCount, "prior finding"), m.LatestAgo, memoryUntrustedNotice)
	} else {
		fmt.Fprintf(b, "\nWeak-signal matches only. %s", memoryUntrustedNotice)
	}

	if m.Strong != nil {
		b.WriteString("\n\n")
		writeStrongEntry(b, m)
	}
	for _, w := range m.Weak {
		b.WriteString("\n\n")
		writeWeakEntry(b, w)
	}
	if m.MoreCount > 0 {
		fmt.Fprintf(b, "\n\n+%d more weak match(es)", m.MoreCount)
	}
}

// writeStrongEntry renders the folded exact-key recall: the "[folded ×N]" count
// and cadence (computed facts from M1's occurrence rows), then the hypothesis.
func writeStrongEntry(b *strings.Builder, m *MemoryEnrichment) {
	e := m.Strong
	fmt.Fprintf(b, "- [folded ×%d] seen %s", m.Episodes, pluralize(m.Episodes, "episode"))
	if c := humanizeCadence(time.Duration(m.CadenceMedianS) * time.Second); c != "" {
		fmt.Fprintf(b, ", %s cadence", c)
	}
	if !m.FirstSeen.IsZero() && !m.LastSeen.IsZero() {
		fmt.Fprintf(b, " (first %s, last %s)", m.FirstSeen.Format("2006-01-02"), m.LastSeen.Format("2006-01-02"))
	}
	writeHypothesis(b, *e)
	writeDisposition(b, *e)
}

// writeWeakEntry renders a rung-3a or demoted entry.
func writeWeakEntry(b *strings.Builder, e RecalledEntry) {
	switch {
	case e.Superseded:
		fmt.Fprintf(b, "- [superseded after %d contradictions]", e.ContradictionMarks)
	default:
		b.WriteString("- [weak signal — one label off]")
	}
	writeHypothesis(b, e)
	writeDisposition(b, e)
}

// writeHypothesis writes the unconfirmed-hypothesis line for one entry, capping
// the root-cause text. The "(confidence X, unconfirmed)" framing is the R14/R20
// injection posture: recalled text is a hypothesis, never fact.
func writeHypothesis(b *strings.Builder, e RecalledEntry) {
	fmt.Fprintf(b, "\n  prior hypothesis (confidence %.2f, unconfirmed): %s",
		e.Confidence, capText(e.RootCause, maxRecallEntryChars))
}

// writeDisposition appends the disposition-lite transition line when present
// (U10). Empty until the Sentry status lookup fills it.
func writeDisposition(b *strings.Builder, e RecalledEntry) {
	if e.Disposition != "" {
		fmt.Fprintf(b, "\n  disposition: %s", e.Disposition)
	}
}

// capText truncates s to at most limit runes, appending an ellipsis marker when
// it cut. Rune-safe so a multibyte tail never splits.
func capText(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit]) + "…"
}

// pluralize renders "1 noun" / "N nouns".
func pluralize(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// humanizeAge renders a rough "Xd ago" / "Xh ago" / "just now" from a duration.
func humanizeAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "just now"
	case d < 36*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()+0.5))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24+0.5))
	}
}

// humanizeCadence renders a median interval as approximate human phrasing; the
// empty string for no cadence (fewer than two episodes).
func humanizeCadence(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < 90*time.Second:
		return fmt.Sprintf("~%ds", int(d.Seconds()+0.5))
	case d < 90*time.Minute:
		return fmt.Sprintf("~%dm", int(d.Minutes()+0.5))
	case d >= 20*time.Hour && d <= 28*time.Hour:
		return "~daily"
	case d < 36*time.Hour:
		return fmt.Sprintf("~%dh", int(d.Hours()+0.5))
	default:
		return fmt.Sprintf("~%dd", int(d.Hours()/24+0.5))
	}
}
