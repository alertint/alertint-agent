// SPDX-License-Identifier: FSL-1.1-ALv2

// Verdict steering (ADR-0029): the group key's governing correction verdict
// contributes deterministic verification queries and demands a ruling before
// its corrected cause may be adopted. Precedence through testing, never
// authority.

package acutetriage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

const (
	// sourceOperator marks a steering query derived from the governing
	// correction verdict's expectation (widen_queries verbatim + one bare
	// probe per cause_series). Executed with floor+model queries; exempt from
	// MaxQueries like the floor (deterministic, ≤ maxSteeringQueries).
	sourceOperator = "operator"

	// maxSteeringQueries bounds operator-sourced queries per triage (D10).
	maxSteeringQueries = 5
)

// GoverningVerdict is the operator entry of the memory enrichment: the group
// key's latest captured verdict, the single operator artifact triage consumes.
// Persist-as-rendered: Age/Date are stamped at fetch time so replay needs no
// clock; anchors + widen exprs are frozen so replay rebuilds identical
// steering queries.
type GoverningVerdict struct {
	IncidentID  string   `json:"incident_id"`
	VerdictID   int64    `json:"verdict_id"`
	Version     int      `json:"version"`
	Kind        string   `json:"kind"` // correction | confirmation
	Date        string   `json:"date"` // YYYY-MM-DD (UTC capture date)
	Age         string   `json:"age"`  // humanized at fetch
	Note        string   `json:"note,omitempty"`
	CauseAlert  string   `json:"cause_alert,omitempty"`
	CauseSeries []string `json:"cause_series,omitempty"`
	WidenExprs  []string `json:"widen_exprs,omitempty"`
	Steers      bool     `json:"steers"`
}

// governingEntry distills a stored verdict into the enrichment entry. The
// expectation decodes leniently (a persisted record is trusted shape-wise;
// unknown future fields must not kill recall). Grading vocabulary
// (must_mention / must_not_conclude) is deliberately NOT carried — it never
// renders into a prompt (R6). CauseAlert/CauseSeries are supplied by MCP
// clients (AI agents reading attacker-influenceable alert labels) and render
// straight into the prompt's "Corrected-cause anchors" line, so they get the
// same injection hardening as Note: flattened (no smuggled newlines) and
// capped at maxRecallEntryChars.
func governingEntry(v *store.IncidentVerdict, now time.Time) *GoverningVerdict {
	if v == nil {
		return nil
	}
	var exp Expectation
	_ = json.Unmarshal([]byte(v.ExpectationJSON), &exp)
	widened := decodeWidened(v)
	exprs := make([]string, 0, len(widened))
	for _, w := range widened {
		if w.Expr != "" {
			exprs = append(exprs, w.Expr)
		}
	}
	return &GoverningVerdict{
		IncidentID:  v.IncidentID,
		VerdictID:   v.ID,
		Version:     v.Version,
		Kind:        v.Verdict,
		Date:        v.CreatedAt.UTC().Format("2006-01-02"),
		Age:         humanizeAge(now.Sub(v.CreatedAt)),
		Note:        capText(flattenRecalled(v.Note), maxRecallEntryChars),
		CauseAlert:  capText(flattenRecalled(exp.CauseAlert), maxRecallEntryChars),
		CauseSeries: hardenRecalledStrings(exp.CauseSeries),
		WidenExprs:  exprs,
		Steers:      v.Verdict == "correction",
	}
}

// hardenRecalledStrings applies the same injection hardening as a single
// recalled string (flattenRecalled + capText at maxRecallEntryChars) to every
// element of an MCP-client-supplied string slice. nil in, nil out.
func hardenRecalledStrings(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = capText(flattenRecalled(s), maxRecallEntryChars)
	}
	return out
}

// buildSteeringQueries derives the correction's deterministic query set: one
// probe per cause_series FIRST, then widen_queries expressions verbatim fill
// whatever budget remains — a deliberate, user-approved deviation from the
// plan's original "widen_queries verbatim first" ordering (Global Constraint
// #2). widen_queries accumulate across verdict captures (merged forward,
// never pruned) and can exceed maxSteeringQueries on their own; emitting them
// first could silently squeeze the cause-series probes — the queries that
// actually test whether the corrected cause is real — out of the round
// entirely, while Backed still ends up true off an unrelated widen query
// (e.g. a generic `up` check). Probes-first guarantees the correction's own
// claim gets tested before any budget goes to accumulated widen exprs.
//
// Probe shape: the metric name as a bare instant vector selector (no guessed
// labels; the max_series bound prices over-breadth, a bad name lands as a
// failed outcome). Deduped by expr, capped at maxSteeringQueries.
func buildSteeringQueries(g *GoverningVerdict) []VerificationQuery {
	if g == nil || !g.Steers {
		return nil
	}
	seen := make(map[string]bool)
	var out []VerificationQuery
	add := func(expr, why string) {
		if expr == "" || seen[expr] || len(out) == maxSteeringQueries {
			return
		}
		seen[expr] = true
		out = append(out, VerificationQuery{Kind: kindPromQL, Source: sourceOperator, Expr: expr, Why: why})
	}
	for _, s := range g.CauseSeries {
		add(s, fmt.Sprintf("operator correction: does %s show the corrected cause?", s))
	}
	for _, e := range g.WidenExprs {
		add(e, "operator correction: evidence widened at capture")
	}
	return out
}

// governingOf is the nil-safe accessor onto a MemoryEnrichment's governing
// verdict, used everywhere the pipeline needs to ask "is a correction
// steering right now?" without repeating the nil check (m itself is nil on
// paths that skip memory fetch entirely, e.g. no store configured).
func governingOf(m *MemoryEnrichment) *GoverningVerdict {
	if m == nil {
		return nil
	}
	return m.Governing
}

// steeringAuditFields adds the incident.analyzed audit fields for a governing
// correction (R12): its verdict identity rides the trail regardless of
// whether a verification round ran (verification disabled still leaves the
// correction governing, just untested), and the ruling itself when call 2
// produced or defaulted one. A no-op when nothing is steering.
func steeringAuditFields(analyzed map[string]any, memory *MemoryEnrichment, ver *VerificationEnrichment) {
	g := governingOf(memory)
	if g == nil || !g.Steers {
		return
	}
	analyzed["steering_verdict_id"] = g.VerdictID
	analyzed["steering_verdict_version"] = g.Version
	if ver != nil && ver.OperatorRuling != nil {
		analyzed["operator_ruling"] = ver.OperatorRuling.Ruling
	}
}

// HistoryReader is the store surface BuildHistory needs: the group key's
// governing verdict, every operator annotation on it, and whether any prior
// incident exists at all. *store.Store satisfies it via Task 1's methods.
type HistoryReader interface {
	GoverningVerdict(ctx context.Context, groupKey string, currentIsDrill bool) (*store.IncidentVerdict, error)
	OperatorAnnotations(ctx context.Context, groupKey string, currentIsDrill bool) ([]store.OperatorAnnotation, error)
	AnyPriorIncident(ctx context.Context, groupKey, excludeIncidentID string, currentIsDrill bool) (bool, error)
}

// maxHistoryNotes bounds the rendered notes list; the remainder is counted,
// not dropped silently (History.NotesMore).
const maxHistoryNotes = 10

// BuildHistory assembles the group key's operator history — the shared
// payload behind the Slack history block, the stdout finding line, and MCP's
// operator_history (R13/D9). Tri-state honest (R8/D8): "first" renders only
// on clean reads with a false unbounded incident-existence check; a read
// error reports "unavailable", never 🆕.
func BuildHistory(ctx context.Context, r HistoryReader, groupKey, incidentID string, isDrill bool,
	episodes int, firstSeen time.Time, windowDays int, now time.Time) *notify.History {
	if r == nil {
		return nil
	}
	unavailable := &notify.History{State: "unavailable"}
	gv, err := r.GoverningVerdict(ctx, groupKey, isDrill)
	if err != nil {
		return unavailable
	}
	notes, err := r.OperatorAnnotations(ctx, groupKey, isDrill)
	if err != nil {
		return unavailable
	}
	anyPrior, err := r.AnyPriorIncident(ctx, groupKey, incidentID, isDrill)
	if err != nil {
		return unavailable
	}

	h := &notify.History{Episodes: episodes, FirstSeen: firstSeen, WindowDays: windowDays}
	if gv != nil {
		h.Verdict = &notify.HistoryVerdict{
			Kind: gv.Verdict,
			Age:  humanizeAge(now.Sub(gv.CreatedAt)),
			Date: gv.CreatedAt.UTC().Format("2006-01-02"),
			Note: capText(flattenRecalled(gv.Note), maxRecallEntryChars),
		}
	}
	verdictNoteSkipped := false
	for _, n := range notes {
		if gv != nil && !verdictNoteSkipped && n.Kind == gv.Verdict && n.Note == gv.Note {
			verdictNoteSkipped = true // the verdict renders itself; don't repeat its note
			continue
		}
		if len(h.Notes) == maxHistoryNotes {
			h.NotesMore++
			continue
		}
		h.Notes = append(h.Notes, notify.HistoryNote{
			Kind: n.Kind,
			Age:  humanizeAge(now.Sub(n.CreatedAt)),
			Note: capText(flattenRecalled(n.Note), maxRecallEntryChars),
		})
	}

	switch {
	case h.Verdict != nil || len(h.Notes) > 0:
		h.State = "history"
	case anyPrior:
		h.State = "seen"
	default:
		h.State = "first"
	}
	return h
}

// operatorEvidenceFetched reports whether the round actually tested the
// governing correction's own claim: a query sourced from the operator tier
// AND fetched AND whose expr names one of the correction's cause_series
// entries. A widen-only match (an operator query whose expr is not a
// cause_series entry) does not count — a correction accumulates widen exprs
// across captures, and an always-fetching widen query (e.g. a generic `up`
// check) must not permanently satisfy "Backed" regardless of whether the
// corrected cause was ever tested. OutcomeEmpty does not count either: an
// empty result carries no sign (ADR-0024), so it can back neither
// "supported" nor "contradicted" — the R4 backstop treats an unbacked ruling
// as absent.
func operatorEvidenceFetched(g *GoverningVerdict, r *VerificationRound) bool {
	if g == nil || r == nil {
		return false
	}
	causeSeries := make(map[string]bool, len(g.CauseSeries))
	for _, s := range g.CauseSeries {
		causeSeries[s] = true
	}
	if len(causeSeries) == 0 {
		return false
	}
	for _, q := range r.Queries {
		if q.Source == sourceOperator && q.Outcome == OutcomeFetched && causeSeries[q.Expr] {
			return true
		}
	}
	return false
}
