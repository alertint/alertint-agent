// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PriorFinding is one allowlisted recalled finding — the redaction boundary
// (distillation-as-privacy-boundary). Only these fields cross from a stored
// incident into the triage prompt and the MCP payload; the whole finding and the
// raw labels_json never do. RootCause/Confidence/Summary are the denormalized
// incident columns; CorroboratingIssueIDs are lifted from the persisted Sentry
// enrichment envelope for the disposition-lite lookup (R19).
type PriorFinding struct {
	IncidentID string
	// GroupKey is the prior incident's verbatim group_key — the sorted group-label
	// values, already the allowlisted recall key (never raw labels_json). The shadow
	// classifier renders the shared/differing delta between it and the current key
	// (R22); the exact-key recall carries it for symmetry.
	GroupKey              string
	AnalyzedAt            time.Time // last_judged_at, falling back to created_at
	Confidence            float64
	Summary               string // analysis_name
	RootCause             string // overall_issue
	ContradictionMarks    int    // memory_refute_marks; a prior demotes from strong at >= 2
	Episodes              int    // this incident's firing episodes = occurrence rows + 1
	CorroboratingIssueIDs []string
	IsDrill               bool
}

// MemoryView is the computed-never-stored recall for one incident's group_key:
// the folded occurrence facts for the key plus the allowlisted prior findings.
// One method computes it (the recoveryView precedent) so what the operator
// inspects over MCP and what the LLM saw in the prompt cannot drift (R26). The
// bidirectional drill filter, the lookback, and exclude-current are enforced
// here, once (R27). Episodes/FirstSeen/LastSeen/CadenceMedian fold M1's
// occurrence rows across every prior finding for the key.
type MemoryView struct {
	GroupKey string
	// Episodes is the folded firing-episode count for the key over the lookback,
	// excluding the current incident — each prior incident's first fire plus its
	// occurrence rows. This is the "recurred xN" number the strong entry renders.
	Episodes int
	// FirstSeen / LastSeen bound the folded episode series (zero when no priors).
	FirstSeen time.Time
	LastSeen  time.Time
	// CadenceMedian is the median interval between consecutive folded episodes,
	// zero when fewer than two episodes exist. A computed fact, never LLM phrasing.
	CadenceMedian time.Duration
	// PriorFindings are the exact-key recalls (rung 1/2), most-recent-first.
	PriorFindings []PriorFinding
	// DrillFiltered records that at least one same-key prior of the opposite
	// drill-ness was excluded — surfaced so the MCP payload can show it (samples
	// idea 6 "excluded.drill_filtered").
	DrillFiltered bool
}

// enrichmentEnvelope is the minimal shape memoryView decodes from a prior
// incident's persisted enrichment_json to lift the corroborating Sentry issue
// ids — nothing else. Decoding this narrow struct (not the whole envelope) keeps
// the allowlist boundary honest: no other persisted field can leak through.
type enrichmentEnvelope struct {
	Sentry struct {
		Reconciliation struct {
			CorroboratingIssueIDs []string `json:"corroborating_issue_ids"`
		} `json:"reconciliation"`
	} `json:"sentry"`
}

// corroboratingIssueIDs pulls the persisted new-in-window Sentry issue ids out of
// an enrichment envelope, defensively: a missing/malformed envelope yields nil,
// never an error — a recall must never fail because a prior finding's enrichment
// was absent or shaped differently.
func corroboratingIssueIDs(enrichmentJSON string) []string {
	if enrichmentJSON == "" {
		return nil
	}
	var env enrichmentEnvelope
	if err := json.Unmarshal([]byte(enrichmentJSON), &env); err != nil {
		return nil
	}
	return env.Sentry.Reconciliation.CorroboratingIssueIDs
}

// priorCandidate is a same-key or prefilter candidate row read before the drill
// filter and occurrence folding are applied.
type priorCandidate struct {
	pf           PriorFinding
	groupKey     string
	firstAlertAt time.Time
}

// scanPriorCandidates reads judged-incident candidate rows into priorCandidates.
// The SELECT column order is fixed by selectPriorCandidatesSQL.
func scanPriorCandidates(rows *sql.Rows) ([]priorCandidate, error) {
	var out []priorCandidate
	for rows.Next() {
		var (
			c              priorCandidate
			enrichmentJSON string
			createdStr     string
			judgedStr      *string
			firstStr       string
		)
		if err := rows.Scan(
			&c.pf.IncidentID, &c.groupKey,
			&c.pf.Summary, &c.pf.RootCause, &c.pf.Confidence,
			&enrichmentJSON, &c.pf.ContradictionMarks,
			&createdStr, &judgedStr, &firstStr,
		); err != nil {
			return nil, fmt.Errorf("store: scan prior candidate: %w", err)
		}
		c.pf.GroupKey = c.groupKey
		c.pf.CorroboratingIssueIDs = corroboratingIssueIDs(enrichmentJSON)
		analyzed, err := time.Parse(time.RFC3339Nano, createdStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse prior created_at: %w", err)
		}
		if judgedStr != nil {
			if t, err := time.Parse(time.RFC3339Nano, *judgedStr); err == nil {
				analyzed = t
			}
		}
		c.pf.AnalyzedAt = analyzed
		if c.firstAlertAt, err = time.Parse(time.RFC3339Nano, firstStr); err != nil {
			return nil, fmt.Errorf("store: parse prior first_alert_at: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// selectPriorCandidatesSQL selects judged incidents (carrying a finding) whose
// created_at is within the lookback and which are not the current incident,
// most-recent-first. The group_key predicate is appended by the caller.
const selectPriorCandidatesSQL = `
	SELECT id, group_key,
	       COALESCE(summary,''), COALESCE(root_cause,''), COALESCE(confidence,0.0),
	       COALESCE(enrichment_json,''), memory_refute_marks,
	       created_at, last_judged_at, first_alert_at
	FROM incidents
	WHERE status IN ('analyzed','resolved')
	  AND created_at >= ?
	  AND id != ?`

// queryPriorCandidates runs a prior-candidate SELECT and returns the scanned
// rows with the result set already closed — so the caller can issue its follow-up
// queries (occurrence stats, drill flags) without holding a SQLite cursor open on
// the shared connection.
func (s *Store) queryPriorCandidates(ctx context.Context, query string, args ...any) ([]priorCandidate, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query prior candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanPriorCandidates(rows)
}

// MemoryView computes the exact-key recall for a triage of currentIncidentID on
// groupKey. since is the lookback cutoff (now - lookback_days). currentIsDrill
// selects the drill side: a real incident recalls only real priors and a drill
// incident only drill priors (R27). Returns a zero-value view (no priors) when
// the key has no judged history — never ErrNotFound.
func (s *Store) MemoryView(ctx context.Context, groupKey, currentIncidentID string, currentIsDrill bool, since time.Time) (*MemoryView, error) {
	candidates, err := s.queryPriorCandidates(ctx,
		selectPriorCandidatesSQL+` AND group_key = ? ORDER BY created_at DESC`,
		since.UTC().Format(time.RFC3339Nano), currentIncidentID, groupKey,
	)
	if err != nil {
		return nil, err
	}

	view := &MemoryView{GroupKey: groupKey}
	survivors, err := s.applyDrillParity(ctx, candidates, currentIsDrill, &view.DrillFiltered)
	if err != nil {
		return nil, err
	}
	if len(survivors) == 0 {
		return view, nil
	}

	ids := make([]string, len(survivors))
	for i := range survivors {
		ids[i] = survivors[i].pf.IncidentID
	}
	stats, err := s.OccurrenceStatsByIncident(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range survivors {
		survivors[i].pf.Episodes = stats[survivors[i].pf.IncidentID].Episodes()
		view.PriorFindings = append(view.PriorFindings, survivors[i].pf)
	}

	// Fold the key's firing episodes: each survivor's first fire plus every
	// occurrence occurred_at within the lookback. Every survivor's first fire
	// counts unconditionally — the survivor is already lookback-filtered by
	// created_at, so a first_alert_at that predates `since` (an alert with an old
	// StartsAt) is still this incident's founding episode; dropping it rendered a
	// nonsensical "[folded ×0]" next to a real recalled hypothesis. Occurrence
	// times are filtered in Go (not SQL) to sidestep the fixed-width vs
	// RFC3339Nano lexical edge.
	episodes := make([]time.Time, 0, len(survivors))
	for i := range survivors {
		episodes = append(episodes, survivors[i].firstAlertAt)
	}
	occTimes, err := s.occurrenceTimesByIncidents(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, t := range occTimes {
		if !t.Before(since) {
			episodes = append(episodes, t)
		}
	}
	sort.Slice(episodes, func(i, j int) bool { return episodes[i].Before(episodes[j]) })
	view.Episodes = len(episodes)
	if len(episodes) > 0 {
		view.FirstSeen = episodes[0]
		view.LastSeen = episodes[len(episodes)-1]
		view.CadenceMedian = medianInterval(episodes)
	}
	return view, nil
}

// MemoryPrefilter finds rung-3a weak-signal candidates for a triage of
// currentIncidentID on groupKey: judged incidents within the lookback whose
// group_key differs from groupKey in exactly one group-label value (exact
// matches are rung 1/2, excluded here). Most-recent-first, drill-parity
// filtered, capped at limit (limit <= 0 uses 3). Per-incident Episodes are
// folded in so a weak entry can render its own recurrence count.
func (s *Store) MemoryPrefilter(ctx context.Context, groupKey, currentIncidentID string, currentIsDrill bool, since time.Time, limit int) ([]PriorFinding, error) {
	if limit <= 0 {
		limit = 3
	}
	candidates, err := s.queryPriorCandidates(ctx,
		selectPriorCandidatesSQL+` AND group_key != ? ORDER BY created_at DESC`,
		since.UTC().Format(time.RFC3339Nano), currentIncidentID, groupKey,
	)
	if err != nil {
		return nil, err
	}

	currentLabels := ParseGroupKey(groupKey)
	matched := candidates[:0]
	for _, c := range candidates {
		if differsInExactlyOne(currentLabels, ParseGroupKey(c.groupKey)) {
			matched = append(matched, c)
		}
	}

	var drillFiltered bool
	survivors, err := s.applyDrillParity(ctx, matched, currentIsDrill, &drillFiltered)
	if err != nil {
		return nil, err
	}
	if len(survivors) > limit {
		survivors = survivors[:limit]
	}
	if len(survivors) == 0 {
		return nil, nil
	}

	ids := make([]string, len(survivors))
	for i := range survivors {
		ids[i] = survivors[i].pf.IncidentID
	}
	stats, err := s.OccurrenceStatsByIncident(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]PriorFinding, len(survivors))
	for i := range survivors {
		survivors[i].pf.Episodes = stats[survivors[i].pf.IncidentID].Episodes()
		out[i] = survivors[i].pf
	}
	return out, nil
}

// applyDrillParity keeps only candidates whose drill-ness matches currentIsDrill
// (one batch IncidentDrillFlags read) and sets *filtered true if any candidate of
// the opposite drill-ness was dropped.
func (s *Store) applyDrillParity(ctx context.Context, candidates []priorCandidate, currentIsDrill bool, filtered *bool) ([]priorCandidate, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	ids := make([]string, len(candidates))
	for i := range candidates {
		ids[i] = candidates[i].pf.IncidentID
	}
	flags, err := s.IncidentDrillFlags(ctx, ids)
	if err != nil {
		return nil, err
	}
	survivors := make([]priorCandidate, 0, len(candidates))
	for _, c := range candidates {
		isDrill := flags[c.pf.IncidentID]
		if isDrill != currentIsDrill {
			*filtered = true
			continue
		}
		c.pf.IsDrill = isDrill
		survivors = append(survivors, c)
	}
	return survivors, nil
}

// occurrenceTimesByIncidents returns every occurrence occurred_at for the given
// incident ids in one query (no N+1), unsorted and unfiltered by time — callers
// filter and sort in Go. An empty id list yields nil.
func (s *Store) occurrenceTimesByIncidents(ctx context.Context, ids []string) ([]time.Time, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return nil, fmt.Errorf("store: marshal incident ids: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT occurred_at FROM incident_occurrences
		WHERE incident_id IN (SELECT value FROM json_each(?))
	`, string(idsJSON))
	if err != nil {
		return nil, fmt.Errorf("store: occurrence times: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, fmt.Errorf("store: scan occurrence time: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("store: parse occurrence time: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// IncrementRefuteMarks bumps an incident's contradiction counter by one and
// returns the new total, so the caller can demote a prior at >= 2 (R17). Returns
// ErrNotFound when the incident row is absent. Writes are serialized on the
// correlator loop, so the read-after-write is race-free.
func (s *Store) IncrementRefuteMarks(ctx context.Context, incidentID string) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET memory_refute_marks = memory_refute_marks + 1, updated_at = ?
		WHERE id = ?
	`, now, incidentID)
	if err != nil {
		return 0, fmt.Errorf("store: increment refute marks: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: increment refute marks rows: %w", err)
	}
	if n == 0 {
		return 0, ErrNotFound
	}
	var marks int
	if err := s.db.QueryRowContext(ctx,
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, incidentID,
	).Scan(&marks); err != nil {
		return 0, fmt.Errorf("store: read refute marks: %w", err)
	}
	return marks, nil
}

// ClearRefuteMarks resets an incident's contradiction counter to zero — called
// when a memory_verdict confirms the finding and when a re-judgment replaces it
// (new hypothesis, clean slate). A no-op zero-row update is not an error: the
// caller's intent (marks == 0) already holds.
func (s *Store) ClearRefuteMarks(ctx context.Context, incidentID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET memory_refute_marks = 0, updated_at = ?
		WHERE id = ? AND memory_refute_marks != 0
	`, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: clear refute marks: %w", err)
	}
	return nil
}

// medianInterval returns the median gap between consecutive ascending times.
// Fewer than two times yields 0 (no interval to measure).
func medianInterval(times []time.Time) time.Duration {
	if len(times) < 2 {
		return 0
	}
	gaps := make([]time.Duration, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]))
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	mid := len(gaps) / 2
	if len(gaps)%2 == 1 {
		return gaps[mid]
	}
	return (gaps[mid-1] + gaps[mid]) / 2
}

// ParseGroupKey splits a "k1=v1,k2=v2" group_key into a label map. Keys are
// sorted and values are simple in practice (cluster/namespace/service), so a
// split on ',' then the first '=' is exact for real keys. Exported so the
// shadow classifier renders its delta from the same parse the prefilter selects
// on — one source of truth for the group_key format.
func ParseGroupKey(key string) map[string]string {
	out := map[string]string{}
	if key == "" {
		return out
	}
	for _, pair := range strings.Split(key, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

// differsInExactlyOne reports whether two label maps share the same key set and
// differ in exactly one value — the rung-3a "one label off" prefilter predicate.
// Different key sets (a different grouping shape) never qualify.
func differsInExactlyOne(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	diffs := 0
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false // key set differs
		}
		if av != bv {
			diffs++
		}
	}
	return diffs == 1
}
