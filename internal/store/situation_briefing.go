// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Select only bounded operator fields in the same transaction as membership,
// assessment and journal. Raw outputs, queries and enrichment never cross it —
// the untruncated observations and limitation are read only to compute the
// analysis's pre-truncation EvidenceFingerprint here, exactly as
// loadMatchedCompletionEvidenceTx reads raw output only to recompute a digest.
func loadSituationAnalysesTx(ctx context.Context, tx *sql.Tx, id string) ([]model.IncidentAnalysis, int, error) {
	rows, err := tx.QueryContext(ctx, `
 SELECT i.id, substr(COALESCE(i.summary,''),1,181), substr(COALESCE(i.root_cause,''),1,501),
   (SELECT json_group_array(value) FROM (
     SELECT substr(value,1,401) AS value FROM json_each(CASE WHEN json_valid(i.output_json) THEN i.output_json ELSE '{}' END, '$.correlation_findings')
     WHERE type='text' LIMIT 3)),
   substr(COALESCE(json_extract(CASE WHEN json_valid(i.enrichment_json) THEN i.enrichment_json ELSE '{}' END,'$.verification.outcome'),''),1,40),
   substr(COALESCE(json_extract(CASE WHEN json_valid(i.enrichment_json) THEN i.enrichment_json ELSE '{}' END,'$.verification.degradation_reason'),''),1,101),
   (SELECT json_group_array(value) FROM json_each(CASE WHEN json_valid(i.output_json) THEN i.output_json ELSE '{}' END, '$.correlation_findings') WHERE type='text'),
   COALESCE(json_extract(CASE WHEN json_valid(i.enrichment_json) THEN i.enrichment_json ELSE '{}' END,'$.verification.degradation_reason'),''),
   i.last_judged_at, i.last_alert_at,
   (SELECT COUNT(*) FROM json_each(CASE WHEN json_valid(i.enrichment_json) THEN i.enrichment_json ELSE '{}' END,'$.verification.rounds') r,
     json_each(CASE WHEN r.type='object' THEN r.value ELSE '{}' END,'$.queries') q
     WHERE COALESCE(json_extract(CASE WHEN q.type='object' THEN q.value ELSE '{}' END,'$.outcome'),'') NOT IN ('fetched','empty')),
   COUNT(*) OVER (), COALESCE(i.enrichment_json,'{}')
 FROM situation_incidents si JOIN incidents i ON i.id=si.incident_id
 WHERE si.situation_id=? AND i.status IN ('analyzed','resolved')
   AND (COALESCE(i.summary,'')<>'' OR COALESCE(i.root_cause,'')<>'')
 ORDER BY i.last_judged_at DESC, i.id ASC LIMIT 3`, id)
	if err != nil {
		return nil, 0, fmt.Errorf("store: load situation analyses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []model.IncidentAnalysis
	var total int
	for rows.Next() {
		var a model.IncidentAnalysis
		var findings, allFindings, fullLimit, last, enrichment string
		var judged sql.NullString
		if err := rows.Scan(&a.IncidentID, &a.Title, &a.Summary, &findings, &a.Verification, &a.VerificationLimit,
			&allFindings, &fullLimit, &judged, &last, &a.VerificationGaps, &total, &enrichment); err != nil {
			return nil, 0, fmt.Errorf("store: scan situation analysis: %w", err)
		}
		if err := json.Unmarshal([]byte(findings), &a.Findings); err != nil {
			return nil, 0, fmt.Errorf("store: decode selected analysis findings: %w", err)
		}
		// Comparison provenance is taken from the FULL recorded observations
		// and limitation, before the display bounds this query already
		// applied above: the same fingerprint the matched completion
		// evidence carries, so materiality never reads a three-item overview
		// as different evidence from a six-item completion (lead
		// authorization, round 4, 2026-09-09). The untruncated text is used
		// only to compute it and never crosses the transaction.
		var recorded []string
		if err := json.Unmarshal([]byte(allFindings), &recorded); err != nil {
			return nil, 0, fmt.Errorf("store: decode recorded analysis findings: %w", err)
		}
		a.VerificationNotes = selectedVerificationNotes(enrichment)
		a.Observations = selectedLogSamples(enrichment)
		sourceEvidence := append(append([]string(nil), a.Observations...), a.VerificationNotes...)
		a.EvidenceFingerprint = model.EvidenceFingerprint(recorded, fullLimit, a.VerificationGaps, sourceEvidence...)
		if judged.Valid {
			at, err := time.Parse(time.RFC3339Nano, judged.String)
			if err != nil {
				return nil, 0, fmt.Errorf("store: parse analysis time: %w", err)
			}
			at = at.UTC()
			a.AnalyzedAt = &at
			latest, err := time.Parse(time.RFC3339Nano, last)
			if err != nil {
				return nil, 0, fmt.Errorf("store: parse analysis member time: %w", err)
			}
			a.Stale = latest.After(at)
		} else {
			a.Stale = true
		}
		out = append(out, model.BoundIncidentAnalysis(a))
	}
	return out, total, rows.Err()
}

// loadMatchedCompletionEvidenceTx reads incidentID's current accepted output
// inside the same transaction and returns its bounded evidence ONLY when the
// success completion digest recomputed over that output (findingOutputDigest,
// the exact content completeSuccessTx recorded on the attempt row) equals
// outputDigest — the positive attempt↔output match lead decision D (round 2,
// 2026-09-09) requires before a completion's result may be attributed to an
// attempt. Selected independently of loadSituationAnalysesTx's top-three
// overview and its non-empty title/root-cause filter, so an accepted
// completion with an EMPTY root cause (no causal hypothesis) is still a
// positively loaded fact here rather than a missing analysis. Returns nil
// evidence (never an error) when the Incident is not in an accepted state,
// carries no output, or its output no longer reproduces the digest: evidence
// unmatched, which establishes nothing. Raw output/enrichment are read only to
// recompute the digest and select bounded fields; they never cross the
// transaction. matched reports whether evidence was positively matched.
func loadMatchedCompletionEvidenceTx(ctx context.Context, tx *sql.Tx, incidentID, outputDigest string) (ev *situation.TriageCompletionEvidence, matched bool, err error) {
	var status string
	var outputJSON, summary, rootCause, enrichment, judged sql.NullString
	var confidence sql.NullFloat64
	err = tx.QueryRowContext(ctx, `
		SELECT status, output_json, summary, root_cause, confidence, enrichment_json, last_judged_at
		FROM incidents WHERE id = ?`, incidentID).
		Scan(&status, &outputJSON, &summary, &rootCause, &confidence, &enrichment, &judged)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: read incident completion evidence: %w", err)
	}
	if status != "analyzed" && status != "resolved" {
		return nil, false, nil
	}
	recorded := findingOutputDigest(TriageFinding{
		OutputJSON: outputJSON.String, Summary: summary.String, RootCause: rootCause.String,
		Confidence: confidence.Float64, EnrichmentJSON: enrichment.String,
	})
	if recorded != outputDigest {
		return nil, false, nil
	}

	ev = &situation.TriageCompletionEvidence{Hypothesis: strings.TrimSpace(rootCause.String)}
	ev.SourceEvidence = append(selectedLogSamples(enrichment.String), selectedVerificationNotes(enrichment.String)...)
	var output struct {
		CorrelationFindings []string `json:"correlation_findings"`
	}
	if outputJSON.Valid && json.Unmarshal([]byte(outputJSON.String), &output) == nil {
		ev.Observations = output.CorrelationFindings
	}
	var envelope struct {
		Verification struct {
			DegradationReason string `json:"degradation_reason"`
			Rounds            []struct {
				Queries []struct {
					Outcome string `json:"outcome"`
				} `json:"queries"`
			} `json:"rounds"`
		} `json:"verification"`
	}
	if enrichment.Valid && json.Unmarshal([]byte(enrichment.String), &envelope) == nil {
		ev.VerificationLimit = envelope.Verification.DegradationReason
		for _, r := range envelope.Verification.Rounds {
			for _, q := range r.Queries {
				if q.Outcome != "fetched" && q.Outcome != "empty" {
					ev.VerificationGaps++
				}
			}
		}
	}
	if judged.Valid {
		at, err := time.Parse(time.RFC3339Nano, judged.String)
		if err != nil {
			return nil, false, fmt.Errorf("store: parse completion judgment time: %w", err)
		}
		at = at.UTC()
		ev.JudgedAt = &at
	}
	return ev, true, nil
}

// Select operational check results; never export raw queries or parameters.
func selectedVerificationNotes(raw string) []string {
	var envelope struct {
		Verification struct {
			Rounds []struct {
				Queries []struct {
					Kind    string `json:"kind"`
					Why     string `json:"why"`
					Outcome string `json:"outcome"`
					Result  string `json:"result"`
				} `json:"queries"`
			} `json:"rounds"`
		} `json:"verification"`
	}
	if json.Unmarshal([]byte(raw), &envelope) != nil {
		return nil
	}
	var notes []string
	seen := map[string]bool{}
	for _, r := range envelope.Verification.Rounds {
		for _, q := range r.Queries {
			var note string
			switch {
			case q.Kind == "incidents_in_window" && q.Outcome == "fetched":
				note = "Incident-window lookup: " + boundedArtifactText(q.Result, 380) + ". A shared cause or relationship is unconfirmed."
			case q.Outcome == "empty" || q.Outcome == "failed" || q.Outcome == "invalid" || q.Outcome == "degraded":
				purpose := strings.Join(strings.Fields(q.Why), " ")
				if purpose == "" {
					purpose = "Verification check"
				}
				if q.Kind == "up_ratio" {
					purpose = "Peer service health"
				}
				if len(purpose) > 110 {
					purpose = boundedArtifactText(purpose, 107) + "…"
				}
				if q.Outcome == "empty" {
					note = purpose + ": returned no data; this check establishes neither health nor failure."
				} else {
					note = purpose + ": check could not establish the requested fact (" + q.Outcome + ")."
				}
			}
			if note != "" && !seen[note] {
				notes = append(notes, note)
				seen[note] = true
			}
		}
	}
	return notes
}

// A bounded, timestamped excerpt is an observation about a log sample, not
// evidence that every request or user failed. Queries and the raw envelope stay
// inside the transaction; Slack escapes each selected excerpt as untrusted text.
func selectedLogSamples(raw string) []string {
	var envelope struct {
		Logs struct {
			Outcome string `json:"outcome"`
			Lines   []struct {
				Timestamp string `json:"timestamp"`
				Line      string `json:"line"`
			} `json:"lines"`
		} `json:"logs"`
	}
	if json.Unmarshal([]byte(raw), &envelope) != nil || envelope.Logs.Outcome != "fetched" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range envelope.Logs.Lines {
		if strings.TrimSpace(line.Line) == "" || seen[line.Line] {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, line.Timestamp)
		if err != nil {
			continue
		}
		seen[line.Line] = true
		out = append(out, "Log sample at "+at.UTC().Format("2006-01-02 15:04:05 UTC")+": "+boundedArtifactText(line.Line, 300))
		if len(out) == 2 {
			break
		}
	}
	return out
}
