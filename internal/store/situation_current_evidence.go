// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
)

// loadCurrentEvidenceTx selects the latest observation per exact query slot,
// not just the reads that happened to fit this cycle. Input and configuration
// fences prevent evidence crossing membership/configuration changes. Rank before
// checking expiry or success: an old success must never replace a newer failure.
// Canonical slot order, rather than recency, makes truncation stable under refresh.
func loadCurrentEvidenceTx(ctx context.Context, tx *sql.Tx, situationID, cycleID string, now time.Time) ([]observationmodel.Run, []situation.SourceObservation, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH scoped_plans AS (
		 SELECT p.id, p.capability, p.scope_json, p.parameters_json,
		        p.start_at, p.end_at, p.limit_count, p.purpose,
		   (unixepoch(substr(end_at,1,19)||'Z')-unixepoch(substr(start_at,1,19)||'Z'))*1000000000
		   + CASE WHEN substr(end_at,20,1)='.' THEN CAST(substr(substr(end_at,21,length(end_at)-21)||'000000000',1,9) AS INTEGER) ELSE 0 END
		   - CASE WHEN substr(start_at,20,1)='.' THEN CAST(substr(substr(start_at,21,length(start_at)-21)||'000000000',1,9) AS INTEGER) ELSE 0 END AS window_ns
		 FROM situation_observation_plans p
		), ranked AS (
		 SELECT r.id, r.cycle_id, r.plan_id, r.status, r.coverage_start, r.coverage_end,
		        r.coverage_complete, r.coverage_returned, r.coverage_omitted,
		        r.limitation_codes_json, r.observed_at, r.expires_at, r.completed_at,
		        r.reused_from_run_id, e.expired_at, p.capability, p.scope_json,
		        p.parameters_json, p.start_at, p.end_at, p.limit_count, p.purpose, p.window_ns,
		        ROW_NUMBER() OVER (
		          PARTITION BY p.capability, p.scope_json, p.parameters_json, p.window_ns, p.limit_count, p.purpose
		          ORDER BY c.generation DESC, r.completed_at DESC, r.id DESC) AS rank
		 FROM situation_observation_runs r
		 JOIN situation_preparation_cycles c ON c.id = r.cycle_id
		 JOIN scoped_plans p ON p.id = r.plan_id
		 JOIN situations s ON s.id = c.situation_id
		 JOIN situation_preparation_cycles current ON current.id = ?
		 LEFT JOIN situation_observation_detail_expirations e ON e.run_id = r.id
		 WHERE c.situation_id = ? AND c.input_version = s.input_version
		   AND c.config_digest = current.config_digest AND c.generation <= current.generation
		)
		SELECT id, cycle_id, plan_id, status, coverage_start, coverage_end,
		       coverage_complete, coverage_returned, coverage_omitted,
		       limitation_codes_json, observed_at, expires_at, completed_at,
		       reused_from_run_id, expired_at, capability, scope_json, parameters_json, start_at, end_at, limit_count, purpose
		FROM ranked WHERE rank = 1
		ORDER BY capability, scope_json, parameters_json, limit_count, purpose, window_ns LIMIT ?`, cycleID, situationID, observationmodel.MaxPlansPerCycle+1)
	if err != nil {
		return nil, nil, fmt.Errorf("store: query current evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type raw struct {
		id, cycle, plan, status, start, end, codes, observed, expires, completed string
		complete, returned, omitted                                              int
		reused, expired                                                          sql.NullString
		capability, scope, params, planStart, planEnd                            string
		limit                                                                    int
		purpose                                                                  string
	}
	var selected []raw
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.id, &r.cycle, &r.plan, &r.status, &r.start, &r.end,
			&r.complete, &r.returned, &r.omitted, &r.codes, &r.observed, &r.expires, &r.completed,
			&r.reused, &r.expired, &r.capability, &r.scope, &r.params, &r.planStart, &r.planEnd, &r.limit, &r.purpose); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		selected = append(selected, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	var runs []observationmodel.Run
	var lifecycle []situation.SourceObservation
	marker := observationmodel.Run{ScopeKey: "evidence-cap", Status: observationmodel.ResultWithheldByBudget,
		LimitationCodes: []string{"evidence_view_truncated"}}
	markerSize, err := currentEvidenceRunSize(marker)
	if err != nil {
		return nil, nil, err
	}
	// Reserve the final gap marker up front. Sum of individually wrapped JSON
	// objects also bounds their shared array/object representation.
	remaining := observationmodel.MaxNormalizedBytesPerCycle - markerSize
	for i, r := range selected {
		if i == observationmodel.MaxPlansPerCycle {
			runs = append(runs, marker)
			break
		}
		record, err := buildRunRecord(ctx, tx, r.id, r.cycle, r.plan, r.status, r.start, r.end,
			r.complete, r.returned, r.omitted, r.codes, r.observed, r.expires, r.completed, r.reused, r.expired)
		if err != nil {
			return nil, nil, err
		}
		run := record.Run
		start, err := time.Parse(time.RFC3339Nano, r.planStart)
		if err != nil {
			return nil, nil, err
		}
		end, err := time.Parse(time.RFC3339Nano, r.planEnd)
		if err != nil {
			return nil, nil, err
		}
		key := sha256.Sum256([]byte(fmt.Sprintf("%s\x1f%s\x1f%s\x1f%s\x1f%d\x1f%s", r.capability, r.scope, r.params, end.Sub(start), r.limit, r.purpose)))
		run.ScopeKey, run.Capability = hex.EncodeToString(key[:]), observationmodel.Capability(r.capability)
		var scope observationmodel.Scope
		if err := json.Unmarshal([]byte(r.scope), &scope); err != nil {
			return nil, nil, err
		}
		run.Scope, run.Parameters = &scope, json.RawMessage(r.params)
		if record.DetailState == observationmodel.DetailStateExpired || !now.Before(run.ExpiresAt) {
			run.Status = observationmodel.ResultStale
			run.Coverage.Complete = false
		}
		for j := range run.Facts {
			f := &run.Facts[j]
			if run.Status == observationmodel.ResultStale || !now.Before(f.ExpiresAt) {
				f.Freshness = observationmodel.FreshnessStale
			}
		}
		size, err := currentEvidenceRunSize(run)
		if err != nil {
			return nil, nil, err
		}
		if size > remaining {
			// Omit the entire oversized payload, not just facts: scope labels
			// and query parameters are evidence bytes too. Keep a stable slot
			// identity and explicit limitation, never a false confirmed-empty.
			run = observationmodel.Run{ScopeKey: run.ScopeKey, Capability: run.Capability,
				Status: observationmodel.ResultWithheldByBudget, LimitationCodes: []string{"evidence_view_truncated"}}
			size, err = currentEvidenceRunSize(run)
			if err != nil {
				return nil, nil, err
			}
			if size > remaining {
				runs = append(runs, marker)
				break
			}
		}
		remaining -= size
		for _, f := range run.Facts {
			if f.Kind != "source_lifecycle" || f.Freshness != observationmodel.FreshnessFresh || run.Status == observationmodel.ResultStale {
				continue
			}
			var batch []situation.SourceObservation
			if err := json.Unmarshal(f.Value, &batch); err != nil {
				return nil, nil, fmt.Errorf("store: decode lifecycle evidence: %w", err)
			}
			lifecycle = append(lifecycle, batch...)
		}
		runs = append(runs, run)
	}
	return runs, lifecycle, nil
}

func currentEvidenceRunSize(run observationmodel.Run) (int, error) {
	encoded, err := json.Marshal(run) //nolint:musttag // byte accounting for the transport-neutral Run, not a wire contract
	if err != nil {
		return 0, err
	}
	projected, err := situation.PreparedEvidenceSize(situation.PreparedState{Runs: []observationmodel.Run{run}})
	return max(len(encoded), projected), err
}
