// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"time"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// loadSemanticDispatches reports lifetime ledger counts and the latest 100
// reservations across all jobs for this signature, in the same read transaction
// as the profile head and job. Missing outcomes are never treated as free calls.
func loadSemanticDispatches(ctx context.Context, tx *sql.Tx, signature string, history *profilemodel.History) error {
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(o.call_id IS NULL),0)
 FROM semantic_profile_calls c JOIN semantic_profile_inference_jobs j ON j.id=c.job_id
 LEFT JOIN semantic_profile_call_outcomes o ON o.call_id=c.id WHERE j.signature_key=?`, signature).
		Scan(&history.DispatchCount, &history.UnknownDispatchCount); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.id,c.job_id,c.attempt,c.dispatched_at,
 COALESCE(o.outcome,'reserved'),COALESCE(o.request_started,'unknown'),o.usage_input_tokens,o.usage_output_tokens,
 COALESCE(o.provider,''),COALESCE(o.model,''),o.completed_at
 FROM semantic_profile_calls c JOIN semantic_profile_inference_jobs j ON j.id=c.job_id
 LEFT JOIN semantic_profile_call_outcomes o ON o.call_id=c.id WHERE j.signature_key=?
 ORDER BY c.dispatched_at DESC,c.id DESC LIMIT 100`, signature)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	history.Dispatches = make([]profilemodel.Dispatch, 0)
	for rows.Next() {
		var d profilemodel.Dispatch
		var dispatched string
		var completed sql.NullString
		var input, output sql.NullInt64
		if err := rows.Scan(&d.ID, &d.JobID, &d.Attempt, &dispatched, &d.Outcome, &d.RequestStarted, &input, &output, &d.Provider, &d.Model, &completed); err != nil {
			return err
		}
		d.DispatchedAt, err = time.Parse(time.RFC3339Nano, dispatched)
		if err != nil {
			return err
		}
		if completed.Valid {
			at, err := time.Parse(time.RFC3339Nano, completed.String)
			if err != nil {
				return err
			}
			d.CompletedAt = &at
		}
		if input.Valid {
			n := int(input.Int64)
			d.UsageInputTokens = &n
		}
		if output.Valid {
			n := int(output.Int64)
			d.UsageOutputTokens = &n
		}
		history.Dispatches = append(history.Dispatches, d)
	}
	history.DispatchesTruncated = history.DispatchCount > len(history.Dispatches)
	return rows.Err()
}
