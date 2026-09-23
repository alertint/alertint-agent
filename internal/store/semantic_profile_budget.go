// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// completeBudgetDeferredProfileTx runs after the caller verifies the live
// owner/token fence. It preserves the unsent reservation/outcome and refunds
// only its latest consumed slot in the same transaction as the durable retry.
func completeBudgetDeferredProfileTx(ctx context.Context, tx *sql.Tx, callID, jobID string, result profilemodel.InferenceResult, now time.Time) (profilemodel.InferenceCommit, error) {
	if result.Outcome != profilemodel.InferenceOutcomeFailed || result.RequestStarted != "false" || result.UsageInputTokens != 0 || result.UsageOutputTokens != 0 {
		return profilemodel.InferenceCommit{}, errors.New("store: budget deferral requires a proved-unsent profile call without usage")
	}
	var current, latest int
	if err := tx.QueryRowContext(ctx, `SELECT c.attempt,(SELECT MAX(attempt) FROM semantic_profile_calls WHERE job_id=c.job_id) FROM semantic_profile_calls c WHERE c.id=? AND c.job_id=?`, callID, jobID).Scan(&current, &latest); err != nil {
		return profilemodel.InferenceCommit{}, err
	}
	if current != latest {
		return profilemodel.InferenceCommit{}, errors.New("store: budget deferral cannot refund an older profile call")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO semantic_profile_call_outcomes(call_id,outcome,request_started,usage_input_tokens,usage_output_tokens,provider,model,completed_at)
 VALUES (?,'failed','false',0,0,?,?,?)`, callID, result.Provider, result.Model, canonicalTime(now)); err != nil {
		return profilemodel.InferenceCommit{}, err
	}
	var retry any
	if result.BudgetRetryAt != nil {
		retry = canonicalTime(*result.BudgetRetryAt)
	}
	res, err := tx.ExecContext(ctx, `UPDATE semantic_profile_inference_jobs SET status='pending',attempt=attempt-1,
 owner=NULL,lease_expires_at=NULL,retry_at=?,error_class=? WHERE id=? AND attempt>0`, retry, profilemodel.ErrorClassBudgetDeferred, jobID)
	if err != nil {
		return profilemodel.InferenceCommit{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return profilemodel.InferenceCommit{}, err
	}
	if n != 1 {
		return profilemodel.InferenceCommit{}, errors.New("store: budget deferral has no consumed profile attempt to refund")
	}
	return profilemodel.InferenceCommit{Outcome: profilemodel.InferenceOutcomeFailed, JobStatus: profilemodel.JobStatePending, ErrorClass: profilemodel.ErrorClassBudgetDeferred}, nil
}
