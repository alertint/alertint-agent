// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/alertint/alertint-agent/internal/situation"
)

// Refund only a first-call budget denial with durable proof of no dispatch.
// This runs inside the fenced projection/schedule commit. Advance the identity
// epoch so immutable call coordinates are never reused; retain every genuine
// prior inference attempt in the counter. There is no blanket budget reset.
func refundBudgetDeniedAttemptTx(ctx context.Context, tx *sql.Tx, claim situation.Claim, commit situation.ControllerCommit) error {
	if commit.BudgetDeniedCallID == nil {
		return nil
	}
	if !commit.Parked.Touch || commit.Parked.Reason != situation.ParkedReasonBudget {
		return errors.New("store: budget refund requires a budget deferral")
	}
	call, err := readAssessmentCallTx(ctx, tx, *commit.BudgetDeniedCallID)
	if err != nil {
		return err
	}
	if call.SituationID != claim.Situation.ID || call.InputVersion != claim.Situation.InputVersion || call.MaterialFactHash != commit.MaterialFactHash || call.CallNumber != 1 {
		return errors.New("store: budget refund does not match this claimed first call")
	}
	var proved, otherCall bool
	if err := tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM situation_assessment_attempts a
			WHERE a.call_id = ? AND a.status = 'failed' AND a.provider_request_started = 'false'
			AND EXISTS(SELECT 1 FROM json_each(a.validation_errors_json) e WHERE e.value = ?)),
		EXISTS(SELECT 1 FROM situation_assessment_calls
			WHERE situation_id = ? AND input_version = ? AND retry_epoch = ? AND work_attempt = ? AND id != ?)`,
		*commit.BudgetDeniedCallID, situation.BudgetDeferralErrorClass,
		call.SituationID, call.InputVersion, call.RetryEpoch, call.WorkAttempt, *commit.BudgetDeniedCallID).Scan(&proved, &otherCall); err != nil {
		return fmt.Errorf("store: prove unsent budget denial: %w", err)
	}
	if !proved || otherCall {
		return errors.New("store: budget refund lacks exclusive proof of no provider dispatch")
	}
	res, err := tx.ExecContext(ctx, `UPDATE situations SET
		controller_work_attempts = controller_work_attempts - 1,
		controller_retry_epoch = controller_retry_epoch + 1
		WHERE id = ? AND controller_retry_epoch = ? AND controller_work_attempts = ?`, call.SituationID, call.RetryEpoch, call.WorkAttempt)
	if err != nil {
		return fmt.Errorf("store: refund budget-denied attempt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("store: budget refund attempt counters changed")
	}
	return nil
}
