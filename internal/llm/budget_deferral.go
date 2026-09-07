// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import (
	"fmt"
	"time"
)

// BudgetDeferredError denies admission, not inference. RetryAt is the earliest
// time to retry admission through the SAME guard, never permission to bypass it.
// Nil means that time alone cannot resolve the block: operator review is needed.
// Callers may refund an inference attempt only with proof it was never sent.
type BudgetDeferredError struct {
	RetryAt *time.Time
	Message string
}

func (e *BudgetDeferredError) Error() string {
	return fmt.Sprintf("%v: %s", ErrBudgetExhausted, e.Message)
}
func (e *BudgetDeferredError) Unwrap() error { return ErrBudgetExhausted }
