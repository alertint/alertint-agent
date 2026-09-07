// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import "time"

func SetBudgetClockForTest(b *Budget, now func() time.Time) { b.now = now }
