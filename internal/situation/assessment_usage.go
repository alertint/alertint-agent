// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import "github.com/alertint/alertint-agent/internal/llm"

func setAssessmentUsage(attempt *AssessmentAttempt, usage llm.Completion) {
	input := usage.InputTokens + usage.CacheCreationInputTokens + usage.CacheReadInputTokens
	output := usage.OutputTokens
	// No usage received is unknown, not proof that a failed request was free.
	if input == 0 && output == 0 {
		return
	}
	attempt.UsageInputTokens, attempt.UsageOutputTokens = &input, &output
}
