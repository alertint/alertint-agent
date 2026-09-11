// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Escape selected prose without shortening it. Slack sections paginate it.
func briefingComplete(s string) string { return briefingText(s, len(s)*6+1) }

func briefingDraft(a model.IncidentAnalysis) bool {
	return a.VerificationLimit == "llm_call_failed" || a.VerificationLimit == "llm_response_invalid" || a.VerificationLimit == "budget_deferred"
}

func briefingRootFinding(b *model.OperatorBriefing) string {
	for _, a := range b.Analyses {
		if briefingDraft(a) {
			continue
		}
		summary := strings.TrimSpace(briefingInterpretation(a))
		if summary == "" {
			continue
		}
		// Use complete sentences when the detailed interpretation is long.
		if len(summary) > 350 {
			if end := strings.Index(summary, ". "); end >= 0 && end < 350 {
				summary = summary[:end+1]
			}
		}
		if len(briefingComplete(summary)) > 700 {
			summary = strings.TrimPrefix(a.Title, "Hypothesis: ")
			if summary == "" || len(briefingComplete(summary)) > 300 {
				summary = "Detailed finding recorded in the analysis reply."
			}
		}
		label := "*Finding:*"
		if a.Stale && !b.Historical {
			label = "*Earlier finding:*"
		}
		return label + " " + briefingComplete(summary) + " Cause not confirmed."
	}
	return ""
}
