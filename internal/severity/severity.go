// SPDX-License-Identifier: FSL-1.1-ALv2

// Package severity ranks severity strings onto a single ordered scale so two
// callers can share one ladder: the Slack min_severity gate (which compares the
// finding severities low/medium/high) and the recurrence severity-rise trigger
// (which compares alert-severity labels such as warning and critical). The two
// vocabularies do not overlap, so one function covers both.
package severity

import "strings"

// Rank maps a severity string to a sortable rank; higher is more severe. Unknown
// or empty strings rank 0 — below everything — so an off-ladder finding always
// posts through the Slack gate and a missing alert-severity label never
// manufactures a severity rise. low/medium/high stay 1/2/3 so the Slack gate's
// behavior is unchanged when it delegates here.
func Rank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace", "info", "low":
		return 1
	case "notice", "warn", "warning", "medium":
		return 2
	case "error", "high":
		return 3
	case "critical", "crit":
		return 4
	case "alert", "emergency", "fatal", "page":
		return 5
	default:
		return 0
	}
}
