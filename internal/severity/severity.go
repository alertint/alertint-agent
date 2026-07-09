// SPDX-License-Identifier: FSL-1.1-ALv2

// Package severity ranks severity strings onto a single ordered scale so two
// callers can share one ladder: the Slack min_severity gate (which compares the
// finding severities low/medium/high) and the recurrence severity-rise trigger
// (which compares alert-severity labels such as warning and critical). The two
// vocabularies do not overlap, so one function covers both.
package severity

import "strings"

// Rank maps a severity string to a sortable rank over the full alert-severity
// ladder; higher is more severe. Unknown or empty strings rank 0 — below
// everything — so a missing alert-severity label never manufactures a severity
// rise. Used by the recurrence severity-rise trigger, which compares alert
// labels (warning, critical, …).
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

// GateRank ranks ONLY the finding-severity gate vocabulary — low/medium/high →
// 1/2/3 — and returns 0 for everything else (empty or off-ladder). It backs the
// Slack min_severity gate, where 0 means "always post": the gate exists to drop
// known-low noise, never to hide an unclassifiable severity. Kept distinct from
// Rank so extending the alert-severity ladder never silently narrows the gate.
func GateRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}
