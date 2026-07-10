// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

// Outcome is the structured result of one best-effort enrichment fetch, shared
// by the metric, log, and change sources so the notification evidence line can
// map every source's outcome to a card state uniformly (R8). Sentry keeps its
// own SentryOutcome (reconciliation semantics predate this) and is mapped in
// buildEvidenceSummary. The zero value is fail-safe: an unset Outcome reads as
// "empty" (a 0), never "unreachable".
type Outcome string

const (
	// OutcomeFetched: the backend returned usable items → card renders the count.
	OutcomeFetched Outcome = "fetched"
	// OutcomeEmpty: queried, nothing matched → card renders 0.
	OutcomeEmpty Outcome = "empty"
	// OutcomeNoSelector: no usable selector could be built → card renders 0.
	OutcomeNoSelector Outcome = "no_selector"
	// OutcomeFailed: the backend was unreachable / errored → card renders "unreachable".
	OutcomeFailed Outcome = "failed"
)
