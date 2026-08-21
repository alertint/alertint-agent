// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"
	"time"
)

// LocalizedInstant is the one renderer helper every Slack instant in the
// Situation surface uses: Situation start, evidence time, next update,
// envelope boundaries, recovery observed/grace, terminal time, and
// prior-episode comparisons. It emits Slack's own date markup so each
// viewer sees the epoch rendered in their device-local timezone and time
// format, with an explicit UTC fallback riding the same payload for
// surfaces that cannot render the markup. The canonical instant itself
// remains UTC everywhere else — storage, audit, MCP, comparison,
// scheduling, hashing, and idempotency never use this text form.
func LocalizedInstant(t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("<!date^%d^{date_short_pretty} at {time}|%s UTC>", t.Unix(), t.Format("2006-01-02 15:04"))
}

// NextUpdateText renders the promised-update line every published
// nonterminal Situation root carries: relative minutes computed from the
// canonical rendered_at/next_update_at pair (a partial minute always rounds
// upward, never displaying a false "any second now"), plus the same instant's
// localized/UTC-fallback absolute form. "or on recovery" appears only when
// the action contract's next_update_on lists recovery_observed — any other
// listed event may update earlier but never replaces the promised timestamp
// text itself. Callers must reconcile a promised deadline against the
// current time before render (never render an already-expired next_update_at
// as if it still lay in the future); this helper only performs the
// arithmetic, it does not know whether renderedAt is already stale.
func NextUpdateText(renderedAt, nextUpdateAt time.Time, nextUpdateOn []string) string {
	minutes := ceilMinutes(nextUpdateAt.Sub(renderedAt))
	text := fmt.Sprintf("Next update in %s, by %s", minuteWords(minutes), LocalizedInstant(nextUpdateAt))
	if containsEvent(nextUpdateOn, "recovery_observed") {
		text += ", or on recovery"
	}
	return text + "."
}

// ceilMinutes rounds a partial minute upward and floors at zero — a
// negative or already-elapsed remaining duration never displays as
// negative minutes; the caller is responsible for reconciling an actually
// expired deadline ahead of render.
func ceilMinutes(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	minutes := int(d / time.Minute)
	if d%time.Minute != 0 {
		minutes++
	}
	return minutes
}

func minuteWords(minutes int) string {
	if minutes == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}

func containsEvent(events []string, want string) bool {
	for _, e := range events {
		if strings.EqualFold(e, want) {
			return true
		}
	}
	return false
}
