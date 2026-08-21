// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strings"
	"testing"
	"time"
)

func mustRFC3339(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}

func TestSlackDateAndCountdown(t *testing.T) {
	renderedAt := mustRFC3339(t, "2026-08-20T10:00:01Z")
	next := mustRFC3339(t, "2026-08-20T10:05:00Z")
	if got := LocalizedInstant(next); got != "<!date^1787220300^{date_short_pretty} at {time}|2026-08-20 10:05 UTC>" {
		t.Fatalf("got=%q", got)
	}
	if got := NextUpdateText(renderedAt, next, []string{"recovery_observed"}); !strings.Contains(got, "in 5 minutes") || !strings.Contains(got, "or on recovery") {
		t.Fatalf("got=%q", got)
	}
}

func TestNextUpdateTextRoundsPartialMinuteUpward(t *testing.T) {
	renderedAt := mustRFC3339(t, "2026-08-20T10:00:00Z")
	next := mustRFC3339(t, "2026-08-20T10:00:01Z")
	if got := NextUpdateText(renderedAt, next, nil); !strings.Contains(got, "in 1 minute,") {
		t.Fatalf("got=%q, want ceil-rounded to 1 minute", got)
	}
}

func TestNextUpdateTextOmitsRecoveryClauseWhenNotListed(t *testing.T) {
	renderedAt := mustRFC3339(t, "2026-08-20T10:00:00Z")
	next := mustRFC3339(t, "2026-08-20T10:02:00Z")
	if got := NextUpdateText(renderedAt, next, []string{"availability_impact"}); strings.Contains(got, "or on recovery") {
		t.Fatalf("got=%q, unexpected recovery clause", got)
	}
}

func TestNextUpdateTextNeverGoesNegative(t *testing.T) {
	// A promised deadline in the past ceils to zero, never negative — callers
	// reconcile before render so Slack never displays an expired countdown,
	// but the helper itself must not produce a nonsensical negative minute.
	renderedAt := mustRFC3339(t, "2026-08-20T10:05:00Z")
	next := mustRFC3339(t, "2026-08-20T10:00:00Z")
	if got := NextUpdateText(renderedAt, next, nil); !strings.Contains(got, "in 0 minutes,") {
		t.Fatalf("got=%q", got)
	}
}
