// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSlackAPISlackDateTokenFormat(t *testing.T) {
	// A fixed instant in a non-UTC location: the token's Unix stamp and UTC
	// fallback must both be computed from the UTC instant, never the
	// location the caller happened to pass in.
	loc := time.FixedZone("TEST", 3*60*60) // UTC+3
	instant := time.Date(2026, 9, 5, 13, 4, 5, 0, loc)
	utc := instant.UTC()

	got := SlackDateToken(instant, "{date_short} {time}")

	wantPrefix := "<!date^" + strconv.FormatInt(utc.Unix(), 10) + "^{date_short} {time}|"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("SlackDateToken() = %q, want prefix %q", got, wantPrefix)
	}
	if !strings.HasSuffix(got, "|"+utc.Format(slackDateFallbackLayout)+">") {
		t.Fatalf("SlackDateToken() = %q, want UTC fallback suffix for %s", got, utc)
	}
	if !strings.Contains(got, "UTC") {
		t.Fatalf("SlackDateToken() = %q, want a UTC fallback marker", got)
	}
}

func TestSlackAPICeilMinutes(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		want int64
	}{
		{"zero", 0, 0},
		{"negative", -30 * time.Second, 0},
		{"exact minute", 2 * time.Minute, 2},
		{"one second over", 2*time.Minute + time.Second, 3},
		{"sub-minute remainder", 30 * time.Second, 1},
		{"just under a minute", 59 * time.Second, 1},
		{"large", 100*time.Minute + time.Nanosecond, 101},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CeilMinutes(c.d); got != c.want {
				t.Fatalf("CeilMinutes(%s) = %d, want %d", c.d, got, c.want)
			}
		})
	}
}

func TestSlackAPIRenderDeadlineFuture(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	deadline := now.Add(90 * time.Second) // ceil-rounds to 2 minutes

	got := RenderDeadline(deadline, now)

	if !strings.HasPrefix(got, "update by ") {
		t.Fatalf("RenderDeadline() = %q, want a current promise, not overdue", got)
	}
	if !strings.Contains(got, "(2 min)") {
		t.Fatalf("RenderDeadline() = %q, want ceil-rounded 2 min remaining", got)
	}
	if !strings.Contains(got, "<!date^") {
		t.Fatalf("RenderDeadline() = %q, want a Slack date token", got)
	}
}

func TestSlackAPIRenderDeadlineOverdue(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		deadline time.Time
	}{
		{"past", now.Add(-5 * time.Minute)},
		{"exactly now", now},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RenderDeadline(c.deadline, now)
			if !strings.HasPrefix(got, "update overdue since ") {
				t.Fatalf("RenderDeadline() = %q, want an overdue message, never a current promise", got)
			}
			if strings.Contains(got, " min)") {
				t.Fatalf("RenderDeadline() = %q, an overdue deadline must not render a countdown", got)
			}
		})
	}
}
