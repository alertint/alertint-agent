// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"time"
)

// slackDateFallbackLayout is the fixed UTC fallback rendered inside every
// <!date^...> token, for a surface that cannot render Slack's special
// markup (spec.md "Root and journal rendering": "Every instant uses Slack
// viewer-local date markup with a UTC fallback").
const slackDateFallbackLayout = "2006-01-02 15:04 MST"

// SlackDateToken renders t as a Slack mrkdwn date token: the viewer's own
// client renders it in the viewer's local time zone and format; a client
// that cannot (a plain-text notification, a screen reader, a webhook log)
// falls back to the fixed UTC string. format is a Slack date-format
// string, e.g. "{date_short} {time}" or "{time}"; see
// https://api.slack.com/reference/surfaces/formatting#date-formatting.
func SlackDateToken(t time.Time, format string) string {
	u := t.UTC()
	return fmt.Sprintf("<!date^%d^%s|%s>", u.Unix(), format, u.Format(slackDateFallbackLayout))
}

// CeilMinutes rounds d up to the nearest whole minute, never negative — the
// promised-update countdown's ceil-rounded minutes remaining (R4).
func CeilMinutes(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Minute - 1) / time.Minute)
}

// RenderDeadline renders one Operator-contract promised-update instant
// relative to now: while still in the future, a countdown ("update by
// <token> (N min)"); once reached or passed at render time, "update
// overdue since <token>" rather than a current promise (R4: "A deadline
// already past at render time renders as overdue, never as a current
// promise").
func RenderDeadline(deadline, now time.Time) string {
	if !deadline.After(now) {
		return fmt.Sprintf("update overdue since %s", SlackDateToken(deadline, "{date_short_pretty} {time}"))
	}
	minutes := CeilMinutes(deadline.Sub(now))
	return fmt.Sprintf("update by %s (%d min)", SlackDateToken(deadline, "{time}"), minutes)
}
