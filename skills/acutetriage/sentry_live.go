// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/alertint/alertint-agent/internal/sentry"
)

// This file is the redaction boundary for the LIVE Sentry read surface (the two
// MCP tools, Spec 3 chunk 02). It reuses Spec 2's distillation primitives
// (exceptionType, rankIssues, inWindow, ratePerMin) and the same include_message
// gating, but widens the decoded frame surface from the single deepest in-app
// file:line to every frame — sourced exclusively through sentry.ExceptionTrace's
// relative-only frame view, NEVER DeepestInAppFrame (KTD3). The MCP layer stays a
// thin serializer over these two functions (KTD1): a second view-model in the MCP
// package would be a denylist waiting to drift.

const (
	// traceIDCap bounds one sentry_issues_trace call's fan-out on the shared token
	// (R13/KTD5); an over-cap list is rejected, not silently truncated.
	traceIDCap = 10
	// maxTraceFrames caps a pathological deep stack, keeping the INNERMOST frames
	// (the cause) and flagging truncation (KTD5).
	maxTraceFrames = 100
	// maxVerbatimLen bounds every verbatim Sentry-controlled string (culprit,
	// function, exception value/type) so an injection payload cannot dominate the
	// agent's context. A bound, not sanitization (Risks; PR #8 deferral carried).
	maxVerbatimLen = 200
	// listLimitDefault / listLimitMax bound the breadth list's 1+limit fan-out
	// (KTD2). "Beyond the cap" holds: the default 20 ≫ the triage K of 3.
	listLimitDefault = 20
	listLimitMax     = 50
)

// liveDeadlineCeiling caps the scaled fan-out deadline so a runaway call still
// terminates, independent of limit (KTD5).
const liveDeadlineCeiling = 30 * time.Second

// SentryStatus is the typed status filter for the breadth tool: a closed enum so
// no raw `is:` string is ever exposed at the MCP surface (KTD4). Each value maps
// to exactly one explicit `is:` token, so ListIssues is never called with the
// empty query that triggers the is:unresolved coercion at issues.go:159-161.
type SentryStatus string

const (
	StatusUnresolved SentryStatus = "unresolved"
	StatusResolved   SentryStatus = "resolved"
	StatusIgnored    SentryStatus = "ignored" // Sentry's API token is `is:ignored`; "muted" is UI wording (documented)
)

// ParseSentryStatus resolves the public status string to a typed value: empty
// defaults to unresolved (R5), an unknown value is rejected. It never returns a
// raw query string — query() owns the is:-token mapping.
func ParseSentryStatus(s string) (SentryStatus, error) {
	switch SentryStatus(s) {
	case "", StatusUnresolved:
		return StatusUnresolved, nil
	case StatusResolved:
		return StatusResolved, nil
	case StatusIgnored:
		return StatusIgnored, nil
	default:
		return "", fmt.Errorf("sentry: unknown status %q (want unresolved, resolved, or ignored)", s)
	}
}

// query maps the status to its single explicit `is:` token — always non-empty, so
// the empty-query coercion is never reached (KTD4).
func (s SentryStatus) query() string {
	switch s {
	case StatusUnresolved:
		return "is:unresolved"
	case StatusResolved:
		return "is:resolved"
	case StatusIgnored:
		return "is:ignored"
	default:
		return "is:unresolved" // unreachable: ParseSentryStatus gates the value
	}
}

// ListParams bundles the inputs to ListSentryIssues so the call is a small struct,
// not eight positional args. Params is the resolved triage envelope (carries
// IncludeMessage and FetchTimeoutSeconds — KTD8); the rest are the live-look scope
// the agent supplies explicitly (no incident id — R4).
type ListParams struct {
	Params  SentryParams
	Project string
	Env     string
	Start   time.Time
	End     time.Time
	Status  SentryStatus
	Limit   int
}

// SentryTrace is the distilled full-trace view for one issue id (R7/R8). Frames is
// the complete exception stacktrace (every frame, in_app flagged — ADR-0005), each
// frame carrying only the relative file:line + function + in_app allowlist (KTD3).
// ExceptionValue is gated by include_message (KTD8). Error is set per id when the
// latest event could not be fetched, so the batch returns a partial result rather
// than failing wholesale (R13). EventTimestamp lets the agent judge staleness (an
// issue is a fingerprint group; its latest event may be a later occurrence); it is
// a *time.Time so it is genuinely OMITTED on a failed/no-exception id — a plain
// time.Time with omitempty still serializes the zero value as "0001-01-01T00:00:00Z"
// (omitempty is a no-op on structs), planting a bogus timestamp next to the Error.
//
// There is deliberately no Permalink field: the trace fetches only events/latest/
// (never the Issue, to keep Issue.Title out of scope), and whether that payload
// carries a group permalink is unverified at planning time — so populating one
// would either guess a field or construct a link, both forbidden (R10/KTD6,
// Assumptions). The breadth list carries the permalink (from the Issue object);
// the trace's PII notice points to Sentry without promising a link.
type SentryTrace struct {
	IssueID         string         `json:"issue_id"`
	ExceptionType   string         `json:"exception_type,omitempty"`
	ExceptionValue  string         `json:"exception_value,omitempty"`
	EventTimestamp  *time.Time     `json:"event_timestamp,omitempty"`
	Frames          []sentry.Frame `json:"frames,omitempty"`
	FramesTruncated bool           `json:"frames_truncated,omitempty"`
	Error           string         `json:"error,omitempty"`
}

// ListSentryIssues is the breadth tool's boundary function: it lists distilled
// issues for an explicit scope/status, live and beyond the triage top-K. It reuses
// the FetchSentry pipeline shape (one bounded deadline → ListIssues → in-window
// filter → rank NEW-first → 1-LatestEvent-per-issue distill) with three live-only
// changes: an explicit status token (KTD4); the in-window activity filter applied
// ONLY for unresolved, since resolved/ignored is a historical disposition lookup
// (KTD7); and file:line sourced from the relative-only frame view, never
// DeepestInAppFrame (KTD2/KTD3). It returns the views, has_more (more in-window
// matches than limit — KTD2), and an error only when the list call itself fails
// (a per-issue LatestEvent miss degrades that issue to culprit, never the call).
func ListSentryIssues(ctx context.Context, r SentryReader, lp ListParams) ([]SentryIssueView, bool, error) {
	if r == nil {
		return nil, false, errors.New("sentry: live read source not configured")
	}
	limit := lp.Limit
	if limit <= 0 {
		limit = listLimitDefault
	}
	if limit > listLimitMax {
		limit = listLimitMax
	}

	// One deadline for the whole 1+limit fan-out, scaled to limit so a high-limit
	// breadth query is not silently truncated by the flat triage timeout (KTD5).
	ctx, cancel := context.WithTimeout(ctx, liveDeadline(lp.Params, limit))
	defer cancel()

	issues, err := r.ListIssues(ctx, lp.Project, lp.Env, lp.Start, lp.End, lp.Status.query())
	if err != nil {
		// An unknown project slug is the most common misconfiguration. Map the 404 to
		// an actionable "project not found" the agent can self-correct on — mirroring
		// the triage path (FetchSentry) — instead of the raw "sentry: api request
		// failed: http 404: <body>", which reads as a transport failure and echoes the
		// response body into the agent's context.
		var apiErr *sentry.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, false, fmt.Errorf("sentry: project %q not found (the label value did not match a Sentry project slug)", lp.Project)
		}
		return nil, false, err
	}

	// The recurring-now in-window-activity filter is the "what is erroring now"
	// guard — right for unresolved, wrong for a resolved/ignored "was this ever
	// resolved or muted" lookup. Drop it for resolved/ignored so a genuinely
	// historical disposition (last-seen before the live window) still surfaces;
	// Sentry's own start/end already scope the list (KTD7).
	active := issues
	if lp.Status == StatusUnresolved {
		active = issues[:0]
		for _, iss := range issues {
			if iss.LastSeen.Before(lp.Start) {
				continue
			}
			active = append(active, iss)
		}
	}

	windowMinutes := lp.End.Sub(lp.Start).Minutes()
	rankIssues(active, lp.Start, lp.End)

	hasMore := len(active) > limit
	if hasMore {
		active = active[:limit]
	}

	views := make([]SentryIssueView, 0, len(active))
	for _, iss := range active {
		views = append(views, distillLive(ctx, r, iss, lp.Start, lp.End, windowMinutes, lp.Params.IncludeMessage))
	}
	return views, hasMore, nil
}

// distillLive renders one issue into the allowlist view for the live list. It
// mirrors Spec 2's distill shape (exception type via exceptionType with the toggle
// gate, blast radius, level, rate, NEW flag) and sets Permalink from the issue —
// but sources file:line from the relative-only frames (sentry.ExceptionTrace),
// NEVER DeepestInAppFrame, so the absPath fallback cannot leak on this wider
// surface (KTD3). Verbatim Sentry-controlled strings are length-capped. A
// LatestEvent miss leaves file:line empty (render falls back to culprit) — a
// per-issue soft-fail, never an error (R13).
func distillLive(ctx context.Context, r SentryReader, iss sentry.Issue, start, end time.Time, windowMinutes float64, includeMessage bool) SentryIssueView {
	v := SentryIssueView{
		ID:            iss.ID,
		ExceptionType: capLen(exceptionType(iss, includeMessage)),
		Culprit:       capLen(iss.Culprit),
		Level:         iss.Level,
		UserCount:     iss.UserCount,
		RatePerMin:    ratePerMin(iss.EventCount(), windowMinutes),
		New:           inWindow(iss.FirstSeen, start, end),
		Permalink:     iss.Permalink,
	}
	if includeMessage {
		v.Message = capLen(iss.Metadata.Value)
	}
	ev, err := r.LatestEvent(ctx, iss.ID)
	if err != nil {
		return v // file:line stays empty → renderer falls back to culprit
	}
	if _, _, frames, ok := sentry.ExceptionTrace(ev); ok {
		if file, line, ok := deepestInAppRelative(frames); ok {
			v.FileLine = capLen(file) + ":" + strconv.Itoa(line) // cap the verbatim path (KTD5 bound)
		}
	}
	return v
}

// deepestInAppRelative returns the deepest (innermost — last in Sentry's
// outermost→innermost order) in-app frame that carries a relative file and a line,
// from the already-safe ExceptionTrace view. It mirrors DeepestInAppFrame's
// selection but over the relative-only File field, so no absPath can surface (the
// asymmetry KTD2/KTD3 closes). ok is false when no in-app frame qualifies, so the
// caller falls back to culprit, never to a library frame.
func deepestInAppRelative(frames []sentry.Frame) (file string, line int, ok bool) {
	for _, fr := range frames {
		if fr.InApp && fr.File != "" && fr.Line > 0 {
			file, line, ok = fr.File, fr.Line, true
		}
	}
	return file, line, ok
}

// TraceSentryIssues is the depth tool's boundary function: per issue id, it fetches
// the latest event and returns the full exception stacktrace (every frame, in_app
// flagged), the event timestamp, and the exception type — with the exception value
// gated by include_message INSIDE this function, never deferred to the serializer
// (KTD8). It rejects an empty or over-cap id list up front (R13), wraps the whole
// fan-out in one deadline scaled to the id count (KTD5), and returns a per-id Error
// for any id it could not fetch — a partial result, never a wholesale failure.
func TraceSentryIssues(ctx context.Context, r SentryReader, p SentryParams, ids []string) ([]SentryTrace, error) {
	if r == nil {
		return nil, errors.New("sentry: live read source not configured")
	}
	if len(ids) == 0 {
		return nil, errors.New("sentry: at least one issue id is required")
	}
	if len(ids) > traceIDCap {
		return nil, fmt.Errorf("sentry: too many issue ids (%d); max %d per call", len(ids), traceIDCap)
	}

	ctx, cancel := context.WithTimeout(ctx, liveDeadline(p, len(ids)))
	defer cancel()

	traces := make([]SentryTrace, 0, len(ids))
	for _, id := range ids {
		traces = append(traces, traceOne(ctx, r, p, id))
	}
	return traces, nil
}

// traceOne distills one issue's latest event. The exception type is sourced from
// the EVENT's exceptionValue.Type (the class name, PII-safe) — the trace never
// fetches the Issue, so Issue.Title (which embeds the value) is structurally out of
// scope and there is no symmetric title fallback. A fetch failure or a
// no-exception event sets Error and returns the partial entry.
func traceOne(ctx context.Context, r SentryReader, p SentryParams, id string) SentryTrace {
	t := SentryTrace{IssueID: id}
	ev, err := r.LatestEvent(ctx, id)
	if err != nil {
		t.Error = "could not fetch latest event: " + err.Error()
		return t
	}
	excType, excValue, frames, ok := sentry.ExceptionTrace(ev)
	if !ok {
		t.Error = "no exception stacktrace in latest event"
		return t
	}
	t.ExceptionType = capLen(excType)
	if p.IncludeMessage {
		t.ExceptionValue = capLen(excValue)
	}
	if !ev.DateCreated.IsZero() {
		ts := ev.DateCreated
		t.EventTimestamp = &ts // omitted (not year-1) when the event carried no timestamp
	}

	if len(frames) > maxTraceFrames {
		frames = frames[len(frames)-maxTraceFrames:] // keep innermost (the cause)
		t.FramesTruncated = true
	}
	// frames is local to this call (the slice ExceptionTrace returned, possibly
	// resliced for the cap above); mutate in place rather than copying. Both
	// verbatim Sentry-controlled strings on a frame — Function and the relative
	// File path — are length-capped so a crafted value cannot dominate the agent's
	// context (a relative path is still attacker-influenceable, not benign).
	for i := range frames {
		frames[i].Function = capLen(frames[i].Function)
		frames[i].File = capLen(frames[i].File)
	}
	t.Frames = frames
	return t
}

// liveDeadline scales the fetch deadline with the fan-out so a high-limit breadth
// query or a full id batch is not silently truncated by the flat triage timeout
// (KTD5). It derives a per-call budget from the triage envelope (FetchTimeoutSeconds
// covered the triage 1+MaxIssues fetch), multiplies by this call's 1+fanout, and
// caps at a ceiling. It NEVER returns a non-positive value — a zero deadline would
// expire context immediately, failing every live call (the KTD8 trap), so a
// degenerate envelope falls back to one second per call.
func liveDeadline(p SentryParams, fanout int) time.Duration {
	denom := 1 + p.MaxIssues
	if denom < 1 {
		denom = 1
	}
	perCall := time.Duration(p.FetchTimeoutSeconds) * time.Second / time.Duration(denom)
	if perCall <= 0 {
		perCall = time.Second
	}
	d := perCall * time.Duration(1+fanout)
	if d > liveDeadlineCeiling {
		d = liveDeadlineCeiling
	}
	return d
}

// capLen bounds a verbatim Sentry-controlled string to maxVerbatimLen runes,
// truncating on a rune boundary so a multibyte character is never split. A bound,
// not sanitization (Risks).
func capLen(s string) string {
	if len(s) <= maxVerbatimLen {
		return s // byte fast-path: ≤ maxVerbatimLen bytes ⇒ ≤ maxVerbatimLen runes, no alloc
	}
	r := []rune(s)
	if len(r) <= maxVerbatimLen {
		return s
	}
	return string(r[:maxVerbatimLen]) + "…"
}
