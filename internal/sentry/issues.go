// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// defaultIssueQuery is the fixed issue-search filter for Spec 2 (KTD4). A
// configurable query knob folds into Spec 3's cross-source work.
const defaultIssueQuery = "is:unresolved"

// Issue is one entry from the project issues-search endpoint. Only the benign,
// distillation-safe fields the Error source renders are decoded — the exception
// type/message, culprit, blast-radius counts, and the first/last-seen
// timestamps. The raw event payload (locals, request bodies, breadcrumbs, user
// context) is never on this object — it lives behind LatestEvent, and even there
// only the stacktrace frames are decoded. "Safe by shape, not by filtering"
// (ADR-0009, KTD8).
type Issue struct {
	ID    string `json:"id"`
	Title string `json:"title"` // "{type}: {value}" — embeds the exception value (often PII); used ONLY as a gated type fallback, never rendered raw (KTD8)

	Culprit   string    `json:"culprit"`
	Level     string    `json:"level"`
	Count     flexInt   `json:"count"`     // window-scoped event count (KTD4); Sentry serializes it as a string, decoded tolerantly
	UserCount int       `json:"userCount"` // affected-user count (blast radius, R6)
	FirstSeen time.Time `json:"firstSeen"` // NEW-in-window flag source (R7)
	LastSeen  time.Time `json:"lastSeen"`

	Metadata IssueMetadata `json:"metadata"`

	// Permalink is the Sentry-returned issue URL, decoded only where the list
	// response already carries it. It is surfaced by the live MCP tools as an
	// OPTIONAL, secondary affordance (R6/R10, KTD6) — never constructed from base
	// URL + org + id. Absent in the response → empty. The triage path never reads
	// it (SentryIssueView keeps it omitempty), so persisted output is unchanged.
	Permalink string `json:"permalink"`
}

// IssueMetadata carries the structured exception identity. Type is the PII-safe
// exception class the Error source renders (R5); Value is the exception message,
// surfaced only behind the include_message toggle (R14). The rendered exception
// type is sourced from Type, NEVER from the issue Title, because Title embeds the
// (often PII-bearing) Value (KTD8).
type IssueMetadata struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// EventCount returns the decoded window-scoped event count as a plain int, so
// callers in other packages need not name the unexported decode type.
func (i Issue) EventCount() int { return int(i.Count) }

// flexInt decodes a JSON value that may be a quoted string ("1500"), a bare
// number (1500), or null into an int. It fails soft to 0 on any parse problem so
// a single odd field can never break the whole issues-page decode (the rate then
// degrades to omitted rather than the section to an error).
type flexInt int

func (n *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		*n = 0
		return nil
	}
	*n = flexInt(v)
	return nil
}

// IssueEvent is the latest event for one issue, decoded down to ONLY its
// exception stacktrace frames plus the event timestamp. The full Sentry event
// carries user, request, breadcrumb, and context entries dense with PII; none of
// them are decoded here, so they cannot enter the process by struct shape (KTD8).
// Consumers are DeepestInAppFrame (triage) and ExceptionTrace (the live MCP
// depth tool); both read only the allowlist below. DateCreated is the event's
// timestamp, returned by the live trace tool so an agent can judge whether the
// latest event is stale relative to the incident (ADR-0005, R7) — an issue is a
// fingerprint group, so the latest event may be a later, different occurrence.
type IssueEvent struct {
	Entries     []eventEntry `json:"entries"`
	DateCreated time.Time    `json:"dateCreated"`
}

type eventEntry struct {
	Type string         `json:"type"`
	Data eventEntryData `json:"data"`
}

type eventEntryData struct {
	Values []exceptionValue `json:"values"`
}

type exceptionValue struct {
	Type       string     `json:"type"`
	Value      string     `json:"value"` // exception message — often PII; surfaced by the live trace tool ONLY behind include_message (gating in U2, never here)
	Stacktrace stacktrace `json:"stacktrace"`
}

type stacktrace struct {
	Frames []frame `json:"frames"`
}

// frame is one stacktrace frame, decoded tolerantly: the Sentry events API uses
// camelCase (lineNo/inApp) in the entries payload, but other surfaces and
// self-hosted versions have used snake_case (line_no/in_app). Accepting both
// de-risks the field-shape uncertainty (KTD9); a miss merely falls back to
// culprit, never panics.
//
// Two filename fields exist deliberately (KTD3):
//   - Filename: the absPath-FOLDED value (filename, or absPath when filename is
//     empty). This can be an absolute /home/<user>/… path. It is read ONLY by
//     DeepestInAppFrame on the Spec 2 triage path, which surfaces a single
//     deepest-in-app line whose relativity Spec 2 reviewed and accepted.
//     UNSAFE FOR THE LIVE SURFACE — do not wire a new live path to it.
//   - relFilename: the relative-only value the live MCP tools read. It captures
//     ONLY the raw `filename` JSON key (never absPath) AND rejects a `filename`
//     that is itself absolute, because Sentry's filename key is absolute on
//     Node/Go/Ruby/PHP/native SDKs (KTD3). The live accessor (ExceptionTrace)
//     reads exclusively this field, so no /home/<user>/… path can reach the
//     widened per-frame surface regardless of in_app.
type frame struct {
	Filename    string // absPath-folded — triage-only, unsafe for the live surface (KTD3)
	relFilename string // relative-only, absolute-rejected — the live allowlist field (KTD3)
	Function    string
	Line        int
	InApp       bool
}

func (f *frame) UnmarshalJSON(b []byte) error {
	var raw struct {
		Filename    string `json:"filename"`
		AbsPath     string `json:"absPath"`
		Function    string `json:"function"`
		LineNoCamel *int   `json:"lineNo"`
		LineNoSnake *int   `json:"line_no"`
		Lineno      *int   `json:"lineno"`
		InAppCamel  *bool  `json:"inApp"`
		InAppSnake  *bool  `json:"in_app"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	// Triage-only folded value: filename, or absPath as a fallback (KTD3).
	f.Filename = raw.Filename
	if f.Filename == "" {
		f.Filename = raw.AbsPath
	}
	// Live allowlist value: the raw filename key ONLY, never absPath, and dropped
	// to empty when it is itself absolute — relativity is the allowlist, not the
	// JSON key (KTD3). Reading the key alone would leak absolute paths on
	// non-Python SDKs.
	f.relFilename = raw.Filename
	if isAbsPath(f.relFilename) {
		f.relFilename = ""
	}
	f.Function = raw.Function
	switch {
	case raw.LineNoCamel != nil:
		f.Line = *raw.LineNoCamel
	case raw.LineNoSnake != nil:
		f.Line = *raw.LineNoSnake
	case raw.Lineno != nil:
		f.Line = *raw.Lineno
	}
	switch {
	case raw.InAppCamel != nil:
		f.InApp = *raw.InAppCamel
	case raw.InAppSnake != nil:
		f.InApp = *raw.InAppSnake
	}
	return nil
}

// isAbsPath reports whether p is an absolute path on ANY platform, not just the
// host OS. filepath.IsAbs alone is host-relative: a Windows "C:\…" path is not
// flagged on a Linux host, and a POSIX "/home/…" path is not flagged on Windows.
// The live frame allowlist must reject both regardless of where alertint runs, so
// this checks POSIX roots, Windows drive letters, UNC/backslash roots, and
// URI-scheme-qualified paths explicitly in addition to the host-native check
// (KTD3). Leading whitespace is trimmed first so " /home/…" cannot slip past the
// prefix checks.
func isAbsPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	// URI-scheme-qualified filename (file://…, webpack://…, https://…): non-Python
	// SDKs (Node ESM, Deno, native) emit a scheme-qualified `filename` key whose
	// path segment carries the absolute /home/<user>/… deploy path. filepath.IsAbs
	// and the enumerated roots below do not recognize these, so reject the scheme
	// form here — the live surface is relative repo paths only (KTD3).
	if hasURIScheme(p) {
		return true
	}
	if filepath.IsAbs(p) {
		return true
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return true // POSIX root, or Windows UNC/backslash root, on a non-matching host
	}
	if len(p) >= 2 && p[1] == ':' { // Windows drive letter, e.g. C:\ or C:/
		c := p[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}

// hasURIScheme reports whether p begins with an RFC 3986 URI scheme followed by
// "://" — scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ). It is intentionally
// strict (a real scheme prefix, not merely containing "://") so a legitimate
// relative path is never dropped, while file://, webpack://, http(s)://, and the
// like are all caught (KTD3).
func hasURIScheme(p string) bool {
	i := strings.Index(p, "://")
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := p[j]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
			// ALPHA — always allowed, including as the first character.
		case c >= '0' && c <= '9', c == '+', c == '-', c == '.':
			if j == 0 {
				return false // a scheme must start with ALPHA
			}
		default:
			return false // any other byte before "://" means this is not a scheme
		}
	}
	return true
}

// ListIssues searches one project's issues active in the window [start, end],
// optionally scoped to an environment, filtered by query (default
// is:unresolved). It hits the PROJECT-scoped endpoint so the conventional label
// value is used directly as the project slug — no slug→numeric-ID resolution
// (KTD3). An unknown slug yields HTTP 404 (a *APIError the caller maps to the
// unknown-project negative signal, R11), not a 200-empty. start/end are sent as
// the W bounds (explicit, not statsPeriod — KTD4). Only the first page is read;
// ranking and the "+N more" count are the fetcher's job from the returned slice.
// Logger-less, incident-unaware (ADR-0004).
func (c *Client) ListIssues(ctx context.Context, project, env string, start, end time.Time, query string) ([]Issue, error) {
	if strings.TrimSpace(query) == "" {
		query = defaultIssueQuery
	}
	q := url.Values{}
	q.Set("query", query)
	q.Set("sort", "date") // explicit, mirroring ListReleases — never rely on a server-side default
	q.Set("start", start.UTC().Format(time.RFC3339))
	q.Set("end", end.UTC().Format(time.RFC3339))
	if env != "" {
		q.Set("environment", env)
	}
	path := "/api/0/projects/" + url.PathEscape(c.org) + "/" + url.PathEscape(project) + "/issues/"
	resp, err := c.doGET(ctx, path, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if err != nil {
		return nil, fmt.Errorf("sentry: read issues: %w", err)
	}
	var issues []Issue
	if err := json.Unmarshal(body, &issues); err != nil {
		return nil, fmt.Errorf("sentry: decode issues: %w", err)
	}
	return issues, nil
}

// LatestEvent fetches the latest event for one issue and decodes ONLY its
// exception stacktrace entries (KTD8/KTD9) — the second call of the 1+K budget
// (KTD5), made once per top-K issue to recover the deepest in-app file:line that
// the issue object alone does not carry. Logger-less (ADR-0004).
func (c *Client) LatestEvent(ctx context.Context, issueID string) (IssueEvent, error) {
	path := "/api/0/issues/" + url.PathEscape(issueID) + "/events/latest/"
	resp, err := c.doGET(ctx, path, nil)
	if err != nil {
		return IssueEvent{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if err != nil {
		return IssueEvent{}, fmt.Errorf("sentry: read event: %w", err)
	}
	var ev IssueEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return IssueEvent{}, fmt.Errorf("sentry: decode event: %w", err)
	}
	return ev, nil
}

// DeepestInAppFrame walks an event's exception stacktrace frames and returns the
// deepest (innermost — last in Sentry's outermost→innermost frame order) frame
// flagged in_app and carrying both a filename and a line (KTD9). ok is false when
// no in-app frame qualifies — a vendored/framework-only trace — so the caller
// falls back to the issue culprit, NEVER to a non-in-app frame. Exported so the
// incident-aware fetcher can call it across the package boundary while staying a
// pure data-returner (ADR-0004). A malformed/empty event yields ok=false, never a
// panic.
func DeepestInAppFrame(ev IssueEvent) (file string, line int, ok bool) {
	for _, entry := range ev.Entries {
		if entry.Type != "exception" {
			continue
		}
		for _, val := range entry.Data.Values {
			for _, fr := range val.Stacktrace.Frames {
				if fr.InApp && fr.Filename != "" && fr.Line > 0 {
					file, line, ok = fr.Filename, fr.Line, true
				}
			}
		}
	}
	return file, line, ok
}

// Frame is the exported, distillation-safe view of one stacktrace frame — the
// per-frame allowlist the live MCP tools surface (ADR-0012, KTD3): File (relative
// only), Line, Function, and the InApp flag. File reads the relative-only,
// absolute-rejected frame field — NEVER absPath and NEVER the absPath-folded
// triage filename — so no /home/<user>/… path can leak, in-app or not. abs_path,
// local variables, and source-context lines are not on this struct: the privacy
// boundary is the SHAPE, not a downstream filter.
type Frame struct {
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Function string `json:"function,omitempty"`
	InApp    bool   `json:"in_app"`
}

// ExceptionTrace extracts an event's full exception stacktrace as an ordered,
// distillation-safe Frame slice plus the exception type and value. It returns
// EVERY frame (in_app flagged), in Sentry's outermost→innermost order — never a
// pre-filtered in-app subset (ADR-0005) — because a framework/library frame is
// sometimes the real cause. Each frame's File comes from the relative-only field
// (KTD3), so abs_path never appears regardless of in_app. ok is false when the
// event carries no exception entry (the caller renders an empty trace, never a
// panic). The returned excValue is the raw exception message; gating it behind
// include_message is the caller's job (U2) — this accessor only decodes.
func ExceptionTrace(ev IssueEvent) (excType, excValue string, frames []Frame, ok bool) {
	for _, entry := range ev.Entries {
		if entry.Type != "exception" {
			continue
		}
		ok = true
		for _, val := range entry.Data.Values {
			// Chained exceptions list values oldest→newest; the last non-empty
			// type/value is the actually-raised exception, which is what an
			// investigator wants foremost.
			if val.Type != "" {
				excType = val.Type
			}
			if val.Value != "" {
				excValue = val.Value
			}
			for _, fr := range val.Stacktrace.Frames {
				frames = append(frames, Frame{
					File:     fr.relFilename,
					Line:     fr.Line,
					Function: fr.Function,
					InApp:    fr.InApp,
				})
			}
		}
	}
	return excType, excValue, frames, ok
}
