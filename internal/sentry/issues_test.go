// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClient_ListIssuesHappyPathSendsScopedQuery(t *testing.T) {
	var gotPath string
	var gotQuery, gotEnv, gotStart, gotEnd, gotSort string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Get("query")
		gotEnv = r.URL.Query().Get("environment")
		gotStart = r.URL.Query().Get("start")
		gotEnd = r.URL.Query().Get("end")
		gotSort = r.URL.Query().Get("sort")
		_, _ = w.Write([]byte(`[
			{"id":"100","title":"KeyError: tenant","culprit":"app.checkout in pay","level":"error",
			 "count":"42","userCount":7,"firstSeen":"2026-06-26T11:54:00Z","lastSeen":"2026-06-26T12:05:00Z",
			 "metadata":{"type":"KeyError","value":"missing tenant_id"}}
		]`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	start := time.Date(2026, 6, 26, 11, 52, 0, 0, time.UTC)
	end := time.Date(2026, 6, 26, 12, 8, 0, 0, time.UTC)
	issues, err := c.ListIssues(context.Background(), "checkout", "production", start, end, "")
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if gotPath != "/api/0/projects/acme/checkout/issues/" {
		t.Errorf("path = %q, want project-scoped endpoint with slug", gotPath)
	}
	if gotQuery != "is:unresolved" {
		t.Errorf("query = %q, want is:unresolved default", gotQuery)
	}
	if gotEnv != "production" {
		t.Errorf("environment = %q, want production", gotEnv)
	}
	if gotStart != start.Format(time.RFC3339) || gotEnd != end.Format(time.RFC3339) {
		t.Errorf("window not sent as explicit start/end: start=%q end=%q", gotStart, gotEnd)
	}
	if gotSort != "date" {
		t.Errorf("sort = %q, want explicit date", gotSort)
	}
	if len(issues) != 1 {
		t.Fatalf("got %d issues, want 1", len(issues))
	}
	got := issues[0]
	if got.ID != "100" || got.Metadata.Type != "KeyError" || got.Culprit != "app.checkout in pay" {
		t.Errorf("decoded issue = %+v", got)
	}
	if got.EventCount() != 42 || got.UserCount != 7 {
		t.Errorf("counts wrong: count=%d userCount=%d", got.EventCount(), got.UserCount)
	}
	if !got.FirstSeen.Equal(time.Date(2026, 6, 26, 11, 54, 0, 0, time.UTC)) {
		t.Errorf("firstSeen = %v", got.FirstSeen)
	}
	// The exception VALUE (potential PII) is decoded only into Metadata.Value —
	// never into the rendered type — and Title is kept distinct.
	if got.Metadata.Value != "missing tenant_id" {
		t.Errorf("metadata.value = %q", got.Metadata.Value)
	}
}

func TestClient_ListIssuesEmptyEnvOmitsParam(t *testing.T) {
	var hadEnv bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadEnv = r.URL.Query()["environment"]
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	if _, err := c.ListIssues(context.Background(), "checkout", "", time.Now(), time.Now(), ""); err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if hadEnv {
		t.Error("environment param must be omitted for a project-only query")
	}
}

func TestClient_ListIssuesRateLimitedThenTypedError(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sentry-Rate-Limit-Reset", strconv.FormatInt(clk.Now().Add(time.Second).Unix(), 10))
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"detail":"rate limited"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, clk)
	c.maxRetries = 2
	_, err := c.ListIssues(context.Background(), "checkout", "", time.Now(), time.Now(), "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("err = %v, want *APIError 429", err)
	}
	if clk.sleepCount() != 2 {
		t.Errorf("sleeps = %d, want 2 (retries exhausted)", clk.sleepCount())
	}
}

func TestClient_ListIssuesUnknownProject404IsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"The requested resource does not exist"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, &fakeClock{})
	_, err := c.ListIssues(context.Background(), "no-such-slug", "", time.Now(), time.Now(), "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %v, want *APIError 404 (the unknown-slug signal the fetcher maps to R11)", err)
	}
}

func TestClient_LatestEventDeepestInAppFrame(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Frames are outermost→innermost; the deepest in-app frame is the last
		// in-app one. A deeper but in_app:false (vendored) frame must be skipped.
		_, _ = w.Write([]byte(`{
			"entries":[
				{"type":"breadcrumbs","data":{"values":[{"type":"x"}]}},
				{"type":"exception","data":{"values":[
					{"type":"KeyError","stacktrace":{"frames":[
						{"filename":"app/handler.py","lineNo":12,"inApp":true},
						{"filename":"app/checkout.py","lineNo":88,"inApp":true},
						{"filename":"site-packages/lib.py","lineNo":401,"inApp":false}
					]}}
				]}}
			]
		}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	ev, err := c.LatestEvent(context.Background(), "100")
	if err != nil {
		t.Fatalf("LatestEvent: %v", err)
	}
	file, line, ok := DeepestInAppFrame(ev)
	if !ok {
		t.Fatal("want ok=true for an event with in-app frames")
	}
	if file != "app/checkout.py" || line != 88 {
		t.Errorf("deepest in-app frame = %s:%d, want app/checkout.py:88 (skip shallower in-app + vendored)", file, line)
	}
}

func TestClient_LatestEventSnakeCaseFrameFields(t *testing.T) {
	// Self-hosted / alternate payloads have used snake_case — the tolerant
	// decoder must still find the in-app frame (KTD9 de-risking).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[{"type":"exception","data":{"values":[
			{"type":"ValueError","stacktrace":{"frames":[
				{"filename":"svc/db.go","line_no":55,"in_app":true}
			]}}
		]}}]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	ev, _ := c.LatestEvent(context.Background(), "1")
	file, line, ok := DeepestInAppFrame(ev)
	if !ok || file != "svc/db.go" || line != 55 {
		t.Errorf("snake_case frame not decoded: %s:%d ok=%v", file, line, ok)
	}
}

func TestDeepestInAppFrame_NoInAppFrameOrEmpty(t *testing.T) {
	// No in-app frame → ok=false (caller falls back to culprit).
	ev := IssueEvent{Entries: []eventEntry{{
		Type: "exception",
		Data: eventEntryData{Values: []exceptionValue{{
			Stacktrace: stacktrace{Frames: []frame{
				{Filename: "vendor/x.go", Line: 9, InApp: false},
			}},
		}}},
	}}}
	if _, _, ok := DeepestInAppFrame(ev); ok {
		t.Error("want ok=false when no frame is in-app")
	}
	// Empty event → ok=false, no panic.
	if _, _, ok := DeepestInAppFrame(IssueEvent{}); ok {
		t.Error("want ok=false for an empty event")
	}
}

func TestClient_LatestEventMalformedBodyNoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	ev, err := c.LatestEvent(context.Background(), "1")
	if err == nil {
		t.Fatal("want decode error for malformed body")
	}
	// Even the zero-value event must be safe to walk.
	if _, _, ok := DeepestInAppFrame(ev); ok {
		t.Error("malformed event must yield ok=false")
	}
}

// mkIssueT / mkEventT decode through the real JSON path so the custom
// UnmarshalJSON (flexInt, the frame relativity guard) is exercised.
func mkIssueT(t *testing.T, raw string) Issue {
	t.Helper()
	var i Issue
	if err := json.Unmarshal([]byte(raw), &i); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	return i
}

func mkEventT(t *testing.T, raw string) IssueEvent {
	t.Helper()
	var ev IssueEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	return ev
}

// jsonStr marshals s to a JSON string literal so paths with backslashes
// (Windows) embed safely in test fixtures.
func jsonStr(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal %q: %v", s, err)
	}
	return string(b)
}

// assertAbsent marshals the decoded frames and fails if needle appears anywhere —
// a serialized-output negative assertion that the allowlist held end-to-end.
func assertAbsent(t *testing.T, frames []Frame, needle string) {
	t.Helper()
	b, err := json.Marshal(frames)
	if err != nil {
		t.Fatalf("marshal frames: %v", err)
	}
	if strings.Contains(string(b), needle) {
		t.Errorf("leak: %q appears in serialized frames %s", needle, b)
	}
}

func TestIssue_PermalinkDecode(t *testing.T) {
	withLink := mkIssueT(t, `{"id":"1","permalink":"https://acme.sentry.io/issues/1/"}`)
	if withLink.Permalink != "https://acme.sentry.io/issues/1/" {
		t.Errorf("permalink = %q, want decoded URL", withLink.Permalink)
	}
	// Absent permalink → empty (never constructed).
	noLink := mkIssueT(t, `{"id":"2"}`)
	if noLink.Permalink != "" {
		t.Errorf("permalink = %q, want empty when absent", noLink.Permalink)
	}
}

func TestExceptionTrace_AllFramesInOrderWithFunctionAndInApp(t *testing.T) {
	ev := mkEventT(t, `{"dateCreated":"2026-06-26T12:05:00Z","entries":[
		{"type":"breadcrumbs","data":{"values":[{"type":"x"}]}},
		{"type":"exception","data":{"values":[{"type":"KeyError","value":"boom",
			"stacktrace":{"frames":[
				{"filename":"app/handler.py","function":"handle","lineNo":12,"inApp":true},
				{"filename":"app/checkout.py","function":"pay","lineNo":88,"inApp":true},
				{"filename":"site-packages/lib.py","function":"call","lineNo":401,"inApp":false}
			]}}]}}
	]}`)
	excType, excValue, frames, ok := ExceptionTrace(ev)
	if !ok {
		t.Fatal("want ok=true for an event with an exception entry")
	}
	if excType != "KeyError" || excValue != "boom" {
		t.Errorf("type/value = %q/%q, want KeyError/boom", excType, excValue)
	}
	if len(frames) != 3 {
		t.Fatalf("want all 3 frames (incl. the library frame), got %d", len(frames))
	}
	// Order is outermost→innermost, preserved verbatim.
	if frames[0].File != "app/handler.py" || frames[0].Function != "handle" || frames[0].Line != 12 || !frames[0].InApp {
		t.Errorf("frame[0] = %+v", frames[0])
	}
	if frames[2].File != "site-packages/lib.py" || frames[2].Function != "call" || frames[2].InApp {
		t.Errorf("library frame[2] = %+v, want in_app=false with its relative file", frames[2])
	}
	if !ev.DateCreated.Equal(time.Date(2026, 6, 26, 12, 5, 0, 0, time.UTC)) {
		t.Errorf("DateCreated = %v, want the decoded event timestamp", ev.DateCreated)
	}
}

func TestExceptionTrace_NeverSurfacesAbsPath(t *testing.T) {
	const home = "/home/deploy/app/views.py"
	// A frame carrying ONLY absPath (no filename) — and marked in_app to prove the
	// guard does not depend on the in_app flag (KTD3, unconditional rule).
	ev := mkEventT(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E",
		"stacktrace":{"frames":[{"absPath":"`+home+`","function":"render","lineNo":5,"inApp":true}]}}]}}]}`)
	_, _, frames, ok := ExceptionTrace(ev)
	if !ok || len(frames) != 1 {
		t.Fatalf("want one frame, ok, got ok=%v frames=%d", ok, len(frames))
	}
	if frames[0].File != "" {
		t.Errorf("File = %q, want empty (absPath must never surface, even in_app)", frames[0].File)
	}
	assertAbsent(t, frames, home)
}

func TestExceptionTrace_RejectsAbsoluteFilenameKey(t *testing.T) {
	// The non-Python-SDK leak: the `filename` key is ITSELF absolute (Node/Go/Ruby/
	// PHP/native). Reading the key alone would leak it; the relativity guard catches it.
	for _, abs := range []string{"/home/deploy/app/handler.js", `C:\Users\deploy\app\handler.cs`} {
		ev := mkEventT(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E",
			"stacktrace":{"frames":[{"filename":`+jsonStr(t, abs)+`,"function":"main","lineNo":9,"inApp":true}]}}]}}]}`)
		_, _, frames, ok := ExceptionTrace(ev)
		if !ok || len(frames) != 1 || frames[0].File != "" {
			t.Errorf("abs filename %q: File = %q, want empty (relativity guard, not just absPath fallback)", abs, frames[0].File)
		}
		assertAbsent(t, frames, abs)
	}
}

func TestExceptionTrace_RelativeFilenamePreserved(t *testing.T) {
	ev := mkEventT(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"E",
		"stacktrace":{"frames":[{"filename":"svc/db.go","function":"Query","line_no":55,"in_app":true}]}}]}}]}`)
	_, _, frames, ok := ExceptionTrace(ev)
	if !ok || len(frames) != 1 || frames[0].File != "svc/db.go" || frames[0].Line != 55 || frames[0].Function != "Query" {
		t.Errorf("relative frame not preserved: %+v", frames)
	}
}

func TestExceptionTrace_NoExceptionEntry(t *testing.T) {
	if _, _, _, ok := ExceptionTrace(IssueEvent{}); ok {
		t.Error("empty event must yield ok=false")
	}
	ev := mkEventT(t, `{"entries":[{"type":"breadcrumbs","data":{"values":[{"type":"x"}]}}]}`)
	if _, _, _, ok := ExceptionTrace(ev); ok {
		t.Error("an event with no exception entry must yield ok=false")
	}
}

// The PII-dense event sections (locals, source context, request, breadcrumbs,
// user) are not on the decode structs at all — a struct-shape guarantee, not a
// downstream filter (KTD3/R9). Feeding a fully-populated payload, none of those
// substrings can appear in the decoded trace.
func TestExceptionTrace_PIIDenseEventStaysOutByShape(t *testing.T) {
	ev := mkEventT(t, `{"entries":[{"type":"exception","data":{"values":[{"type":"KeyError","value":"missing key",
		"stacktrace":{"frames":[{"filename":"app/x.py","function":"f","lineNo":1,"inApp":true,
			"vars":{"password":"hunter2"},
			"context_line":"secret = load('/etc/creds')",
			"pre_context":["pre_secret_line"],
			"post_context":["post_secret_line"]}]}}]}},
		{"type":"request","data":{"url":"https://x/pay?card=4111111111111111","headers":[["Cookie","session=abc"]]}},
		{"type":"breadcrumbs","data":{"values":[{"message":"user bob@acme.com logged in"}]}}
	]}`)
	_, excValue, frames, ok := ExceptionTrace(ev)
	if !ok {
		t.Fatal("want ok")
	}
	if excValue != "missing key" {
		t.Errorf("excValue = %q", excValue)
	}
	for _, leak := range []string{"hunter2", "/etc/creds", "pre_secret_line", "post_secret_line", "4111111111111111", "session=abc", "bob@acme.com"} {
		assertAbsent(t, frames, leak)
	}
}

func TestIsAbsPath(t *testing.T) {
	abs := []string{"/home/x", "/var/log", `\\unc\share`, `\windows`, "C:\\x", "c:/x", "D:\\proj\\a.cs",
		// URI-scheme-qualified filenames (Node ESM / Deno / webpack / native SDKs)
		// carry the absolute deploy path in their path segment — rejected (KTD3).
		"file:///home/deploy/app/handler.mjs", "webpack:///home/deploy/src/pay.ts",
		"https://cdn.example.com/app.js", "app+build://home/x",
		// Leading whitespace must not let an absolute path slip past the checks.
		" /home/x", "\t/var/log"}
	rel := []string{"", "app/x.py", "svc/db.go", "site-packages/lib.py", "a.js", "./rel",
		// A bare "://" with no valid scheme prefix is not a URI — stays relative.
		"://weird", "a b/c"}
	for _, p := range abs {
		if !isAbsPath(p) {
			t.Errorf("isAbsPath(%q) = false, want true", p)
		}
	}
	for _, p := range rel {
		if isAbsPath(p) {
			t.Errorf("isAbsPath(%q) = true, want false", p)
		}
	}
}

func TestFlexInt_TolerantDecode(t *testing.T) {
	cases := map[string]int{
		`{"count":"1500"}`: 1500,
		`{"count":1500}`:   1500,
		`{"count":null}`:   0,
		`{"count":"oops"}`: 0,
		`{}`:               0,
	}
	for body, want := range cases {
		var iss Issue
		if err := json.Unmarshal([]byte(body), &iss); err != nil {
			t.Fatalf("decode %q: %v", body, err)
		}
		if iss.EventCount() != want {
			t.Errorf("count from %q = %d, want %d", body, iss.EventCount(), want)
		}
	}
}
