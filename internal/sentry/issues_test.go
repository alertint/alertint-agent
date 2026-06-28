// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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
