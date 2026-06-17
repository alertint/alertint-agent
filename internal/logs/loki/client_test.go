// SPDX-License-Identifier: FSL-1.1-ALv2

package loki

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
)

// recorder records the requests a test server received.
type recorder struct {
	queries    []string
	directions []string
	limits     []string
	starts     []string
	ends       []string
	auth       []string
	orgID      []string
	paths      []string
}

// newServer starts an httptest server that records requests and replies with
// the given sequence of JSON bodies (one per request, last repeated).
func newServer(t *testing.T, rec *recorder, bodies ...string) *httptest.Server {
	t.Helper()
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.paths = append(rec.paths, r.URL.Path)
		rec.queries = append(rec.queries, r.URL.Query().Get("query"))
		rec.directions = append(rec.directions, r.URL.Query().Get("direction"))
		rec.limits = append(rec.limits, r.URL.Query().Get("limit"))
		rec.starts = append(rec.starts, r.URL.Query().Get("start"))
		rec.ends = append(rec.ends, r.URL.Query().Get("end"))
		rec.auth = append(rec.auth, r.Header.Get("Authorization"))
		// net/http canonicalizes incoming header keys, so the tenant header
		// arrives as the canonical "X-Scope-Orgid" regardless of how it was sent.
		rec.orgID = append(rec.orgID, r.Header.Get("X-Scope-Orgid"))
		body := bodies[len(bodies)-1]
		if i < len(bodies) {
			body = bodies[i]
		}
		i++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func streamsBody(streams ...string) string {
	return `{"status":"success","data":{"resultType":"streams","result":[` + strings.Join(streams, ",") + `]}}`
}

// stream builds one {"stream":{...},"values":[["ns","line"],...]} entry. The
// test inputs are simple ASCII, so %q renders valid JSON strings.
func stream(values ...[2]string) string {
	vs := make([]string, 0, len(values))
	for _, v := range values {
		vs = append(vs, fmt.Sprintf("[%q,%q]", v[0], v[1]))
	}
	return `{"stream":{"app":"api"},"values":[` + strings.Join(vs, ",") + `]}`
}

func sel(kv ...string) logs.Selector {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return logs.Selector{Labels: m}
}

func TestFetchRecent_RequestShape(t *testing.T) {
	rec := &recorder{}
	srv := newServer(t, rec, streamsBody(stream([2]string{"1718630591000000000", "ERROR boom"})))
	c := NewClient(Config{BaseURL: srv.URL, LineFilter: ""})

	start := time.Date(2026, 6, 17, 13, 48, 11, 0, time.UTC)
	end := time.Date(2026, 6, 17, 14, 3, 11, 0, time.UTC)
	_, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), start, end, 50)
	if err != nil {
		t.Fatal(err)
	}
	if rec.paths[0] != "/loki/api/v1/query_range" {
		t.Errorf("path = %q", rec.paths[0])
	}
	if rec.directions[0] != "backward" {
		t.Errorf("direction = %q, want backward", rec.directions[0])
	}
	if rec.limits[0] != "50" {
		t.Errorf("limit = %q, want 50", rec.limits[0])
	}
	// Times must be sent as RFC3339Nano and round-trip to the originals.
	if rec.starts[0] != start.Format(time.RFC3339Nano) {
		t.Errorf("start param = %q, want RFC3339Nano %q", rec.starts[0], start.Format(time.RFC3339Nano))
	}
	if rec.ends[0] != end.Format(time.RFC3339Nano) {
		t.Errorf("end param = %q, want RFC3339Nano %q", rec.ends[0], end.Format(time.RFC3339Nano))
	}
	if pt, err := time.Parse(time.RFC3339Nano, rec.starts[0]); err != nil || !pt.Equal(start) {
		t.Errorf("start not parseable RFC3339Nano: %q (%v)", rec.starts[0], err)
	}
}

func TestFetchRecent_StreamsDecode(t *testing.T) {
	rec := &recorder{}
	srv := newServer(t, rec, streamsBody(stream(
		[2]string{"1718630591000000000", "newest"},
		[2]string{"1718630590000000000", "older"},
	)))
	c := NewClient(Config{BaseURL: srv.URL, LineFilter: ""})
	got, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Lines) != 2 || got.Lines[0].Line != "newest" || got.Lines[1].Line != "older" {
		t.Fatalf("decoded lines wrong: %+v", got.Lines)
	}
	wantTS := time.Unix(0, 1718630591000000000).UTC()
	if !got.Lines[0].Timestamp.Equal(wantTS) {
		t.Errorf("ts = %v, want %v", got.Lines[0].Timestamp, wantTS)
	}
}

func TestFetchRecent_MultiStreamMergeNewestFirst(t *testing.T) {
	rec := &recorder{}
	// Three streams, each internally ordered, with interleaved timestamps. The
	// global newest line (ts ...95) lives in the SECOND stream — a naive
	// stream-order concat would not put it first.
	body := streamsBody(
		`{"stream":{"pod":"a"},"values":[["1718630593000000000","a-mid"],["1718630590000000000","a-old"]]}`,
		`{"stream":{"pod":"b"},"values":[["1718630595000000000","b-newest"],["1718630591000000000","b-old"]]}`,
		`{"stream":{"pod":"c"},"values":[["1718630594000000000","c-mid"]]}`,
	)
	srv := newServer(t, rec, body)
	c := NewClient(Config{BaseURL: srv.URL, LineFilter: ""})
	got, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"b-newest", "c-mid", "a-mid", "b-old", "a-old"}
	if len(got.Lines) != len(wantOrder) {
		t.Fatalf("got %d lines, want %d", len(got.Lines), len(wantOrder))
	}
	for i, w := range wantOrder {
		if got.Lines[i].Line != w {
			t.Fatalf("position %d = %q, want %q (merge not newest-first)", i, got.Lines[i].Line, w)
		}
	}
}

func TestFetchRecent_LabelMapTranslation(t *testing.T) {
	rec := &recorder{}
	srv := newServer(t, rec, streamsBody(stream([2]string{"1", "x"})))
	c := NewClient(Config{
		BaseURL:    srv.URL,
		LineFilter: "",
		LabelMap:   map[string]string{"service": "app", "instance": ""},
	})
	// service→app (rename), instance→drop, namespace passthrough.
	_, err := c.FetchRecent(context.Background(),
		sel("service", "api", "instance", "10.0.0.1:9100", "namespace", "prod"),
		time.Unix(0, 0), time.Now(), 50)
	if err != nil {
		t.Fatal(err)
	}
	got := rec.queries[0]
	if !strings.Contains(got, `app="api"`) {
		t.Errorf("query missing renamed app: %q", got)
	}
	if !strings.Contains(got, `namespace="prod"`) {
		t.Errorf("query missing passthrough namespace: %q", got)
	}
	if strings.Contains(got, "instance") {
		t.Errorf("dropped key instance leaked into query: %q", got)
	}
	// Deterministic sorted matcher.
	if got != `{app="api",namespace="prod"}` {
		t.Errorf("matcher = %q, want {app=\"api\",namespace=\"prod\"}", got)
	}
}

func TestFetchRecent_AllLabelsDroppedReturnsEmptyNoCall(t *testing.T) {
	rec := &recorder{}
	srv := newServer(t, rec, streamsBody())
	c := NewClient(Config{BaseURL: srv.URL, LabelMap: map[string]string{"instance": ""}})
	got, err := c.FetchRecent(context.Background(), sel("instance", "x"), time.Unix(0, 0), time.Now(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Lines) != 0 || got.Query != "" {
		t.Fatalf("want empty Fetched, got %+v", got)
	}
	if len(rec.paths) != 0 {
		t.Fatalf("expected no HTTP call when no label survives, got %d", len(rec.paths))
	}
}

func TestFetchRecent_FilteredThenFallback(t *testing.T) {
	t.Run("filtered hit, no fallback", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, streamsBody(stream([2]string{"1", "ERROR x"})))
		c := NewClient(Config{BaseURL: srv.URL, LineFilter: `|~ "error"`})
		got, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(rec.paths) != 1 {
			t.Fatalf("expected exactly 1 call, got %d", len(rec.paths))
		}
		if !strings.Contains(got.Query, `|~ "error"`) {
			t.Errorf("Fetched.Query should be the filtered query: %q", got.Query)
		}
	})

	t.Run("filtered empty, one unfiltered fallback", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec,
			streamsBody(), // filtered pass: empty
			streamsBody(stream([2]string{"1", "plain line"})), // fallback: hit
		)
		c := NewClient(Config{BaseURL: srv.URL, LineFilter: `|~ "error"`})
		got, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(rec.paths) != 2 {
			t.Fatalf("expected 2 calls (filtered+fallback), got %d", len(rec.paths))
		}
		if strings.Contains(rec.queries[1], "error") {
			t.Errorf("fallback query should have line_filter stripped: %q", rec.queries[1])
		}
		if got.Query != `{namespace="prod"}` {
			t.Errorf("Fetched.Query should be the unfiltered matcher: %q", got.Query)
		}
		if len(got.Lines) != 1 {
			t.Errorf("fallback lines = %d, want 1", len(got.Lines))
		}
	})

	t.Run("line_filter empty: single call, no fallback", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, streamsBody()) // empty, but no fallback because filter disabled
		c := NewClient(Config{BaseURL: srv.URL, LineFilter: ""})
		got, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(rec.paths) != 1 {
			t.Fatalf("expected exactly 1 call, got %d", len(rec.paths))
		}
		if got.Query != `{namespace="prod"}` {
			t.Errorf("Query = %q", got.Query)
		}
	})
}

// TestFetchRecent_FilteredBudgetExhaustedNoFallback proves the filtered and
// fallback passes share ONE deadline: when the filtered pass exhausts the
// budget, FetchRecent errors out and the fallback is never issued (§3.3 step 3).
func TestFetchRecent_FilteredBudgetExhaustedNoFallback(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		<-r.Context().Done() // block until the client deadline cancels this request
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{BaseURL: srv.URL, LineFilter: `|~ "error"`})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.FetchRecent(ctx, sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50)
	if err == nil {
		t.Fatal("expected error when the filtered pass exhausts the shared budget")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("fallback must NOT run after the filtered pass exhausts the budget: got %d calls, want 1", got)
	}
}

func TestAuthModes(t *testing.T) {
	t.Run("none: no header", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, streamsBody(stream([2]string{"1", "x"})))
		c := NewClient(Config{BaseURL: srv.URL, AuthMode: "none", LineFilter: ""})
		_, _ = c.FetchRecent(context.Background(), sel("namespace", "p"), time.Unix(0, 0), time.Now(), 1)
		if rec.auth[0] != "" {
			t.Errorf("auth header = %q, want empty", rec.auth[0])
		}
	})
	t.Run("bearer", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, streamsBody(stream([2]string{"1", "x"})))
		c := NewClient(Config{BaseURL: srv.URL, AuthMode: "bearer", Secret: "tok123", LineFilter: ""})
		_, _ = c.FetchRecent(context.Background(), sel("namespace", "p"), time.Unix(0, 0), time.Now(), 1)
		if rec.auth[0] != "Bearer tok123" {
			t.Errorf("auth = %q", rec.auth[0])
		}
	})
	t.Run("basic", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, streamsBody(stream([2]string{"1", "x"})))
		c := NewClient(Config{BaseURL: srv.URL, AuthMode: "basic", Username: "123456", Secret: "pw", LineFilter: ""})
		_, _ = c.FetchRecent(context.Background(), sel("namespace", "p"), time.Unix(0, 0), time.Now(), 1)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("123456:pw"))
		if rec.auth[0] != want {
			t.Errorf("auth = %q, want %q", rec.auth[0], want)
		}
	})
}

func TestOrgIDHeader(t *testing.T) {
	t.Run("set when org_id non-empty", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, streamsBody(stream([2]string{"1", "x"})))
		c := NewClient(Config{BaseURL: srv.URL, OrgID: "tenant-7", LineFilter: ""})
		_, _ = c.FetchRecent(context.Background(), sel("namespace", "p"), time.Unix(0, 0), time.Now(), 1)
		if rec.orgID[0] != "tenant-7" {
			t.Errorf("X-Scope-OrgID = %q, want tenant-7", rec.orgID[0])
		}
	})
	t.Run("absent when org_id empty", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, streamsBody(stream([2]string{"1", "x"})))
		c := NewClient(Config{BaseURL: srv.URL, LineFilter: ""})
		_, _ = c.FetchRecent(context.Background(), sel("namespace", "p"), time.Unix(0, 0), time.Now(), 1)
		if rec.orgID[0] != "" {
			t.Errorf("X-Scope-OrgID = %q, want empty", rec.orgID[0])
		}
	})
}

func TestNonSuccessEnvelopeIsError(t *testing.T) {
	rec := &recorder{}
	srv := newServer(t, rec, `{"status":"error","errorType":"bad_data","error":"parse error"}`)
	c := NewClient(Config{BaseURL: srv.URL, LineFilter: ""})
	_, err := c.FetchRecent(context.Background(), sel("namespace", "p"), time.Unix(0, 0), time.Now(), 1)
	if err == nil {
		t.Fatal("expected error for non-success envelope")
	}
}

func TestHTTPErrorStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("no auth"))
	}))
	t.Cleanup(srv.Close)
	c := NewClient(Config{BaseURL: srv.URL, LineFilter: ""})
	_, err := c.FetchRecent(context.Background(), sel("namespace", "p"), time.Unix(0, 0), time.Now(), 1)
	if err == nil || !strings.Contains(err.Error(), "http 401") {
		t.Fatalf("want http 401 error, got %v", err)
	}
}

func TestQueryRange_Passthrough(t *testing.T) {
	rec := &recorder{}
	srv := newServer(t, rec, `{"status":"success","data":{"resultType":"streams","result":[]}}`)
	c := NewClient(Config{BaseURL: srv.URL})
	data, err := c.QueryRange(context.Background(), `{app="api"} |= "boom"`, time.Unix(0, 0), time.Now(), 100, "forward")
	if err != nil {
		t.Fatal(err)
	}
	if rec.queries[0] != `{app="api"} |= "boom"` {
		t.Errorf("passthrough query mangled: %q", rec.queries[0])
	}
	if rec.directions[0] != "forward" {
		t.Errorf("direction = %q, want forward", rec.directions[0])
	}
	if rec.limits[0] != "100" {
		t.Errorf("limit = %q, want 100", rec.limits[0])
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("data not raw JSON: %v", err)
	}
	if parsed["resultType"] != "streams" {
		t.Errorf("passthrough did not return raw data: %v", parsed)
	}
}

func TestQueryRange_DefaultsDirectionBackward(t *testing.T) {
	rec := &recorder{}
	srv := newServer(t, rec, `{"status":"success","data":{}}`)
	c := NewClient(Config{BaseURL: srv.URL})
	_, _ = c.QueryRange(context.Background(), `{app="api"}`, time.Unix(0, 0), time.Now(), 0, "")
	if rec.directions[0] != "backward" {
		t.Errorf("default direction = %q, want backward", rec.directions[0])
	}
	if rec.limits[0] != "" {
		t.Errorf("limit should be omitted when 0, got %q", rec.limits[0])
	}
}
