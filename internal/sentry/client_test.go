// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a deterministic clock for backoff tests: Sleep records the
// requested delay and advances Now instead of waiting.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sleeps = append(f.sleeps, d)
	f.now = f.now.Add(d)
	return nil
}

func (f *fakeClock) sleepCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sleeps)
}

// newTestClient points a Client at a test server and swaps in a fake clock.
func newTestClient(t *testing.T, srv *httptest.Server, clk clock) *Client {
	t.Helper()
	c := NewClient(Config{BaseURL: srv.URL, Org: "acme", Token: "sntrys-test"})
	if clk != nil {
		c.clk = clk
	}
	return c
}

func TestClient_ListReleasesHappyPath(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`[
			{"version":"checkout@1.2.0","dateCreated":"2026-06-25T10:00:00Z","dateReleased":"2026-06-25T10:05:00Z","deployCount":1,
			 "lastDeploy":{"id":"d-1","environment":"production","dateFinished":"2026-06-25T10:06:00Z"}},
			{"version":"checkout@1.1.0","dateCreated":"2026-06-24T09:00:00Z","dateReleased":null,"deployCount":0,"lastDeploy":null}
		]`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	releases, next, err := c.ListReleases(context.Background(), nil, "")
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	if next != "" {
		t.Errorf("next = %q, want empty (no Link header)", next)
	}
	if len(releases) != 2 {
		t.Fatalf("got %d releases, want 2", len(releases))
	}
	r0 := releases[0]
	if r0.Version != "checkout@1.2.0" || r0.DeployCount != 1 {
		t.Errorf("release[0] = %+v", r0)
	}
	if r0.DateReleased == nil || !r0.DateReleased.Equal(time.Date(2026, 6, 25, 10, 5, 0, 0, time.UTC)) {
		t.Errorf("release[0].DateReleased = %v, want 2026-06-25T10:05:00Z", r0.DateReleased)
	}
	if r0.LastDeploy == nil || r0.LastDeploy.ID != "d-1" || r0.LastDeploy.Environment == nil || *r0.LastDeploy.Environment != "production" {
		t.Errorf("release[0].LastDeploy = %+v", r0.LastDeploy)
	}
	if !r0.LastDeploy.DateFinished.Equal(time.Date(2026, 6, 25, 10, 6, 0, 0, time.UTC)) {
		t.Errorf("lastDeploy.DateFinished = %v", r0.LastDeploy.DateFinished)
	}
	// Release without deploy: nullable fields decode to nil.
	if releases[1].DateReleased != nil || releases[1].LastDeploy != nil {
		t.Errorf("release[1] nullable fields not nil: %+v", releases[1])
	}
	if gotAuth != "Bearer sntrys-test" {
		t.Errorf("Authorization = %q, want Bearer sntrys-test", gotAuth)
	}
	if gotPath != "/api/0/organizations/acme/releases/" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestClient_ListReleasesPagination(t *testing.T) {
	page := 0
	var cursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		if page == 0 {
			page++
			// rel="next" with results="true" → there is another page.
			w.Header().Set("Link", `<`+r.Host+`/?cursor=0:0:1>; rel="previous"; results="false"; cursor="0:0:1", `+
				`<`+r.Host+`/?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"`)
			_, _ = w.Write([]byte(`[{"version":"a@1","dateCreated":"2026-06-25T10:00:00Z","deployCount":0}]`))
			return
		}
		// Terminal page: results="false" on next.
		w.Header().Set("Link", `<`+r.Host+`/?cursor=0:100:0>; rel="next"; results="false"; cursor="0:100:0"`)
		_, _ = w.Write([]byte(`[{"version":"b@2","dateCreated":"2026-06-24T10:00:00Z","deployCount":0}]`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	var all []Release
	cursor := ""
	for {
		rels, next, err := c.ListReleases(context.Background(), nil, cursor)
		if err != nil {
			t.Fatalf("ListReleases: %v", err)
		}
		all = append(all, rels...)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(all) != 2 || all[0].Version != "a@1" || all[1].Version != "b@2" {
		t.Fatalf("paginated releases = %+v", all)
	}
	if len(cursors) != 2 || cursors[0] != "" || cursors[1] != "0:100:0" {
		t.Errorf("cursors sent = %v, want [\"\", \"0:100:0\"]", cursors)
	}
}

func TestClient_ListDeploysEncodesVersionAndProject(t *testing.T) {
	var reqURI, gotProject string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqURI = r.RequestURI
		gotProject = r.URL.Query().Get("project")
		_, _ = w.Write([]byte(`[
			{"id":"d-9","environment":"production","dateFinished":"2026-06-25T11:00:00Z"},
			{"id":"d-10","environment":"staging","dateFinished":"2026-06-25T11:01:00Z"}
		]`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	deploys, err := c.ListDeploys(context.Background(), "checkout", "checkout@1.2.0/build")
	if err != nil {
		t.Fatalf("ListDeploys: %v", err)
	}
	if len(deploys) != 2 || deploys[0].ID != "d-9" || deploys[1].ID != "d-10" {
		t.Fatalf("deploys = %+v", deploys)
	}
	if deploys[0].Environment == nil || *deploys[0].Environment != "production" {
		t.Errorf("deploy[0].Environment = %v", deploys[0].Environment)
	}
	if !deploys[0].DateFinished.Equal(time.Date(2026, 6, 25, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("deploy[0].DateFinished = %v", deploys[0].DateFinished)
	}
	// The structurally dangerous '/' in the version must be percent-encoded so
	// it doesn't split into extra path segments ('@' is legal in a path segment
	// and is left as-is by url.PathEscape).
	if !strings.Contains(reqURI, "checkout@1.2.0%2Fbuild/deploys/") {
		t.Errorf("request URI %q does not contain the slash-encoded version path", reqURI)
	}
	if gotProject != "checkout" {
		t.Errorf("project param = %q, want checkout", gotProject)
	}
}

func TestClient_RateLimitBacksOffThenSucceeds(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)}
	// Reset is 5 seconds into the future at the moment of the 429.
	resetEpoch := clk.now.Add(5 * time.Second).Unix()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.Header().Set("X-Sentry-Rate-Limit-Reset", strconv.FormatInt(resetEpoch, 10))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"detail":"rate limited"}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, clk)
	if _, _, err := c.ListReleases(context.Background(), nil, ""); err != nil {
		t.Fatalf("ListReleases after backoff: %v", err)
	}
	if hits != 2 {
		t.Errorf("server hits = %d, want 2 (one 429 + one retry)", hits)
	}
	if clk.sleepCount() != 1 {
		t.Fatalf("sleeps = %d, want 1", clk.sleepCount())
	}
	if got := clk.sleeps[0]; got != 5*time.Second {
		t.Errorf("backoff = %v, want 5s (until Reset)", got)
	}
}

func TestClient_RateLimitExhaustionReturnsTypedError(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sentry-Rate-Limit-Reset", strconv.FormatInt(clk.Now().Add(time.Second).Unix(), 10))
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"detail":"rate limited"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, clk)
	c.maxRetries = 2
	_, _, err := c.ListReleases(context.Background(), nil, "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", apiErr.StatusCode)
	}
	// One initial + maxRetries backoffs = 2 sleeps.
	if clk.sleepCount() != 2 {
		t.Errorf("sleeps = %d, want 2", clk.sleepCount())
	}
}

func TestClient_Non429ErrorIsTypedAndNotRetried(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"forbidden: project:read required"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, &fakeClock{})
	_, err := c.ListDeploys(context.Background(), "checkout", "1.0")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("err = %v, want *APIError 403", err)
	}
	if hits != 1 {
		t.Errorf("server hits = %d, want 1 (4xx is not retried)", hits)
	}
}

func TestClient_5xxRetriesThenErrors(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, &fakeClock{})
	c.maxRetries = 2
	_, _, err := c.ListReleases(context.Background(), nil, "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("err = %v, want *APIError 502", err)
	}
	if hits != 3 { // 1 initial + 2 retries
		t.Errorf("server hits = %d, want 3", hits)
	}
}

func TestClient_TimeoutErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, Org: "acme", Token: "t", TimeoutSeconds: 0})
	c.httpClient.Timeout = 20 * time.Millisecond
	if _, _, err := c.ListReleases(context.Background(), nil, ""); err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
