// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

func oversizedIssuesBody() []byte {
	pad := strings.Repeat("x", model.MaxDecodedResponseBytes)
	return []byte(`[{"id":"1","title":"` + pad + `"}]`)
}

// TestClient_ListIssuesBoundedRefusesOversizedDecodedBody proves the
// proactive path caps the decoded body at model.MaxDecodedResponseBytes —
// far below the legacy 8 MiB maxRespBody — and reports ErrResponseTooLarge
// after exactly one accounted physical request (F10).
func TestClient_ListIssuesBoundedRefusesOversizedDecodedBody(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write(oversizedIssuesBody())
	}))
	defer srv.Close()

	c := newTestClient(t, srv, &fakeClock{})
	var befores, afters int
	_, err := c.ListIssuesBounded(context.Background(), "checkout", "", time.Now(), time.Now(), "", 10,
		func() error { befores++; return nil },
		func(bool, error) { afters++ })
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
	if calls != 1 || befores != 1 || afters != 1 {
		t.Fatalf("physical=%d befores=%d afters=%d, want exactly one accounted request", calls, befores, afters)
	}
}

// redirectServer answers the first two requests with a 302 and the third
// with body, counting physical requests.
func redirectServer(t *testing.T, body string) (*httptest.Server, *int32) {
	t.Helper()
	var physical int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		physical++
		if physical < 3 {
			http.Redirect(w, r, "/hop/"+strconv.Itoa(int(physical)), http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &physical
}

// TestClient_ListIssuesBoundedRefusesRedirect proves the instrumented path
// treats a 3xx as a final, non-retryable failure (ErrRedirectRefused,
// reported through after()) after exactly one physical attempt (F19).
func TestClient_ListIssuesBoundedRefusesRedirect(t *testing.T) {
	srv, physical := redirectServer(t, `[]`)
	clk := &fakeClock{}
	c := newTestClient(t, srv, clk)
	var befores int
	var afterErrs []error
	_, err := c.ListIssuesBounded(context.Background(), "checkout", "", time.Now(), time.Now(), "", 10,
		func() error { befores++; return nil },
		func(started bool, err error) { afterErrs = append(afterErrs, err) })
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("err = %v, want ErrRedirectRefused", err)
	}
	if *physical != 1 || befores != 1 || len(afterErrs) != 1 || !errors.Is(afterErrs[0], ErrRedirectRefused) {
		t.Fatalf("physical=%d befores=%d afters=%v, want one accounted attempt carrying the sentinel", *physical, befores, afterErrs)
	}
	if clk.sleepCount() != 0 {
		t.Fatalf("sleeps = %d, want 0: a 3xx is never retried", clk.sleepCount())
	}
}

// TestClient_ListIssuesLegacyFollowsRedirect pins that the legacy path
// keeps http.Client's default redirect policy.
func TestClient_ListIssuesLegacyFollowsRedirect(t *testing.T) {
	srv, physical := redirectServer(t, `[]`)
	c := newTestClient(t, srv, &fakeClock{})
	if _, err := c.ListIssues(context.Background(), "checkout", "", time.Now(), time.Now(), ""); err != nil {
		t.Fatalf("legacy ListIssues must still follow redirects: %v", err)
	}
	if *physical != 3 {
		t.Fatalf("physical requests = %d, want 3 (two hops followed)", *physical)
	}
}

// TestClient_ListIssuesLegacyPathNotCapped pins that the existing
// ListIssues (Acute Triage) keeps its own, looser maxRespBody behaviour.
func TestClient_ListIssuesLegacyPathNotCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(oversizedIssuesBody())
	}))
	defer srv.Close()

	c := newTestClient(t, srv, &fakeClock{})
	issues, err := c.ListIssues(context.Background(), "checkout", "", time.Now(), time.Now(), "")
	if err != nil {
		t.Fatalf("legacy ListIssues must remain on its 8 MiB cap: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(issues))
	}
}
