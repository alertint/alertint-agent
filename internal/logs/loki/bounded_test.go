// SPDX-License-Identifier: FSL-1.1-ALv2

package loki

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

func oversizedStreamsBody() []byte {
	pad := strings.Repeat("x", model.MaxDecodedResponseBytes)
	return []byte(`{"status":"success","data":{"resultType":"streams","result":[],"pad":"` + pad + `"}}`)
}

// TestFetchRecentBounded_RefusesOversizedDecodedBody proves the proactive
// path returns ErrResponseTooLarge — after reporting the one physical
// request through after() — instead of buffering a decoded body past
// model.MaxDecodedResponseBytes (F10).
func TestFetchRecentBounded_RefusesOversizedDecodedBody(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(oversizedStreamsBody())
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{BaseURL: srv.URL, LineFilter: `|~ "error"`})
	var befores int
	var afterErrs []error
	_, err := c.FetchRecentBounded(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50,
		func() error { befores++; return nil },
		func(started bool, err error) { afterErrs = append(afterErrs, err) })
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
	if calls != 1 || befores != 1 || len(afterErrs) != 1 {
		t.Fatalf("physical=%d befores=%d afters=%d, want exactly one accounted request and no fallback", calls, befores, len(afterErrs))
	}
	if !errors.Is(afterErrs[0], ErrResponseTooLarge) {
		t.Fatalf("after() must see the sentinel so the outcome is classified, got %v", afterErrs[0])
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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &physical
}

// TestFetchRecentBounded_RefusesRedirect proves the bounded path treats a
// 3xx as the final answer (ErrRedirectRefused, reported through after())
// after exactly one physical request, and never runs the unfiltered
// fallback afterwards (F19).
func TestFetchRecentBounded_RefusesRedirect(t *testing.T) {
	srv, physical := redirectServer(t, streamsBody())
	c := NewClient(Config{BaseURL: srv.URL, LineFilter: `|~ "error"`})
	var befores int
	var afterErrs []error
	_, err := c.FetchRecentBounded(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50,
		func() error { befores++; return nil },
		func(started bool, err error) { afterErrs = append(afterErrs, err) })
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("err = %v, want ErrRedirectRefused", err)
	}
	if *physical != 1 || befores != 1 || len(afterErrs) != 1 || !errors.Is(afterErrs[0], ErrRedirectRefused) {
		t.Fatalf("physical=%d befores=%d afters=%v, want one accounted request carrying the sentinel", *physical, befores, afterErrs)
	}
}

// TestFetchRecent_LegacyFollowsRedirect pins that the legacy path keeps
// http.Client's default redirect policy.
func TestFetchRecent_LegacyFollowsRedirect(t *testing.T) {
	srv, physical := redirectServer(t, streamsBody())
	c := NewClient(Config{BaseURL: srv.URL})
	if _, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50); err != nil {
		t.Fatalf("legacy FetchRecent must still follow redirects: %v", err)
	}
	if *physical != 3 {
		t.Fatalf("physical requests = %d, want 3 (two hops followed)", *physical)
	}
}

// TestFetchRecent_LegacyPathNotCapped pins that the existing unbounded
// FetchRecent (Acute Triage) is unaffected by the bounded sibling's cap.
func TestFetchRecent_LegacyPathNotCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(oversizedStreamsBody())
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{BaseURL: srv.URL})
	if _, err := c.FetchRecent(context.Background(), sel("namespace", "prod"), time.Unix(0, 0), time.Now(), 50); err != nil {
		t.Fatalf("legacy FetchRecent must remain uncapped: %v", err)
	}
}
