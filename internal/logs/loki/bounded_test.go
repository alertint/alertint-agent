// SPDX-License-Identifier: FSL-1.1-ALv2

package loki

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
