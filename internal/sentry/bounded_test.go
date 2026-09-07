// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

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
