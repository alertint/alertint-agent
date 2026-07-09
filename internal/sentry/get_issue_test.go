// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClient_GetIssue_DecodesOnlyAllowlistedFields verifies the disposition-lite
// read hits /api/0/issues/{id}/ and decodes ONLY status + lastSeen — the sensitive
// culprit/metadata/title fields in the response never enter IssueStatus.
func TestClient_GetIssue_DecodesOnlyAllowlistedFields(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{
			"id":"ISSUE-1","status":"resolved","lastSeen":"2026-07-06T02:00:00Z",
			"culprit":"SECRET culprit path","title":"SECRET boom",
			"metadata":{"value":"SECRET exception text"}
		}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	st, err := c.GetIssue(context.Background(), "ISSUE-1")
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if gotPath != "/api/0/issues/ISSUE-1/" {
		t.Errorf("path = %q, want /api/0/issues/ISSUE-1/", gotPath)
	}
	if st.Status != "resolved" || st.LastSeen != "2026-07-06T02:00:00Z" {
		t.Errorf("decoded = %+v, want status=resolved lastSeen=2026-07-06T02:00:00Z", st)
	}
	// The narrow struct cannot carry the sensitive fields — a receipt on the boundary.
	if strings.Contains(st.Status+st.LastSeen, "SECRET") {
		t.Errorf("sensitive fields leaked into IssueStatus: %+v", st)
	}
}

func TestClient_GetIssue_NotFoundIsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"The requested resource does not exist"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv, nil)
	_, err := c.GetIssue(context.Background(), "GONE")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("GetIssue on 404 = %v, want *APIError{404}", err)
	}
}
