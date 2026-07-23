// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestQueryInstant_LimitParam verifies the optional server-side series bound is
// sent as the Prometheus API "limit" query parameter only when positive: a
// bounded enrichment query caps the returned series, an on-demand query (limit
// 0) stays unbounded.
func TestQueryInstant_LimitParam(t *testing.T) {
	cases := []struct {
		name  string
		limit int
		want  string // expected value of the "limit" query param ("" = absent)
	}{
		{"positive limit is sent", 200, "200"},
		{"zero limit is omitted", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			var present bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Query().Get("limit")
				_, present = r.URL.Query()["limit"]
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
			}))
			defer srv.Close()

			c := NewClient(Config{BaseURL: srv.URL, TimeoutSeconds: 5})
			if _, err := c.QueryInstant(context.Background(), `{instance="db-01"}`, time.Now(), tc.limit); err != nil {
				t.Fatalf("QueryInstant: %v", err)
			}
			if tc.want == "" {
				if present {
					t.Errorf("limit must be absent for limit=0, got %q", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("limit param = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestOrgIDHeader verifies the tenant header needed by multi-tenant
// Mimir/Cortex: X-Scope-OrgID is sent when org_id is configured and absent
// otherwise, so requests to vanilla Prometheus are byte-identical to before.
func TestOrgIDHeader(t *testing.T) {
	t.Run("set when org_id non-empty", func(t *testing.T) {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("X-Scope-Orgid") // arrives canonical regardless of how it was sent
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}))
		defer srv.Close()

		c := NewClient(Config{BaseURL: srv.URL, OrgID: "tenant-7", TimeoutSeconds: 5})
		if _, err := c.QueryInstant(context.Background(), "up", time.Time{}, 0); err != nil {
			t.Fatalf("QueryInstant: %v", err)
		}
		if got != "tenant-7" {
			t.Errorf("X-Scope-OrgID = %q, want tenant-7", got)
		}
	})

	t.Run("absent when org_id empty", func(t *testing.T) {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("X-Scope-Orgid") // arrives canonical regardless of how it was sent
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}))
		defer srv.Close()

		c := NewClient(Config{BaseURL: srv.URL, TimeoutSeconds: 5})
		if _, err := c.QueryInstant(context.Background(), "up", time.Time{}, 0); err != nil {
			t.Fatalf("QueryInstant: %v", err)
		}
		if got != "" {
			t.Errorf("X-Scope-OrgID = %q, want absent", got)
		}
	})
}
