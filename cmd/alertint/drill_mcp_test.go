// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mcpErrorFake(t *testing.T, handler http.HandlerFunc) *mcpOneShotClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return newMCPOneShotClient(srv.URL, "tok", &http.Client{Timeout: 2 * time.Second})
}

// TestMCPOneShot_ErrorBranches covers the client's failure surfaces — the
// plan's "riskiest seam": rpc error objects, tool isError results, empty
// content, non-JSON bodies, and non-200 statuses.
func TestMCPOneShot_ErrorBranches(t *testing.T) {
	ctx := context.Background()

	cases := map[string]struct {
		handler http.HandlerFunc
		want    string
	}{
		"rpc error object": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`))
			},
			want: "rpc error -32601",
		},
		"tool isError result": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"incident \"nope\" not found"}]}}`))
			},
			want: "not found",
		},
		"empty content": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
			},
			want: "empty tool result",
		},
		"non-JSON body": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("<html>proxy error</html>"))
			},
			want: "decode response",
		},
		"http 500": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			want: "http 500",
		},
		"http 401": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			},
			want: "http 401",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := mcpErrorFake(t, tc.handler)
			_, err := c.callTool(ctx, "alertint_get_incident", map[string]any{"incident_id": "x"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("callTool = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// TestMCPOneShot_SessionHeaderCarried: the id returned by initialize rides
// every subsequent tools/call.
func TestMCPOneShot_SessionHeaderCarried(t *testing.T) {
	var toolCallSession string
	c := mcpErrorFake(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Mcp-Session-Id"), "mcp-session-") {
			toolCallSession = r.Header.Get("Mcp-Session-Id")
		}
		w.Header().Set("Mcp-Session-Id", "mcp-session-abc")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{}"}]}}`))
	})
	ctx := context.Background()
	if err := c.initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if _, err := c.callTool(ctx, "alertint_list_incidents", nil); err != nil {
		t.Fatalf("callTool: %v", err)
	}
	if toolCallSession != "mcp-session-abc" {
		t.Fatalf("tools/call session header = %q, want the initialize-returned id", toolCallSession)
	}
}
