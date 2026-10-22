// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	_ "net/http/pprof" //nolint:gosec // G108: linked in only to prove the receivers never serve it
	"testing"
)

// TestReceiversNeverServePprof: the agent binary links net/http/pprof, which
// registers its handlers on http.DefaultServeMux. Profiles are served only
// on telemetry.pprof.addr's own listener, never on the receivers port.
func TestReceiversNeverServePprof(t *testing.T) {
	h := newHarness(t)
	response := httptest.NewRecorder()
	h.host.Handler().ServeHTTP(response, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/debug/pprof/heap?debug=1", nil))
	if response.Code == http.StatusOK {
		t.Fatalf("receivers answered /debug/pprof/heap with %d", response.Code)
	}
}
