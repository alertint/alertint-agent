// SPDX-License-Identifier: FSL-1.1-ALv2

package anthropic

import (
	"testing"
	"time"
)

// TestTimeoutDefaultPreserved locks the historical hardcoded 120 s HTTP timeout:
// a Config that leaves TimeoutSeconds unset must still get the 120 s budget the
// triage client has always used, so the shadow-classifier parameterization does
// not silently shorten the triage call.
func TestTimeoutDefaultPreserved(t *testing.T) {
	c := New(Config{APIKey: "k"}, nil, nil)
	if got := c.http.Timeout; got != 120*time.Second {
		t.Errorf("default http timeout = %v, want 120s", got)
	}
}

// TestTimeoutParameterized locks the seconds-scale budget the classifier needs:
// a set Config.TimeoutSeconds becomes the client's HTTP timeout, so a second
// Haiku client can bound itself far below the triage client's 120 s.
func TestTimeoutParameterized(t *testing.T) {
	c := New(Config{APIKey: "k", TimeoutSeconds: 10}, nil, nil)
	if got := c.http.Timeout; got != 10*time.Second {
		t.Errorf("http timeout = %v, want 10s", got)
	}
}
