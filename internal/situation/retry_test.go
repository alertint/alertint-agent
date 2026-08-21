// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"testing"
	"time"
)

func TestRetryPolicyNextExponentialNoJitter(t *testing.T) {
	p := RetryPolicy{Initial: 5 * time.Second, Maximum: 300 * time.Second, JitterPercent: 20}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{4, 40 * time.Second},
		{5, 80 * time.Second},
		{6, 160 * time.Second},
		{7, 300 * time.Second}, // clamped to Maximum
		{20, 300 * time.Second},
	}
	for _, tc := range cases {
		// randomUnit 0.5 applies no jitter (midpoint of the +/-20% range).
		if got := p.Next(tc.attempt, 0.5); got != tc.want {
			t.Errorf("Next(%d, 0.5) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestRetryPolicyNextAppliesJitterBounds(t *testing.T) {
	p := RetryPolicy{Initial: 5 * time.Second, Maximum: 300 * time.Second, JitterPercent: 20}
	// randomUnit=0 -> -20%, randomUnit=1 -> +20%.
	if got, want := p.Next(1, 0), 4*time.Second; got != want {
		t.Errorf("Next(1, 0) = %v, want %v", got, want)
	}
	if got, want := p.Next(1, 1), 6*time.Second; got != want {
		t.Errorf("Next(1, 1) = %v, want %v", got, want)
	}
}

func TestRetryPolicyNextClampsAttemptAndRandomUnit(t *testing.T) {
	p := RetryPolicy{Initial: 5 * time.Second, Maximum: 300 * time.Second, JitterPercent: 20}
	if got, want := p.Next(0, 0.5), 5*time.Second; got != want {
		t.Errorf("Next(0, 0.5) = %v, want %v (attempt clamped to 1)", got, want)
	}
	if got, want := p.Next(-5, 0.5), 5*time.Second; got != want {
		t.Errorf("Next(-5, 0.5) = %v, want %v (attempt clamped to 1)", got, want)
	}
	if got := p.Next(1, -1); got < 0 {
		t.Errorf("Next(1, -1) = %v, must not go negative", got)
	}
	if got, want := p.Next(1, 2), 6*time.Second; got != want {
		t.Errorf("Next(1, 2) = %v, want %v (randomUnit clamped to 1)", got, want)
	}
}

func TestRetryPolicyNextAppliesDefaults(t *testing.T) {
	var p RetryPolicy // zero value: defaults per spec (initial=5s, maximum=300s)
	if got, want := p.Next(1, 0.5), 5*time.Second; got != want {
		t.Errorf("zero-value Next(1, 0.5) = %v, want default %v", got, want)
	}
	if got, want := p.Next(20, 0.5), 300*time.Second; got != want {
		t.Errorf("zero-value Next(20, 0.5) = %v, want default max %v", got, want)
	}
}
