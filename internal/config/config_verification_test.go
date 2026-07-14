// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestVerificationDefaults(t *testing.T) {
	cfg := Defaults()
	if !cfg.VerificationEnabled() {
		t.Fatal("verification must default on")
	}
	v := cfg.Triage.Verification
	if v.MaxQueries != 4 || v.QueryTimeoutSeconds != 10 || v.MaxRounds != 1 {
		t.Fatalf("unexpected defaults: %+v", v)
	}
}

func TestVerificationValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"max_rounds too high", func(c *Config) { c.Triage.Verification.MaxRounds = 2 },
			"triage: verification: max_rounds: multi-round not yet supported"},
		{"max_rounds zero", func(c *Config) { c.Triage.Verification.MaxRounds = 0 },
			"triage: verification: max_rounds: must be 1"},
		{"negative max_queries", func(c *Config) { c.Triage.Verification.MaxQueries = -1 },
			"triage: verification: max_queries: must be >= 0"},
		{"zero timeout", func(c *Config) { c.Triage.Verification.QueryTimeoutSeconds = 0 },
			"triage: verification: query_timeout_seconds: must be > 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			c := &cfg
			tc.mutate(c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q in error, got %v", tc.wantErr, err)
			}
		})
	}
}
