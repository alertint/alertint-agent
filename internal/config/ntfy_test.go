// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestLoadNTFYSelection(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		valid       bool
	}{
		{"defaults", "", true}, {"empty", "    events: []\n", true},
		{"unknown", "    events: [invented]\n", false},
		{"invalid_url", "    base_url: ftp://example.org\n", false},
		{"invalid_topic", "    topic: a/b\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(minimalValidYAML, "  stdout: true", "  stdout: true\n  ntfy:\n    enabled: true\n    topic: lab\n"+tc.extra, 1)
			cfg, err := Load(writeConfig(t, body))
			if (err == nil) != tc.valid {
				t.Fatalf("Load error = %v; valid = %v", err, tc.valid)
			}
			if err == nil && cfg == nil {
				t.Fatal("missing config")
			}
		})
	}
}
