// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

func TestStorageRetentionDefaults(t *testing.T) {
	s := Defaults().Storage
	if s.RetentionDays != 90 || s.RetentionSizePercent != 80 || s.RetentionSize != "" || s.AuditRetentionDays != 365 {
		t.Fatalf("storage retention defaults = %+v, want 90 days, 80%%, no absolute size, audit 365 days", s)
	}
	if n := s.RetentionSizeBytes(); n != 0 {
		t.Fatalf("RetentionSizeBytes() = %d with no retention_size", n)
	}
}

// withStorage adds lines under the base config's storage block.
func withStorage(t *testing.T, lines string) string {
	t.Helper()
	base := situationsBaseYAML(t)
	i := strings.Index(base, "storage:\n")
	if i < 0 {
		t.Fatal("base config has no storage block")
	}
	at := i + len("storage:\n")
	return base[:at] + lines + base[at:]
}

func TestStorageRetentionValidation(t *testing.T) {
	cases := []struct {
		name, lines, wantErr string
		wantBytes            int64
	}{
		{"defaults", "", "", 0},
		{"limits off", "  retention_days: 0\n  retention_size_percent: 0\n  audit_retention_days: 0\n", "", 0},
		{"absolute size", "  retention_size: 8GiB\n", "", 8 << 30},
		{"decimal size", "  retention_size: 500MB\n", "", 500e6},
		{"size with space", "  retention_size: 2 TiB\n", "", 2 << 40},
		{"negative days", "  retention_days: -1\n", "storage.retention_days must be >= 0", 0},
		{"negative audit days", "  audit_retention_days: -5\n", "storage.audit_retention_days must be >= 0", 0},
		{"percent too high", "  retention_size_percent: 99\n", "storage.retention_size_percent must be between 0 and 95", 0},
		{"unknown unit", "  retention_size: 8gigs\n", "storage.retention_size", 0},
		{"fraction", "  retention_size: 1.5GiB\n", "storage.retention_size", 0},
		{"too small", "  retention_size: 1MiB\n", "at least 64MiB", 0},
		{"unknown key", "  retention: 30d\n", "field retention not found", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadFrom(strings.NewReader(withStorage(t, tc.lines)), "test.yaml")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := cfg.Storage.RetentionSizeBytes(); got != tc.wantBytes {
				t.Fatalf("RetentionSizeBytes() = %d, want %d", got, tc.wantBytes)
			}
		})
	}
}

func TestStorageWithoutSizeLimitWarns(t *testing.T) {
	cfg, err := LoadFrom(strings.NewReader(withStorage(t, "  retention_size_percent: 0\n")), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range cfg.Warnings() {
		found = found || strings.Contains(w, "no size limit")
	}
	if !found {
		t.Fatalf("warnings %v do not mention the missing size limit", cfg.Warnings())
	}
	cfg, err = LoadFrom(strings.NewReader(withStorage(t, "  retention_size_percent: 0\n  retention_size: 4GiB\n")), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range cfg.Warnings() {
		if strings.Contains(w, "no size limit") {
			t.Fatalf("an absolute size limit still warned: %q", w)
		}
	}
}
