// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"regexp"
	"strings"
	"testing"
)

func TestPublicHandleUsesSortedScopeAndDominantSymptom(t *testing.T) {
	got, err := PublicHandle([]string{"prod", "DB 01"}, "CPU > 90%", "123e4567-e89b-12d3-a456-426614174000", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "db-01-prod-cpu-90" {
		t.Fatalf("handle = %q", got)
	}
}

func TestPublicHandleCollisionSuffixIsBoundedLowercaseBase32(t *testing.T) {
	got, err := PublicHandle([]string{strings.Repeat("A", 80)}, "database unavailable", "123e4567-e89b-12d3-a456-426614174000", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 63 || !regexp.MustCompile(`^[a-z0-9-]+-[a-z2-7]{8}$`).MatchString(got) {
		t.Fatalf("collision handle = %q (len %d)", got, len(got))
	}
	if got != PublicHandleMust(t, []string{strings.Repeat("A", 80)}, "database unavailable", "123e4567-e89b-12d3-a456-426614174000", true) {
		t.Fatal("handle is not deterministic")
	}
}

func PublicHandleMust(t *testing.T, values []string, symptom, id string, collision bool) string {
	t.Helper()
	handle, err := PublicHandle(values, symptom, id, collision)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}
