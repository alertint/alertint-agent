// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"strings"
	"testing"
)

func TestPublicHandleDeterministicAndBounded(t *testing.T) {
	a, err := PublicHandle([]string{"checkout", "prod"}, "High error rate", "018f6f15-8500-7000-8000-000000000001", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PublicHandle([]string{"prod", "checkout"}, "High error rate", "018f6f15-8500-7000-8000-000000000001", false)
	if err != nil {
		t.Fatal(err)
	}
	if a != "checkout-prod-high-error-rate" || b != a || len(a) > 63 {
		t.Fatalf("handles = %q, %q", a, b)
	}
}

func TestPublicHandleCollisionGetsStableSuffix(t *testing.T) {
	got, err := PublicHandle([]string{"prod"}, "failure", "018f6f15-8500-7000-8000-000000000001", true)
	if err != nil {
		t.Fatal(err)
	}
	if got == "prod-failure" || len(got) > 63 {
		t.Fatalf("handle = %q", got)
	}
}

func TestPublicHandleCollisionRequiresValidUUID(t *testing.T) {
	_, err := PublicHandle([]string{"prod"}, "failure", "not-a-uuid", true)
	if err == nil {
		t.Fatal("want error for non-uuid situation id on collision, got nil")
	}
}

func TestPublicHandleTruncatesOversizedSlug(t *testing.T) {
	values := []string{strings.Repeat("checkout", 10), strings.Repeat("prod", 10)}
	got, err := PublicHandle(values, strings.Repeat("high error rate ", 10), "018f6f15-8500-7000-8000-000000000001", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 63 {
		t.Fatalf("handle = %q, len %d > 63", got, len(got))
	}
	if strings.HasSuffix(got, "-") {
		t.Fatalf("handle = %q, want no trailing hyphen after truncation", got)
	}
}
