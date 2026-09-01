// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import "testing"

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
