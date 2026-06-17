// SPDX-License-Identifier: FSL-1.1-ALv2

package logs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mkLine(sec int, text string) Line {
	return Line{Timestamp: time.Unix(int64(sec), 0).UTC(), Line: text}
}

func TestNormalize_EmptyInput(t *testing.T) {
	if got := Normalize(nil, MaxBytes, MaxLineChars); got != nil {
		t.Fatalf("Normalize(nil) = %v, want nil", got)
	}
}

func TestNormalize_PerLineTruncation(t *testing.T) {
	long := strings.Repeat("x", 1200)
	out := Normalize([]Line{mkLine(3, long)}, MaxBytes, MaxLineChars)
	if len(out) != 1 {
		t.Fatalf("got %d lines, want 1", len(out))
	}
	if got := len([]rune(out[0].Line)); got != MaxLineChars {
		t.Fatalf("line truncated to %d runes, want %d", got, MaxLineChars)
	}
}

func TestNormalize_MultibyteTruncationDoesNotSplit(t *testing.T) {
	// 600 multi-byte runes; truncating to 500 must yield exactly 500 valid runes.
	in := strings.Repeat("é", 600)
	out := Normalize([]Line{mkLine(1, in)}, MaxBytes, MaxLineChars)
	if got := len([]rune(out[0].Line)); got != MaxLineChars {
		t.Fatalf("rune count = %d, want %d", got, MaxLineChars)
	}
	for _, r := range out[0].Line {
		if r == '�' {
			t.Fatal("truncation split a multi-byte rune")
		}
	}
}

func TestNormalize_ByteCapDropsTailOldest(t *testing.T) {
	// Newest-first input: ts 100 (newest) .. 96 (oldest). 80-byte lines, cap 200
	// => only the first 2 (newest) survive; the tail (oldest) is dropped.
	body := strings.Repeat("a", 80)
	in := []Line{
		mkLine(100, body), // newest — kept
		mkLine(99, body),  // kept (total 160 <= 200)
		mkLine(98, body),  // would push to 240 > 200 — dropped
		mkLine(97, body),
		mkLine(96, body), // oldest
	}
	out := Normalize(in, 200, MaxLineChars)
	if len(out) != 2 {
		t.Fatalf("kept %d lines, want 2", len(out))
	}
	// Order preserved and the survivors are the newest two.
	if !out[0].Timestamp.Equal(in[0].Timestamp) || !out[1].Timestamp.Equal(in[1].Timestamp) {
		t.Fatalf("survivors are not the newest-first prefix: %v", out)
	}
}

func TestNormalize_AlwaysKeepsNewestEvenIfOversized(t *testing.T) {
	// First line alone exceeds the byte cap; it must still survive (post per-line
	// truncation it is <= MaxLineChars bytes, but the cap here is smaller).
	body := strings.Repeat("a", 400) // 400 bytes, cap 100
	out := Normalize([]Line{mkLine(5, body), mkLine(4, body)}, 100, MaxLineChars)
	if len(out) != 1 {
		t.Fatalf("kept %d lines, want exactly 1 (newest)", len(out))
	}
	if !out[0].Timestamp.Equal(time.Unix(5, 0).UTC()) {
		t.Fatal("kept line is not the newest")
	}
}

func TestNormalize_PreservesOrder(t *testing.T) {
	in := []Line{mkLine(10, "c"), mkLine(9, "b"), mkLine(8, "a")}
	out := Normalize(in, MaxBytes, MaxLineChars)
	if len(out) != 3 {
		t.Fatalf("kept %d, want 3", len(out))
	}
	for i := range in {
		if out[i].Line != in[i].Line {
			t.Fatalf("order changed at %d: %q != %q", i, out[i].Line, in[i].Line)
		}
	}
}

func TestSelectorRoundTrip(t *testing.T) {
	sel := Selector{Labels: map[string]string{"namespace": "prod", "service": "api"}}
	if sel.Labels["namespace"] != "prod" || sel.Labels["service"] != "api" {
		t.Fatal("selector did not carry labels")
	}
}

func TestLineJSONRoundTrip(t *testing.T) {
	ln := Line{Timestamp: time.Unix(1718630591, 0).UTC(), Line: "ERROR boom"}
	b, err := json.Marshal(ln)
	if err != nil {
		t.Fatal(err)
	}
	var back Line
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Timestamp.Equal(ln.Timestamp) || back.Line != ln.Line {
		t.Fatalf("round-trip mismatch: %+v != %+v", back, ln)
	}
}

func TestAllowedSelectorKeys_ExcludesAlertMetadata(t *testing.T) {
	allowed := map[string]bool{}
	for _, k := range AllowedSelectorKeys {
		allowed[k] = true
	}
	for _, want := range []string{"namespace", "service", "job", "pod", "container", "instance"} {
		if !allowed[want] {
			t.Fatalf("AllowedSelectorKeys missing %q", want)
		}
	}
	for _, noise := range []string{"alertname", "severity", "prometheus"} {
		if allowed[noise] {
			t.Fatalf("AllowedSelectorKeys must not include alert-metadata key %q", noise)
		}
	}
}
