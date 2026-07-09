// SPDX-License-Identifier: FSL-1.1-ALv2

package severity

import "testing"

func TestRank_Ordering(t *testing.T) {
	// Alert-severity labels (info/warning/critical/page) and the finding gate
	// (low/medium/high) share one ascending ladder.
	pairs := []struct{ lo, hi string }{
		{"info", "warning"},
		{"warning", "error"},
		{"error", "critical"},
		{"critical", "page"},
		{"low", "medium"},
		{"medium", "high"},
		{"low", "warning"},
		{"", "info"},     // unknown/empty ranks below everything
		{"bogus", "low"}, // unknown ranks below everything
	}
	for _, p := range pairs {
		if Rank(p.lo) >= Rank(p.hi) {
			t.Errorf("Rank(%q)=%d should be < Rank(%q)=%d", p.lo, Rank(p.lo), p.hi, Rank(p.hi))
		}
	}
}

func TestRank_SlackGateValuesPreserved(t *testing.T) {
	if Rank("low") != 1 || Rank("medium") != 2 || Rank("high") != 3 {
		t.Errorf("low/medium/high must stay 1/2/3 for the Slack gate; got %d/%d/%d", Rank("low"), Rank("medium"), Rank("high"))
	}
	if Rank("") != 0 || Rank("bogus") != 0 {
		t.Errorf("unknown/empty must rank 0; got %d/%d", Rank(""), Rank("bogus"))
	}
}

func TestRank_CaseAndWhitespaceInsensitive(t *testing.T) {
	if Rank(" Critical ") != Rank("critical") {
		t.Errorf("Rank must trim and lowercase: %d != %d", Rank(" Critical "), Rank("critical"))
	}
	if Rank("WARN") != Rank("warning") {
		t.Errorf("warn and warning must rank equal: %d != %d", Rank("WARN"), Rank("warning"))
	}
}
