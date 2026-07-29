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

func TestGateRank_OnlyLowMediumHigh(t *testing.T) {
	if GateRank("low") != 1 || GateRank("medium") != 2 || GateRank("high") != 3 {
		t.Errorf("gate ladder must be low/medium/high=1/2/3; got %d/%d/%d", GateRank("low"), GateRank("medium"), GateRank("high"))
	}
	// Everything off the finding-gate ladder ranks 0 (always posts) — the gate
	// must not gain new below-threshold values as the alert ladder grows.
	for _, s := range []string{"", "warning", "info", "critical", "error", "page", "bogus"} {
		if GateRank(s) != 0 {
			t.Errorf("GateRank(%q) = %d, want 0 (off-ladder always posts)", s, GateRank(s))
		}
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

func TestRank_ZabbixVocabulary(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"information", 1},
		{"Information", 1},
		{"average", 2},
		{"Average", 2},
		{"high", 3},      // pre-existing tier, shared with "error"
		{"warning", 2},   // pre-existing tier
		{"disaster", 5},
		{"Disaster", 5},
		{"not classified", 0}, // unknown ranks below everything
	}
	for _, c := range cases {
		if got := Rank(c.in); got != c.want {
			t.Errorf("Rank(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestGateRank_UnaffectedByZabbixNames(t *testing.T) {
	for _, s := range []string{"disaster", "average", "information"} {
		if got := GateRank(s); got != 0 {
			t.Errorf("GateRank(%q) = %d, want 0 (gate vocabulary is only low/medium/high)", s, got)
		}
	}
}
