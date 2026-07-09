// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"time"
)

// drillCandidate is a drill incident as seen over MCP, distilled to what the
// rerun-salt matcher needs.
type drillCandidate struct {
	ID          string
	GroupKey    string
	Status      string
	Drill       bool
	LastAlertAt time.Time
	Occurrences int
}

// drillRerunSalt scans candidate incidents for a prior drill of THIS scenario
// inside the collapse window whose group salt can be reused, so a re-fire lands
// on it (recurrence collapse) instead of minting a fresh incident. It matches:
// drill-flagged, judged (analyzed|resolved), last activity within window of now,
// every non-salted group label equal to the scenario's canned value, and the
// salted (first) label equal to the canned prefix plus a salt. It returns the
// incident id, the salt to reuse, and true; or ok=false to mint a fresh salt.
// The most recent match wins. The rerun still fires with FRESH fingerprints so
// its alerts are a new firing episode (a distinct-fingerprint attach), not an
// unchanged repeat.
func drillRerunSalt(cands []drillCandidate, groupLabels []string, now time.Time, window time.Duration) (id, salt string, ok bool) {
	saltedKey := firstGroupLabel(groupLabels)
	if saltedKey == "" {
		return "", "", false
	}
	prefix := cannedGroupValue(saltedKey) + "-"

	var best drillCandidate
	var bestSalt string
	found := false
	for _, c := range cands {
		if !c.Drill || (c.Status != "analyzed" && c.Status != "resolved") {
			continue
		}
		if now.Sub(c.LastAlertAt) > window {
			continue
		}
		labels := parseGroupKey(c.GroupKey)
		if !nonSaltedLabelsMatch(labels, groupLabels, saltedKey) {
			continue
		}
		sv, hasSalted := labels[saltedKey]
		if !hasSalted || !strings.HasPrefix(sv, prefix) {
			continue
		}
		s := strings.TrimPrefix(sv, prefix)
		if s == "" {
			continue
		}
		if !found || c.LastAlertAt.After(best.LastAlertAt) {
			best, bestSalt, found = c, s, true
		}
	}
	if !found {
		return "", "", false
	}
	return best.ID, bestSalt, true
}

func firstGroupLabel(groupLabels []string) string {
	for _, k := range groupLabels {
		if k = strings.TrimSpace(k); k != "" {
			return k
		}
	}
	return ""
}

func nonSaltedLabelsMatch(labels map[string]string, groupLabels []string, saltedKey string) bool {
	for _, k := range groupLabels {
		k = strings.TrimSpace(k)
		if k == "" || k == saltedKey {
			continue
		}
		if labels[k] != cannedGroupValue(k) {
			return false
		}
	}
	return true
}

// cannedGroupValue mirrors materializeScenario's per-label value: the canned
// value for a known key, else "drill-<key>".
func cannedGroupValue(key string) string {
	if v, ok := cannedGroupValues[key]; ok {
		return v
	}
	return "drill-" + key
}

// parseGroupKey splits the correlator's "k=v,k=v" group key into a label map.
func parseGroupKey(gk string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(gk, ",") {
		if k, v, found := strings.Cut(part, "="); found {
			out[strings.TrimSpace(k)] = v
		}
	}
	return out
}
