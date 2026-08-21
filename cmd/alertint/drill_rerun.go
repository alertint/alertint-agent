// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// drillSituationCandidate is a Situation as seen over MCP
// (alertint_situation_list), distilled to what the rerun-salt matcher and
// the post-rerun linkage check need.
type drillSituationCandidate struct {
	ID                  string
	GroupKey            string
	Lifecycle           string
	PreviousSituationID *string
	UpdatedAt           time.Time
}

// drillSituation builds a drillSituationCandidate from its identity fields.
// An empty previousSituationID means unlinked (PreviousSituationID stays nil).
func drillSituation(id, lifecycle, previousSituationID string) drillSituationCandidate {
	c := drillSituationCandidate{ID: id, Lifecycle: lifecycle}
	if previousSituationID != "" {
		c.PreviousSituationID = &previousSituationID
	}
	return c
}

// isTerminalLifecycle reports whether lifecycle is one of the two terminal
// states (recovered, closed_unknown) that never reopen.
func isTerminalLifecycle(lifecycle string) bool {
	return lifecycle == string(model.LifecycleRecovered) || lifecycle == string(model.LifecycleClosedUnknown)
}

// isNewLinkedDrill reports whether next is the fresh, correctly-linked
// Situation the runtime mints when a rerun's exact group key lands on a
// terminal owner (spec: "Situation creation and public identity" — "If the
// latest Situation is terminal, attachment creates a new Situation linked
// through previous_situation_id"; and the Hard wiring change section: "a
// rerun after terminal recovery creates a new linked Drill Situation"): a
// different id than prior, previous_situation_id pointing back at prior, and
// prior itself actually terminal — a link claim against a nonterminal prior
// is never trusted.
func isNewLinkedDrill(prior, next drillSituationCandidate) bool {
	if next.ID == "" || next.ID == prior.ID {
		return false
	}
	if next.PreviousSituationID == nil || *next.PreviousSituationID != prior.ID {
		return false
	}
	return isTerminalLifecycle(prior.Lifecycle)
}

// drillRerunSalt scans candidate Situations for a prior drill of THIS
// scenario, inside the collapse window, whose group salt can be reused so a
// re-fire lands on its exact group key. The runtime's own Situation-identity
// rules then decide the outcome server-side (spec: "Situation creation and
// public identity" and the recurrence attach decision in the Hard wiring
// change section) — attach into the same Situation while it is active or
// recovery_pending, or mint a fresh Situation linked through
// previous_situation_id once the owner has gone terminal — so this matcher
// does not filter by lifecycle itself; the caller re-fetches the Situation
// for this exact key afterward and classifies which of the two happened. It
// matches: every non-salted group label equal to the scenario's canned
// value, and the salted (first) label equal to the canned prefix plus the
// scenario key plus a salt — the scenario key in the salted value is what
// keeps scenarios apart (their canned group labels are otherwise identical,
// so without it a storm rerun would collapse into a flagship Situation). It
// returns the matched Situation id, its lifecycle (so the caller can later
// confirm a terminal-triggered link), the salt to reuse, and true; or
// ok=false to mint a fresh salt. The most recently updated match wins. The
// rerun still fires with FRESH fingerprints so its alerts are a new firing
// episode (a distinct-fingerprint attach), not an unchanged repeat.
func drillRerunSalt(cands []drillSituationCandidate, groupLabels []string, scenarioKey string, now time.Time, window time.Duration) (id, lifecycle, salt string, ok bool) {
	groupLabels = effectiveDrillGroupLabels(groupLabels)
	saltedKey := firstGroupLabel(groupLabels)
	if saltedKey == "" || scenarioKey == "" {
		return "", "", "", false
	}
	prefix := cannedGroupValue(saltedKey) + "-" + scenarioKey + "-"

	var best drillSituationCandidate
	var bestSalt string
	found := false
	for _, c := range cands {
		if now.Sub(c.UpdatedAt) > window {
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
		if !found || c.UpdatedAt.After(best.UpdatedAt) {
			best, bestSalt, found = c, s, true
		}
	}
	if !found {
		return "", "", "", false
	}
	return best.ID, best.Lifecycle, bestSalt, true
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
