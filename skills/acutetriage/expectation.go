// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Expectation is the agent-authored structured label of a captured verdict
// (D7): the discriminating evidence and the conclusion constraints the
// expectation diff grades against. Presence checks only — nothing fuzzier.
type Expectation struct {
	CauseAlert      string   `json:"cause_alert,omitempty"`
	CauseSeries     []string `json:"cause_series,omitempty"`
	SeverityRank    string   `json:"severity_rank,omitempty"`
	MustMention     []string `json:"must_mention,omitempty"`
	MustNotConclude []string `json:"must_not_conclude,omitempty"`
}

// parseExpectation strictly decodes the tool argument. At least one graded
// field (must_mention / must_not_conclude) is required — an expectation with
// neither could never turn a grade red or green.
func parseExpectation(raw json.RawMessage) (Expectation, error) {
	var e Expectation
	if len(raw) == 0 {
		return e, errors.New("acutetriage: capture: expectation is required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, fmt.Errorf("acutetriage: capture: expectation: %w", err)
	}
	if len(e.MustMention) == 0 && len(e.MustNotConclude) == 0 {
		return e, errors.New("acutetriage: capture: expectation needs must_mention or must_not_conclude")
	}
	return e, nil
}

// canonicalExpectationJSON is the stable at-rest / comparison encoding
// (struct field order is fixed, so byte equality means semantic equality).
func canonicalExpectationJSON(e Expectation) string {
	b, _ := json.Marshal(e)
	return string(b)
}

// synthesizeNote derives the annotation note when the caller passes none
// (D7): deterministic, from the expectation only.
func synthesizeNote(verdict string, e Expectation) string {
	verb := "corrected"
	if verdict == "confirmation" {
		verb = "confirmed"
	}
	var parts []string
	if e.CauseAlert != "" {
		parts = append(parts, "cause "+e.CauseAlert)
	}
	if len(e.MustMention) > 0 {
		parts = append(parts, "must mention "+strings.Join(e.MustMention, ", "))
	}
	if len(e.MustNotConclude) > 0 {
		parts = append(parts, "not "+strings.Join(e.MustNotConclude, ", "))
	}
	if len(parts) == 0 {
		return verb
	}
	return verb + ": " + strings.Join(parts, "; ")
}
