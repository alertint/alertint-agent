// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/alertint/alertint-agent/internal/store"
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

// frozenEnvelope is the decoded persist-as-rendered enrichment envelope — the
// frozen inputs replay and the stage-1 diff re-assemble from.
type frozenEnvelope struct {
	Metrics      *MetricEnrichment       `json:"metrics"`
	Logs         *LogEnrichment          `json:"logs"`
	Changes      *ChangeEnrichment       `json:"changes"`
	Sentry       *SentryEnrichment       `json:"sentry"`
	Memory       *MemoryEnrichment       `json:"memory"`
	Verification *VerificationEnrichment `json:"verification"`
}

// decodeFrozenEnvelope is defensive: "" or malformed JSON yields a zero
// envelope (sections simply absent), never an error — mirrors
// corroboratingIssueIDs in internal/store/memory.go.
func decodeFrozenEnvelope(enrichmentJSON string) frozenEnvelope {
	var env frozenEnvelope
	if enrichmentJSON == "" {
		return env
	}
	_ = json.Unmarshal([]byte(enrichmentJSON), &env)
	return env
}

// stage1Corpus assembles the DETERMINISTIC evidence surfaces current rules
// assemble for this incident — everything the pipeline would put in front of
// the model before any LLM call: the evidence pack, the rules decision's
// prompt template + hint + references, the metric-selector and floor exprs,
// and the frozen metrics/logs/changes/sentry sections. Memory is deliberately
// EXCLUDED (R18: context, never evidence — and a captured correction must not
// grade itself green). No I/O, no LLM.
func (s *Skill) stage1Corpus(inc store.Incident, alerts []store.Alert, frozen frozenEnvelope) string {
	decision := s.cfg.Rules.EvaluateIncident(alerts)
	pack := BuildEvidencePack(inc, alerts, s.cfg.WindowSeconds)
	packJSON, _ := json.Marshal(pack)

	var b strings.Builder
	b.Write(packJSON)
	b.WriteString("\n")
	b.WriteString(s.systemPrompt(decision, len(alerts)))
	b.WriteString("\n")
	b.WriteString(decision.RootCauseHint)
	for _, r := range decision.References {
		b.WriteString("\n" + r)
	}
	if sel := renderPromMatcher(buildMetricSelector(alerts)); sel != "" {
		b.WriteString("\n" + sel)
	}
	for _, m := range instanceSupplements(alerts) {
		b.WriteString("\n" + m)
	}
	for _, q := range floorPlan(alerts) {
		b.WriteString("\n" + q.Expr)
	}
	if frozen.Metrics != nil {
		if sb, err := json.Marshal(frozen.Metrics); err == nil {
			b.WriteString("\n")
			b.Write(sb)
		}
	}
	if frozen.Logs != nil {
		if sb, err := json.Marshal(frozen.Logs); err == nil {
			b.WriteString("\n")
			b.Write(sb)
		}
	}
	if frozen.Changes != nil {
		if sb, err := json.Marshal(frozen.Changes); err == nil {
			b.WriteString("\n")
			b.Write(sb)
		}
	}
	if frozen.Sentry != nil {
		if sb, err := json.Marshal(frozen.Sentry); err == nil {
			b.WriteString("\n")
			b.Write(sb)
		}
	}
	return b.String()
}

// evidenceDiff is the stage-1 result: what the expectation needs that the
// assembled pack lacks. Either list non-empty ⇒ red, layer evidence-selection.
type evidenceDiff struct {
	MissingSeries   []string
	MissingSubjects []string
}

func diffExpectationAgainstPack(e Expectation, corpus string) evidenceDiff {
	var d evidenceDiff
	for _, s := range e.CauseSeries {
		if s != "" && !strings.Contains(corpus, s) { // series names are case-sensitive
			d.MissingSeries = append(d.MissingSeries, s)
		}
	}
	lower := strings.ToLower(corpus)
	for _, m := range e.MustMention {
		if m != "" && !strings.Contains(lower, strings.ToLower(m)) {
			d.MissingSubjects = append(d.MissingSubjects, m)
		}
	}
	return d
}

// diffExpectationAgainstFinding is the stage-2 judgment: presence checks over
// the replayed finding's text. missingMention/badConclusions non-empty ⇒ red,
// layer synthesis. severity_rank / cause_alert mismatches are warnings only —
// red/green stays on the two presence checks ("nothing fuzzier").
func diffExpectationAgainstFinding(e Expectation, resp llmResponse) (missingMention, badConclusions, warnings []string) {
	text := strings.ToLower(resp.AnalysisName + "\n" + resp.OverallIssue + "\n" + strings.Join(resp.CorrelationFindings, "\n"))
	for _, m := range e.MustMention {
		if m != "" && !strings.Contains(text, strings.ToLower(m)) {
			missingMention = append(missingMention, m)
		}
	}
	for _, c := range e.MustNotConclude {
		if c != "" && strings.Contains(text, strings.ToLower(c)) {
			badConclusions = append(badConclusions, c)
		}
	}
	if e.SeverityRank != "" && !strings.EqualFold(e.SeverityRank, resp.Severity) {
		warnings = append(warnings, fmt.Sprintf("severity %q differs from expected %q", resp.Severity, e.SeverityRank))
	}
	if e.CauseAlert != "" && !strings.Contains(text, strings.ToLower(e.CauseAlert)) {
		warnings = append(warnings, fmt.Sprintf("finding does not name expected cause alert %q", e.CauseAlert))
	}
	return missingMention, badConclusions, warnings
}

// lintExpectationVerifiable warns when the expectation's cause series is in
// neither the frozen snapshot (verification queries/results, metric sections)
// nor the widened set — such a verdict can never go green (D10).
func lintExpectationVerifiable(e Expectation, frozen frozenEnvelope, widened []VerificationQuery) []string {
	var haystack strings.Builder
	if frozen.Verification != nil {
		for _, r := range frozen.Verification.Rounds {
			for _, q := range r.Queries {
				haystack.WriteString(q.Expr + "\n" + q.Result + "\n")
			}
		}
	}
	if frozen.Metrics != nil {
		if b, err := json.Marshal(frozen.Metrics); err == nil {
			haystack.Write(b)
		}
	}
	for _, q := range widened {
		haystack.WriteString(q.Expr + "\n" + q.Result + "\n")
	}
	hs := haystack.String()
	var warnings []string
	for _, s := range e.CauseSeries {
		if s != "" && !strings.Contains(hs, s) {
			warnings = append(warnings, fmt.Sprintf("expectation unverifiable — cause series %q is in neither snapshot nor widening; this verdict can never go green", s))
		}
	}
	return warnings
}
