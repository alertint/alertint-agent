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
	b, _ := json.Marshal(e) //nolint:errchkjson // Expectation is plain strings/[]string; Marshal cannot fail
	return string(b)
}

// synthesizeNote derives the annotation note when the caller passes none
// (D7): deterministic, from the expectation only. MustMention/MustNotConclude
// are grading vocabulary (R6) — the note becomes GoverningVerdict.Note, which
// renders straight into the triage prompt, so those fields must NEVER
// contribute phrasing here or the model is handed its own grading rubric.
// CauseAlert is not grading vocabulary — it's the same evidence-anchor field
// that already travels separately via GoverningVerdict.CauseAlert and renders
// explicitly as a "Corrected-cause anchors:" line — so it stays.
func synthesizeNote(verdict string, e Expectation) string {
	verb := "corrected"
	if verdict == "confirmation" {
		verb = "confirmed"
	}
	if e.CauseAlert == "" {
		return verb
	}
	// Capped below store.MaxAnnotationNoteChars (leaving room for capText's
	// ellipsis marker): a schema-valid but very long cause_alert must not make
	// the synthesized note alone exceed the store's write-boundary cap, failing
	// an atomic capture on a caller who never opted into a free-text note at all.
	return capText(verb+": cause "+e.CauseAlert, store.MaxAnnotationNoteChars-1)
}

// frozenEnvelope is the decoded persist-as-rendered enrichment envelope — the
// frozen inputs replay and the stage-1 diff re-assemble from.
type frozenEnvelope struct {
	Metrics      *MetricEnrichment       `json:"metrics"`
	Logs         *LogEnrichment          `json:"logs"`
	Changes      *ChangeEnrichment       `json:"changes"`
	Sentry       *SentryEnrichment       `json:"sentry"`
	Zabbix       *ZabbixContext          `json:"zabbix"`
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
	packJSON, _ := json.Marshal(pack) //nolint:errchkjson // same EvidencePack the pipeline already marshals successfully every triage; a failure here just narrows the diff corpus, never fatal

	var b strings.Builder
	b.Write(packJSON)
	b.WriteString("\n")
	b.WriteString(s.systemPrompt(decision, len(alerts)))
	b.WriteString("\n")
	b.WriteString(decision.RootCauseHint)
	for _, r := range decision.References {
		b.WriteString("\n" + r)
	}
	metricSel := buildMetricSelector(alerts, s.cfg.MetricParams.ExtraSelectorLabels)
	if sel := renderPromMatcher(metricSel); sel != "" {
		b.WriteString("\n" + sel)
	}
	for _, m := range instanceSupplements(alerts, extraSelectorValues(metricSel, s.cfg.MetricParams.ExtraSelectorLabels)) {
		b.WriteString("\n" + m)
	}
	for _, q := range composeFloor(s.verifyParams(), s.cfg.ZabbixParams.HostLabel, alerts) {
		b.WriteString("\n" + q.Expr)
		if hs := hostsFromParams(q.Params); len(hs) > 0 {
			b.WriteString("\n" + strings.Join(hs, ","))
		}
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
	if frozen.Zabbix != nil {
		if sb, err := json.Marshal(frozen.Zabbix); err == nil {
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

// lintExpectationVerifiable warns at capture time about two distinct ways an
// expectation can never be tested:
//
//   - A correction naming NO evidence anchor at all (cause_alert,
//     cause_series, or widened evidence) can never generate a single
//     steering query — buildSteeringQueries draws exclusively from
//     cause_series and widened evidence (governingEntry.WidenExprs). Once
//     captured, Steers stays true forever with nothing to test, so
//     applySteeringCap clamps every future triage on this group key with no
//     way out until a newer capture on the key adds an anchor. This check
//     fires only for verdict=="correction" — a confirmation never steers, so
//     it carries no such obligation.
//   - The expectation's cause series is in neither the frozen snapshot
//     (verification queries/results, metric sections) nor the widened set —
//     such a verdict can never go green (D10). A query whose Outcome is
//     failed/degraded/invalid contributes nothing: its Expr still names the
//     series, but neither a failed fetch nor a query that was never executed
//     at all (invalid) is evidence the series is verifiable — counting
//     either would let a permanently-unreachable or malformed series pass the
//     lint.
func lintExpectationVerifiable(verdict string, e Expectation, frozen frozenEnvelope, widened []VerificationQuery) []string {
	var warnings []string
	if verdict == "correction" && e.CauseAlert == "" && len(e.CauseSeries) == 0 && len(widened) == 0 {
		warnings = append(warnings, "this correction names no evidence anchors (cause_alert, cause_series, or "+
			"widen_queries) — it can never be tested; every future triage on this group key will be "+
			"confidence-capped until a newer capture adds anchors")
	}

	var haystack strings.Builder
	writeIfAnswered := func(q VerificationQuery) {
		if q.Outcome == OutcomeFailed || q.Outcome == OutcomeDegraded || q.Outcome == OutcomeInvalid {
			return
		}
		haystack.WriteString(q.Expr + "\n" + q.Result + "\n")
	}
	if frozen.Verification != nil {
		for _, r := range frozen.Verification.Rounds {
			for _, q := range r.Queries {
				writeIfAnswered(q)
			}
		}
	}
	if frozen.Metrics != nil {
		if b, err := json.Marshal(frozen.Metrics); err == nil {
			haystack.Write(b)
		}
	}
	for _, q := range widened {
		writeIfAnswered(q)
	}
	hs := haystack.String()
	for _, s := range e.CauseSeries {
		if s != "" && !strings.Contains(hs, s) {
			warnings = append(warnings, fmt.Sprintf("expectation unverifiable — cause series %q is in neither snapshot nor widening; this verdict can never go green", s))
		}
	}
	return warnings
}
