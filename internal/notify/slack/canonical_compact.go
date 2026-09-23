// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/alertint/alertint-agent/internal/situation/model"
	prommodel "github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql/parser"
	slacklib "github.com/slack-go/slack"
)

// Only known redundant status text is removed; arbitrary detail can carry a
// limitation or retry disposition and must survive compaction.
func compactSourceResult(c model.SourceCheck) (symbol, result string) {
	detail := strings.TrimSpace(c.Detail)
	detail = strings.TrimPrefix(detail, "Query succeeded; ")
	detail = strings.TrimPrefix(detail, "query succeeded; ")
	switch c.Outcome {
	case model.SourceCheckConfigured:
		symbol, result = "·", "awaiting results"
		if strings.EqualFold(detail, "Configured; awaiting collection result") {
			detail = ""
		}
	case model.SourceCheckEmpty:
		symbol, result = "∅", "query succeeded · empty result"
		if c.Source == "Changes" {
			symbol, result = "✓", "query succeeded · no records in the checked window"
			if strings.EqualFold(detail, "no changes in window") {
				detail = ""
			}
		}
		if detail == "(no data)" {
			detail = ""
		}
	case model.SourceCheckReturned:
		symbol, result = "✓", "data returned"
		if c.RecordsKnown {
			result = fmt.Sprintf("%s %s returned", canonicalNumber(c.Records), canonicalSourceUnit(c.Unit))
		}
		if detail != "" && (!c.RecordsKnown || strings.HasPrefix(detail, fmt.Sprintf("%d ", c.Records))) {
			result = ""
		}
	case model.SourceCheckFailed:
		symbol, result = "✕", "query failed"
		if c.CallsKnown && c.Calls > 0 && !strings.Contains(strings.ToLower(detail), "attempt") {
			unit := "attempts"
			if c.Calls == 1 {
				unit = "attempt"
			}
			result += fmt.Sprintf(" · %d %s", c.Calls, unit)
		}
	case model.SourceCheckSkipped:
		symbol, result = "—", "not queried"
	default:
		symbol, result = "?", "result unavailable"
	}
	if detail != "" {
		if result != "" {
			result += " · "
		}
		result += detail
	}
	return symbol, result
}

// Old recorded checks used model rationales as labels. Shorten recognizable
// subjects only; never publish the rationale's speculative causal implication.
func compactCheckName(name string) string {
	if len(name) <= 80 {
		return name
	}
	// Retain a short first clause when possible, without a truncated sentence.
	for _, sep := range []string{";", ". "} {
		if first, _, ok := strings.Cut(name, sep); ok && len(first) <= 80 {
			return first
		}
	}
	return "Recorded check"
}

func compactObservation(observation string) string {
	text := strings.TrimSpace(observation)
	if strings.HasPrefix(text, "Log sample at ") {
		if _, body, ok := strings.Cut(text, " UTC: "); ok {
			text = "Log sample: " + body
		}
	}
	// A metadata-only tail after a complete log sentence is not the message.
	// Keep identifiers inside the narrative; raw attributes remain in evidence
	// storage. Supported findings are never passed through this excerpt helper.
	text = strings.Join(strings.Fields(text), " ")
	if !strings.HasPrefix(text, "Log sample: ") {
		return text
	}
	at := strings.LastIndex(text, ". ")
	if at < 0 {
		return text
	}
	for _, field := range strings.Fields(text[at+2:]) {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" || value == "" {
			return text
		}
	}
	return text[:at+1]
}

func compactInvestigationStep(step string, b *model.OperatorBriefing) string {
	// Only replace a real execution statement. Queued, waiting, blocked and
	// superseded work retain their recorded disposition.
	if !strings.HasPrefix(step, "Investigating") {
		return step
	}
	scope := briefingExecutionScope(b)
	scope = strings.Replace(scope, " for "+briefingScope(b), "", 1)
	return "Investigating" + scope + strings.TrimPrefix(step, "Investigating"+briefingExecutionScope(b))
}

func compactRecoveryDeadline(step string, t model.Transition, b *model.OperatorBriefing) string {
	grace := b.Work.SourceGraceUntil
	if t.Lifecycle != model.LifecycleRecoveryPending || grace == nil {
		return step
	}
	old := SlackDateToken(*grace, "{time}")
	step = strings.Replace(step, "through "+old, "until "+SlackDateToken(*grace, "{time_secs}"), 1)
	if t.ActionContract.NextUpdateAt != nil && grace.Equal(*t.ActionContract.NextUpdateAt) {
		step = strings.Replace(step, " Next status check: "+old+".", "", 1)
		step = strings.Replace(step, "until "+SlackDateToken(*grace, "{time_secs}")+".", "until "+SlackDateToken(*grace, "{time_secs}")+", when the next status check is scheduled.", 1)
	}
	return step
}

// Canonical activity is a separate leading section, so oversized evidence can
// never remove it. Historical/legacy messages keep their existing block path.
func canonicalDetailBlocks(detail string, terminal bool) []slacklib.Block {
	var metadata string
	if terminal {
		if body, tail, ok := strings.Cut(detail, "*Confirmed:*"); ok {
			detail = body
			metadata = "*Confirmed:*" + tail
			if times, mcp, found := strings.Cut(metadata, "\n\n*MCP:*"); found {
				metadata = times
				detail += "\n\n*MCP:*" + mcp
			}
		}
	}
	context := briefingSections(strings.TrimSpace(metadata))
	first, rest, _ := strings.Cut(strings.TrimSpace(detail), "\n\n")
	blocks := briefingSections(first)
	evidence := briefingSections(rest)
	// Reserve three blocks for headline, delivery markers and recorded time.
	if len(blocks)+len(evidence)+len(context) > 47 {
		blocks = append(blocks, sectionBlock("Evidence exceeds Slack's message size. Details via MCP."))
		for _, paragraph := range strings.Split(rest, "\n\n") {
			if strings.HasPrefix(paragraph, "*Action:*") || strings.HasPrefix(paragraph, "*MCP:*") {
				blocks = append(blocks, briefingSections(paragraph)...)
			}
		}
	} else {
		blocks = append(blocks, evidence...)
	}
	return append(blocks, context...)
}

// Only shorten the known lookup result grammar. Unrecognized resource labels
// stay intact rather than losing the identity that distinguishes incidents.
var compactOtherAlertPattern = regexp.MustCompile(`alertname=([^,;]+),service=([^ ,;]+) \((?:critical|warning|info), (?:ready|analyzed|collecting|failed|resolved)\)`)

func compactOtherAlerts(detail string) string {
	detail = strings.Replace(detail, " incidents on other group keys (", " incidents (", 1)
	return compactOtherAlertPattern.ReplaceAllString(detail, "$1 · $2")
}

// Only completed, reconciled diagnoses are eligible. Keep the original
// interpretation wording; the shared Finding label does not change verification.
func canonicalWorkingDiagnosis(b *model.OperatorBriefing) string {
	for _, a := range b.Analyses {
		if a.Verification != "revised" || briefingDraft(a) {
			continue
		}
		if summary := canonicalShort(strings.TrimSpace(a.Summary), 500); summary != "" {
			return summary
		}
		if title := canonicalShort(strings.TrimPrefix(a.Title, "Hypothesis: "), 180); title != "" {
			return title
		}
	}
	return ""
}

func canonicalCheckName(c model.SourceCheck) string {
	if c.Kind != "promql" || c.QueryExpr == "" {
		return compactCheckName(c.Check)
	}
	expr, err := parser.NewParser(parser.Options{}).ParseExpr(c.QueryExpr)
	if err != nil {
		return "PromQL check"
	}
	var metrics, grouping, scope []string
	addScope := func(value string) {
		for _, existing := range scope {
			if existing == value {
				return
			}
		}
		scope = append(scope, value)
	}
	prefix := ""
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		switch n := node.(type) {
		case *parser.VectorSelector:
			for _, matcher := range n.LabelMatchers {
				if matcher.Name != "__name__" {
					addScope(matcher.String())
				}
			}
			if n.OriginalOffset != 0 {
				addScope("offset " + prommodel.Duration(n.OriginalOffset).String())
			}
			if n.Name != "" {
				name := strings.TrimSuffix(strings.TrimSuffix(n.Name, "_bucket"), "_total")
				name = strings.ReplaceAll(name, "_", " ")
				found := false
				for _, m := range metrics {
					if m == name {
						found = true
					}
				}
				if !found {
					metrics = append(metrics, name)
				}
			}
		case *parser.MatrixSelector:
			addScope(prommodel.Duration(n.Range).String() + " window")
		case *parser.Call:
			if n.Func.Name == "histogram_quantile" && len(n.Args) > 0 {
				if q, ok := n.Args[0].(*parser.NumberLiteral); ok {
					prefix = fmt.Sprintf("P%g ", q.Val*100)
				}
			}
		case *parser.AggregateExpr:
			if len(n.Grouping) > 0 {
				kind := " by "
				if n.Without {
					kind = " without "
				}
				grouping = append(grouping, kind+strings.ReplaceAll(strings.Join(n.Grouping, ", "), "_", " "))
			}
		}
		return nil
	})
	if len(metrics) == 0 {
		return "PromQL check"
	}
	label := prefix + strings.Join(metrics, " / ") + strings.Join(grouping, "")
	if len(scope) > 0 {
		label += " · " + strings.Join(scope, ", ")
	}
	if len(label) > 120 {
		return "PromQL check"
	}
	return label
}

func canonicalEvidenceObservation(observation string) string {
	if strings.HasPrefix(observation, "Log sample") && !canonicalDiagnostic(observation) {
		return ""
	}
	return compactObservation(observation)
}

func canonicalFindingLine(finding string, historical bool) string {
	label, prefix := "*Finding:* ", ""
	if historical {
		prefix = "During the incident: "
	}
	if strings.HasPrefix(finding, "Alert reported: ") {
		finding = strings.TrimPrefix(finding, "Alert reported: ")
		label, prefix = "*Alert reported:* ", ""
		if historical {
			label = "*Earlier alert:* "
		}
	}
	return label + prefix + briefingComplete(finding)
}
