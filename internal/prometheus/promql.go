// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"fmt"
	"slices"
	"sort"

	promqlparser "github.com/prometheus/prometheus/promql/parser"
)

// ValidateExpr parses expr with the official Prometheus PromQL grammar.
// A fresh facade keeps the unstable upstream parser API confined here.
func ValidateExpr(expr string) error {
	if _, err := promqlparser.NewParser(promqlparser.Options{}).ParseExpr(expr); err != nil {
		return fmt.Errorf("prometheus: invalid promql: %w", err)
	}
	return nil
}

// promqlSignature is a normalized, order-preserving summary of the semantic
// anchors in a PromQL expression: the things a syntax-only repair must never
// change. Grouping punctuation, whitespace, comments, and aggregation
// wrapping/grouping syntax (which a syntax repair is explicitly allowed to
// add or relocate) are deliberately excluded.
type promqlSignature struct {
	metricRefs []string // vector-selector metric names, in encounter order
	calls      []string // non-aggregator function names, in encounter order
	matchers   []string // "label<op>value" label-matcher triples, sorted
	literals   []string // "kind:value" duration/number/string literals, in encounter order
}

// ValidateSyntaxRepair reports whether repaired is a syntax-only rewrite of
// original: the same metric references, function calls, label matchers, and
// literals, with only grouping punctuation and aggregation wrapping/grouping
// syntax (e.g. moving or completing a `by (...)` clause) allowed to differ.
// It never inspects query text in its error messages, only the class of
// anchor that changed.
//
// If original cannot be tokenized far enough to establish a signature, this
// fails closed: the repair is rejected rather than approved on a partial
// read.
func ValidateSyntaxRepair(original, repaired string) error {
	originalSig, err := buildPromqlSignature(original)
	if err != nil {
		return fmt.Errorf("prometheus: syntax repair rejected: original expression not fully tokenizable")
	}
	repairedSig, err := buildPromqlSignature(repaired)
	if err != nil {
		return fmt.Errorf("prometheus: syntax repair rejected: repaired expression not fully tokenizable")
	}

	switch {
	case !slices.Equal(originalSig.metricRefs, repairedSig.metricRefs):
		return fmt.Errorf("prometheus: syntax repair changed a metric reference")
	case !slices.Equal(originalSig.calls, repairedSig.calls):
		return fmt.Errorf("prometheus: syntax repair changed a function call")
	case !slices.Equal(originalSig.matchers, repairedSig.matchers):
		return fmt.Errorf("prometheus: syntax repair changed a label matcher")
	case !slices.Equal(originalSig.literals, repairedSig.literals):
		return fmt.Errorf("prometheus: syntax repair changed a literal")
	}
	return nil
}

// buildPromqlSignature tokenizes expr with the official lexer and reduces
// the token stream to a promqlSignature. It returns an error if expr cannot
// be fully tokenized.
func buildPromqlSignature(expr string) (promqlSignature, error) {
	items, err := lexAllItems(expr)
	if err != nil {
		return promqlSignature{}, err
	}

	var sig promqlSignature
	braceDepth := 0

	for i := 0; i < len(items); i++ {
		it := items[i]
		switch {
		case it.Typ == promqlparser.LEFT_BRACE:
			braceDepth++

		case it.Typ == promqlparser.RIGHT_BRACE:
			if braceDepth > 0 {
				braceDepth--
			}

		case it.Typ == promqlparser.BY || it.Typ == promqlparser.WITHOUT:
			// The grouping label list that may follow `by`/`without` is
			// aggregation syntax a repair is allowed to add or move; skip
			// the keyword and, if present, the whole balanced parenthesized
			// list that follows it.
			if i+1 < len(items) && items[i+1].Typ == promqlparser.LEFT_PAREN {
				depth := 1
				j := i + 2
				for ; j < len(items) && depth > 0; j++ {
					switch items[j].Typ {
					case promqlparser.LEFT_PAREN:
						depth++
					case promqlparser.RIGHT_PAREN:
						depth--
					}
				}
				i = j - 1
			}

		case it.Typ.IsAggregator():
			// The aggregation operator itself (sum, avg, ...) is exactly
			// the syntax a repair is allowed to add; it carries no anchor
			// content of its own.

		case it.Typ == promqlparser.IDENTIFIER, it.Typ == promqlparser.METRIC_IDENTIFIER:
			if braceDepth > 0 && i+2 < len(items) && isMatcherOp(items[i+1].Typ) {
				sig.matchers = append(sig.matchers, it.Val+items[i+1].Val+items[i+2].Val)
				i += 2
				continue
			}
			if i+1 < len(items) && items[i+1].Typ == promqlparser.LEFT_PAREN {
				sig.calls = append(sig.calls, it.Val)
				continue
			}
			if braceDepth == 0 {
				sig.metricRefs = append(sig.metricRefs, it.Val)
			}

		case it.Typ == promqlparser.DURATION:
			sig.literals = append(sig.literals, "duration:"+it.Val)

		case it.Typ == promqlparser.NUMBER:
			sig.literals = append(sig.literals, "number:"+it.Val)

		case it.Typ == promqlparser.STRING:
			sig.literals = append(sig.literals, "string:"+it.Val)
		}
	}

	sort.Strings(sig.matchers)
	return sig, nil
}

// isMatcherOp reports whether t is one of the four label-matcher operators.
func isMatcherOp(t promqlparser.ItemType) bool {
	switch t {
	case promqlparser.EQL, promqlparser.NEQ, promqlparser.EQL_REGEX, promqlparser.NEQ_REGEX:
		return true
	}
	return false
}

// lexAllItems runs the official lexer to completion and returns every item
// up to (but not including) EOF, skipping comments. It returns an error if
// the lexer produces an ERROR item, i.e. expr cannot be fully tokenized.
func lexAllItems(expr string) ([]promqlparser.Item, error) {
	lexer := promqlparser.Lex(expr)
	var items []promqlparser.Item
	for {
		var it promqlparser.Item
		lexer.NextItem(&it)
		switch it.Typ {
		case promqlparser.EOF:
			return items, nil
		case promqlparser.ERROR:
			return nil, fmt.Errorf("prometheus: promql lexer error")
		case promqlparser.COMMENT:
			continue
		default:
			items = append(items, it)
		}
	}
}
