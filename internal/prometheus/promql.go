// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"fmt"
	"slices"
	"sort"
	"strings"

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
// change. Only grouping punctuation, whitespace, comments, and the PRESENCE of
// an aggregation wrapper (which a syntax repair is explicitly allowed to add,
// per ADR-0043) are excluded — everything a reader would call "what this query
// asks" is anchored here.
type promqlSignature struct {
	metricRefs    []string   // vector-selector metric names, in encounter order
	calls         []string   // non-aggregator function names, in encounter order
	matcherGroups [][]string // one entry per `{...}` selector, in encounter order; each
	// entry holds that selector's "label<op>value" triples, sorted within the
	// selector only. Grouping by originating selector (rather than pooling every
	// matcher into one flat sorted list) is required so that swapping label
	// values between two different selectors is detected as a change, not
	// masked by a global sort turning the comparison into a multiset check.
	literals []string // "kind:value" duration/number/string literals, in encounter order
	// groupClauses holds one "by:l1,l2" / "without:l1,l2" entry per by/without
	// clause, in encounter order. Labels are sorted within a clause (`by (a,b)`
	// and `by (b,a)` group identically), but the keyword is kept so a
	// by<->without swap — which inverts kept vs. excluded labels — is caught
	// too. Relocating a clause is legal syntax repair; changing WHICH labels it
	// names is a different question being asked.
	groupClauses []string
	// aggregators holds the aggregation keywords (sum, avg, topk, ...) in
	// encounter order. ValidateSyntaxRepair compares this ONLY when the
	// original already had at least one: introducing the aggregation an
	// expression was missing is the canonical repair (issue 62), but swapping
	// topk for bottomk in an expression that already aggregated is a semantic
	// change wearing a syntax repair's clothes.
	aggregators []string
	// operators holds arithmetic/comparison/set/@ operator tokens (everything
	// the pinned parser's ItemType.IsOperator reports), in encounter order.
	// Label-matcher operators never reach here: they are consumed whole as part
	// of a matcher triple, where matcherGroups already anchors them together
	// with their label and value.
	operators []string
}

// ValidateSyntaxRepair reports whether repaired is a syntax-only rewrite of
// original: the same metric references, function calls, label matchers,
// literals, grouping label lists, operators, and — when the original already
// aggregated — the same aggregation operator. Only grouping punctuation and
// the introduction or relocation of an aggregation wrapper (e.g. completing
// `increase(x[1h]) by (type)` into `sum by (type) (increase(x[1h]))`) may
// differ. It never inspects query text in its error messages, only the class
// of anchor that changed.
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
	case !equalMatcherGroups(originalSig.matcherGroups, repairedSig.matcherGroups):
		return fmt.Errorf("prometheus: syntax repair changed a label matcher")
	case !slices.Equal(originalSig.literals, repairedSig.literals):
		return fmt.Errorf("prometheus: syntax repair changed a literal")
	case !slices.Equal(originalSig.groupClauses, repairedSig.groupClauses):
		return fmt.Errorf("prometheus: syntax repair changed a grouping label list")
	case !slices.Equal(originalSig.operators, repairedSig.operators):
		return fmt.Errorf("prometheus: syntax repair changed an operator")
	// Guarded, deliberately: an original with NO aggregator may gain exactly
	// the one it was missing (the issue-62 relocation this whole repair path
	// exists for). An original that already aggregated may not have that
	// aggregator swapped for a different one.
	case len(originalSig.aggregators) > 0 && !slices.Equal(originalSig.aggregators, repairedSig.aggregators):
		return fmt.Errorf("prometheus: syntax repair changed an aggregation operator")
	}
	return nil
}

// equalMatcherGroups reports whether a and b hold the same label-matcher
// triples per selector, in the same selector order. Each group is compared
// as a set (its own contents were sorted when built), but the groups
// themselves are compared positionally so a value swapped between two
// different selectors is caught rather than masked.
func equalMatcherGroups(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
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
	var currentGroup []string // matcher triples for the selector braces currently open

	for i := 0; i < len(items); i++ {
		it := items[i]
		switch {
		case it.Typ == promqlparser.LEFT_BRACE:
			if braceDepth == 0 {
				currentGroup = nil
			}
			braceDepth++

		case it.Typ == promqlparser.RIGHT_BRACE:
			if braceDepth > 0 {
				braceDepth--
				if braceDepth == 0 {
					sort.Strings(currentGroup)
					sig.matcherGroups = append(sig.matcherGroups, currentGroup)
					currentGroup = nil
				}
			}

		// Checked before every keyword-shaped case below, and deliberately
		// blind to the label name's token type: PromQL accepts keywords
		// (`quantile`, `count`, `and`, ...) and quoted strings as label names,
		// so anything sitting in front of a matcher operator inside an open
		// selector is a label name, whatever it lexed as. Consuming the triple
		// here is also what keeps those tokens from being double-counted as an
		// aggregator, an operator, or a literal.
		case matcherTripleAt(items, i, braceDepth):
			currentGroup = append(currentGroup, it.Val+items[i+1].Val+items[i+2].Val)
			i += 2

		case isGroupClauseKeyword(it.Typ):
			var clause string
			clause, i = readGroupClause(items, i)
			sig.groupClauses = append(sig.groupClauses, clause)

		case it.Typ.IsAggregator():
			// WHETHER an expression aggregates is repairable syntax; WHICH
			// aggregator it uses is not (sum and topk answer different
			// questions). ValidateSyntaxRepair applies the distinction.
			sig.aggregators = append(sig.aggregators, it.Val)

		case it.Typ.IsOperator():
			// Arithmetic, comparison, set operators and the `@` modifier, per
			// the pinned parser's own classifier rather than a hand-rolled
			// list. Label-matcher operators never reach this case — the
			// matcher-triple case above already consumed them.
			sig.operators = append(sig.operators, it.Val)

		case it.Typ == promqlparser.IDENTIFIER, it.Typ == promqlparser.METRIC_IDENTIFIER:
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

	return sig, nil
}

// matcherTripleAt reports whether items[i:i+3] is a `label<op>value` matcher
// triple inside an open selector brace. The label-name slot is intentionally
// untyped: PromQL's grammar accepts keywords and quoted strings as label names,
// so what matters is only that a matcher operator follows.
func matcherTripleAt(items []promqlparser.Item, i, braceDepth int) bool {
	return braceDepth > 0 && i+2 < len(items) && isMatcherOp(items[i+1].Typ)
}

// isGroupClauseKeyword reports whether t opens a parenthesized label list whose
// contents readGroupClause should anchor: an aggregation modifier (`by` /
// `without`) or a vector-matching clause (`on` / `ignoring`).
//
// GROUP_LEFT/GROUP_RIGHT are deliberately absent. Their label list is OPTIONAL,
// so `group_left (foo + bar)` would have a plain parenthesized EXPRESSION
// consumed as if it were labels — hiding its metric references from the rest of
// the signature, which is the opposite of failing closed. Left uncased, their
// labels fall through to metricRefs, where a change is still caught (as a
// changed metric reference rather than a changed label list): less precise,
// but safe.
func isGroupClauseKeyword(t promqlparser.ItemType) bool {
	switch t {
	case promqlparser.BY, promqlparser.WITHOUT, promqlparser.ON, promqlparser.IGNORING:
		return true
	}
	return false
}

// groupClauseKeyword names the clause t opens, for the signature entry.
func groupClauseKeyword(t promqlparser.ItemType) string {
	switch t {
	case promqlparser.WITHOUT:
		return "without"
	case promqlparser.ON:
		return "on"
	case promqlparser.IGNORING:
		return "ignoring"
	}
	return "by"
}

// readGroupClause reduces the grouping or vector-matching clause starting at
// items[i] (the keyword itself) to one signature entry, and returns the index
// of the clause's last token so the caller's loop resumes just past it.
//
// A clause may be relocated or introduced outright by a repair, so its POSITION
// carries no anchor content — but the labels it names decide what the query
// groups or matches over, so they do. The whole balanced parenthesized list is
// consumed; every depth-1 token other than the separating commas counts as a
// label, since PromQL's `maybe_label` rule admits keywords (`quantile`,
// `count`, `start`, ...) and quoted strings there, not just identifiers.
// Labels are sorted (`by (a,b)` and `by (b,a)` group identically) and the
// keyword is kept, so by<->without and on<->ignoring swaps are caught. A
// keyword with no list at all — not realistic PromQL, but the caller must not
// misread the token stream if it ever appears — still yields an entry with an
// empty label list rather than being dropped.
func readGroupClause(items []promqlparser.Item, i int) (string, int) {
	keyword := groupClauseKeyword(items[i].Typ)
	var labels []string
	if i+1 < len(items) && items[i+1].Typ == promqlparser.LEFT_PAREN {
		depth := 1
		j := i + 2
		for ; j < len(items) && depth > 0; j++ {
			switch {
			case items[j].Typ == promqlparser.LEFT_PAREN:
				depth++
			case items[j].Typ == promqlparser.RIGHT_PAREN:
				depth--
			case items[j].Typ == promqlparser.COMMA:
				// separator, not a label
			case depth == 1:
				labels = append(labels, items[j].Val)
			}
		}
		i = j - 1
	}
	sort.Strings(labels)
	return keyword + ":" + strings.Join(labels, ","), i
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
