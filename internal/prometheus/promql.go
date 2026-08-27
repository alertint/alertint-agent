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

// canonToken is one token of an expression's canonical form: either a lexer
// item carried through verbatim (typ and val as the lexer produced them), or
// the synthetic token a `label<op>value` matcher triple collapses into (typ
// zero — no real ItemType is zero — val the three parts concatenated, matcher
// true). Two canonical tokens are the same token only if all three fields
// agree, so nothing is ever compared on its value alone.
type canonToken struct {
	typ     promqlparser.ItemType
	val     string
	matcher bool
}

// promqlCanonical is an expression reduced to the two things the repair gate
// compares: the token sequence with by/without clauses lifted out, and those
// clauses as a sorted list.
type promqlCanonical struct {
	tokens  []canonToken
	clauses []string
}

// ValidateSyntaxRepair reports whether repaired is a rewrite of original that
// the syntax-repair path is allowed to produce. It is a WHITELIST, not a list
// of forbidden changes: the two token sequences must be identical except for
// the three rewrites named below, so every keyword, modifier, parenthesis,
// bracket, comma, literal and identifier the repair touched but that is not
// whitelisted makes the sequences differ, and the repair is rejected. A PromQL
// keyword added to a future parser needs no new case here — it is anchored the
// moment the lexer emits it.
//
// The whitelist:
//
//   - W1, by/without relocation. Every `by (…)` / `without (…)` clause is
//     lifted out of both sequences into a clause list (keyword kept, labels
//     sorted). The sorted clause lists must be equal: a clause may move or
//     swap places with another, but its keyword and labels may not change.
//     `on` / `ignoring` / `group_left` / `group_right` are NOT lifted — their
//     position decides which operator they modify, so they stay in the
//     sequence with their parens and labels as ordinary tokens.
//   - W2, at most one new aggregation wrapper, and only over an original that
//     had none. If both sides have the same number of aggregators the
//     remainders must be exactly equal. If the original had none and the
//     repaired has exactly one, that aggregator plus its opening parenthesis
//     and the matching closing one are removed, and what is left must be
//     exactly the original. Anything else is rejected — including a second
//     aggregator and a parameterised wrapper such as `topk(5, …)`, whose
//     parameter and comma survive the removal and do not match.
//   - W3, matcher order inside one selector. The `label<op>value` triples of a
//     single `{…}` selector are collapsed into one token each and sorted among
//     themselves. Matchers of one selector apply conjunctively, so their order
//     cannot change what is selected; the braces, the commas and every other
//     token stay exactly where they were, and matchers are never pooled across
//     selectors (that would let two selectors swap label values unnoticed).
//
// The original is by construction INVALID PromQL, so there is no parse tree to
// compare against — only what the token stream says. That is enough in the
// fail-closed direction: any disagreement is a rejection, and a rejected repair
// only means one optional verification query does not run (ADR-0043).
//
// Errors name the class of the first divergence and never include query text.
// If either side cannot be tokenized this fails closed: the repair is rejected
// rather than approved on a partial read.
func ValidateSyntaxRepair(original, repaired string) error {
	originalCanon, err := canonicalizePromql(original)
	if err != nil {
		return fmt.Errorf("prometheus: syntax repair rejected: original expression not fully tokenizable")
	}
	repairedCanon, err := canonicalizePromql(repaired)
	if err != nil {
		return fmt.Errorf("prometheus: syntax repair rejected: repaired expression not fully tokenizable")
	}
	if !slices.Equal(originalCanon.clauses, repairedCanon.clauses) {
		return fmt.Errorf("prometheus: syntax repair changed a grouping label list")
	}
	return compareCanonTokens(originalCanon.tokens, repairedCanon.tokens)
}

// compareCanonTokens applies W2 and then requires the two remainders to be
// token-for-token equal.
func compareCanonTokens(original, repaired []canonToken) error {
	aggOriginal := countAggregators(original)
	aggRepaired := countAggregators(repaired)
	switch {
	case aggOriginal == aggRepaired:
		return firstCanonDivergence(original, repaired)
	case aggOriginal == 0 && aggRepaired == 1:
		// The issue-62 repair: the expression was missing the aggregation its
		// grouping clause implied, and the model wrapped it. Strip exactly the
		// wrapper and the two sides must then agree exactly.
		stripped, ok := stripAggregationWrapper(repaired)
		if !ok {
			return fmt.Errorf("prometheus: syntax repair changed an aggregation operator")
		}
		return firstCanonDivergence(original, stripped)
	default:
		// Aggregation removed, a second one added, or one added to an
		// expression that already aggregated: none of those is a repair.
		return fmt.Errorf("prometheus: syntax repair changed an aggregation operator")
	}
}

// countAggregators counts the aggregation keywords (sum, topk, quantile, ...)
// in a canonical sequence, per the pinned parser's own classifier.
func countAggregators(tokens []canonToken) int {
	n := 0
	for _, tok := range tokens {
		if tok.typ.IsAggregator() {
			n++
		}
	}
	return n
}

// stripAggregationWrapper removes the single aggregator token, the LEFT_PAREN
// that must follow it, and that parenthesis's match from tokens. It reports
// false when the aggregator is not shaped like a bare `agg( … )` wrapper — an
// aggregator with a grouping-modifier or parameter list in between, or an
// unbalanced parenthesis — so the caller can reject rather than guess. A
// parameterised wrapper (`topk(5, …)`) does pass this shape check; its 5 and
// comma then remain and fail the sequence comparison, which is the same
// rejection by a more precise route.
func stripAggregationWrapper(tokens []canonToken) ([]canonToken, bool) {
	open := -1
	for i, tok := range tokens {
		if tok.typ.IsAggregator() {
			open = i
			break
		}
	}
	if open < 0 || open+1 >= len(tokens) || tokens[open+1].typ != promqlparser.LEFT_PAREN {
		return nil, false
	}
	depth, closing := 0, -1
	for j := open + 1; j < len(tokens) && closing < 0; j++ {
		switch tokens[j].typ {
		case promqlparser.LEFT_PAREN:
			depth++
		case promqlparser.RIGHT_PAREN:
			depth--
			if depth == 0 {
				closing = j
			}
		}
	}
	if closing < 0 {
		return nil, false
	}
	stripped := make([]canonToken, 0, len(tokens)-3)
	for i, tok := range tokens {
		if i == open || i == open+1 || i == closing {
			continue
		}
		stripped = append(stripped, tok)
	}
	return stripped, true
}

// firstCanonDivergence returns nil when the two sequences are identical, and
// otherwise an error naming the class of the first position where they differ.
// The class is read off the original's token there, falling back to the
// repaired's (one of the two may not exist, when the sequences differ in
// length) and finally to the structural catch-all.
func firstCanonDivergence(original, repaired []canonToken) error {
	for i := range max(len(original), len(repaired)) {
		if i < len(original) && i < len(repaired) && original[i] == repaired[i] {
			continue
		}
		class := ""
		if i < len(original) {
			class = canonTokenClass(original, i)
		}
		if class == "" && i < len(repaired) {
			class = canonTokenClass(repaired, i)
		}
		if class == "" {
			class = "the expression structure"
		}
		return fmt.Errorf("prometheus: syntax repair changed %s", class)
	}
	return nil
}

// canonTokenClass names the anchor class tokens[i] belongs to, for the error
// message. It returns "" for tokens that carry no class of their own —
// parentheses, brackets, commas, and the bare keywords and modifiers (offset,
// bool, @ start/end, on, ignoring, group_left, group_right) — whose change the
// caller reports as a structural one.
func canonTokenClass(tokens []canonToken, i int) string {
	tok := tokens[i]
	switch {
	case tok.typ.IsAggregator():
		return "an aggregation operator"
	case tok.typ.IsOperator():
		return "an operator"
	case tok.matcher:
		return "a label matcher"
	case tok.typ == promqlparser.DURATION, tok.typ == promqlparser.NUMBER, tok.typ == promqlparser.STRING:
		return "a literal"
	case tok.typ == promqlparser.IDENTIFIER, tok.typ == promqlparser.METRIC_IDENTIFIER:
		if i+1 < len(tokens) && tokens[i+1].typ == promqlparser.LEFT_PAREN {
			return "a function call"
		}
		return "a metric reference"
	}
	return ""
}

// canonicalizePromql lexes expr and reduces it to its canonical form: the token
// sequence with matcher triples collapsed and sorted within each selector (W3)
// and by/without clauses lifted out (W1), plus those clauses sorted. Every
// other token is carried through verbatim and in place — nothing is dropped,
// because a token that leaves the sequence is a token whose change cannot be
// detected. It returns an error if expr cannot be fully tokenized.
func canonicalizePromql(expr string) (promqlCanonical, error) {
	items, err := lexAllItems(expr)
	if err != nil {
		return promqlCanonical{}, err
	}

	var canon promqlCanonical
	braceDepth := 0
	var matcherSlots []int // positions in canon.tokens of the open selector's matchers

	for i := 0; i < len(items); i++ {
		it := items[i]
		switch {
		case it.Typ == promqlparser.LEFT_BRACE:
			if braceDepth == 0 {
				matcherSlots = nil
			}
			braceDepth++
			canon.tokens = append(canon.tokens, canonToken{typ: it.Typ, val: it.Val})

		case it.Typ == promqlparser.RIGHT_BRACE:
			canon.tokens = append(canon.tokens, canonToken{typ: it.Typ, val: it.Val})
			if braceDepth > 0 {
				braceDepth--
				if braceDepth == 0 {
					sortMatcherSlots(canon.tokens, matcherSlots)
					matcherSlots = nil
				}
			}

		// Checked before every keyword-shaped case below, and deliberately
		// blind to the label name's token type: PromQL accepts keywords
		// (`quantile`, `count`, `and`, ...) and quoted strings as label names,
		// so anything sitting in front of a matcher operator inside an open
		// selector is a label name, whatever it lexed as. Collapsing the triple
		// here is also what lets W3 sort matchers without a matcher operator
		// drifting away from the label and value it belongs to.
		case matcherTripleAt(items, i, braceDepth):
			matcherSlots = append(matcherSlots, len(canon.tokens))
			canon.tokens = append(canon.tokens, canonToken{val: it.Val + items[i+1].Val + items[i+2].Val, matcher: true})
			i += 2

		// Only outside braces: inside a selector the lexer emits every label
		// name as an IDENTIFIER, but the depth check makes that independent of
		// the lexer rather than reliant on it.
		case braceDepth == 0 && isGroupClauseKeyword(it.Typ):
			var clause string
			clause, i = readGroupClause(items, i)
			canon.clauses = append(canon.clauses, clause)

		default:
			canon.tokens = append(canon.tokens, canonToken{typ: it.Typ, val: it.Val})
		}
	}

	// A clause carries no position (relocating it is the repair), so the list
	// is sorted before it is compared.
	sort.Strings(canon.clauses)
	return canon, nil
}

// sortMatcherSlots sorts, in place, the matcher tokens sitting at the given
// positions of tokens — leaving every other token, the commas between the
// matchers included, exactly where it is.
func sortMatcherSlots(tokens []canonToken, slots []int) {
	if len(slots) < 2 {
		return
	}
	vals := make([]string, 0, len(slots))
	for _, slot := range slots {
		vals = append(vals, tokens[slot].val)
	}
	sort.Strings(vals)
	for i, slot := range slots {
		tokens[slot].val = vals[i]
	}
}

// matcherTripleAt reports whether items[i:i+3] is a `label<op>value` matcher
// triple inside an open selector brace. The label-name slot is intentionally
// untyped: PromQL's grammar accepts keywords and quoted strings as label names,
// so what matters is only that a matcher operator follows.
func matcherTripleAt(items []promqlparser.Item, i, braceDepth int) bool {
	return braceDepth > 0 && i+2 < len(items) && isMatcherOp(items[i+1].Typ)
}

// isGroupClauseKeyword reports whether t opens an aggregation grouping clause
// (`by` / `without`) whose parenthesized label list readGroupClause lifts out
// of the token sequence.
//
// ON/IGNORING/GROUP_LEFT/GROUP_RIGHT are deliberately absent. Lifting a clause
// out of the sequence discards its position, and for a vector-matching or
// cardinality modifier the position IS the meaning: which binary operator it
// attaches to. `a / on(instance) b * c` and `a / b * on(instance) c` match on
// different operators and must not compare equal. Left in the sequence, their
// keyword, parens and labels are anchored as ordinary tokens, positions and
// all — and GROUP_LEFT/GROUP_RIGHT, whose label list is optional, need no
// list-shape guess at all.
func isGroupClauseKeyword(t promqlparser.ItemType) bool {
	switch t {
	case promqlparser.BY, promqlparser.WITHOUT:
		return true
	}
	return false
}

// groupClauseKeyword names the clause t opens, for the clause-list entry.
func groupClauseKeyword(t promqlparser.ItemType) string {
	if t == promqlparser.WITHOUT {
		return "without"
	}
	return "by"
}

// readGroupClause reduces the grouping clause starting at items[i] (the keyword
// itself) to one clause-list entry, and returns the index of the clause's last
// token so the caller's loop resumes just past it.
//
// A clause may be relocated or introduced outright by a repair, so its POSITION
// carries no anchor content — but the labels it names decide what the query
// groups over, so they do. The whole balanced parenthesized list is consumed;
// every depth-1 token other than the separating commas counts as a label, since
// PromQL's `maybe_label` rule admits keywords (`quantile`, `count`, `start`,
// ...) and quoted strings there, not just identifiers. Labels are sorted
// (`by (a,b)` and `by (b,a)` group identically) and the keyword is kept, so a
// by<->without swap — which inverts kept vs. excluded labels — is caught. A
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
