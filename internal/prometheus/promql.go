// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"fmt"
	"sort"
	"strconv"
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

// promqlClause is one `by (…)` / `without (…)` clause lifted out of the token
// sequence: text is the normalized `by:l1,l2` form (keyword kept, labels
// sorted) and index is the position in the remainder token slice the clause was
// lifted from — i.e. the boundary of the sub-expression it groups. The index is
// as meaning-carrying as the labels: it is the only evidence of WHICH
// sub-expression the clause was meant to group, so it is compared, not
// discarded.
type promqlClause struct {
	index int
	text  string
}

// promqlCanonical is an expression reduced to the two things the repair gate
// compares: the token sequence with by/without clauses lifted out, and those
// clauses in encounter order with their lift positions.
type promqlCanonical struct {
	tokens  []canonToken
	clauses []promqlClause
}

// ValidateSyntaxRepair reports whether repaired is a rewrite of original that
// the syntax-repair path is allowed to produce. It is a WHITELIST, not a list
// of forbidden changes: the canonical token sequences must be identical and the
// clause lists must match position for position, except for the one rewrite
// below. Every keyword, modifier, parenthesis, bracket, comma, literal and
// identifier a repair touched that is not part of that rewrite makes the two
// forms differ, so it is rejected. A PromQL keyword added to a future parser
// needs no new case here — it is anchored the moment the lexer emits it.
//
// The whitelist:
//
//   - W1, by/without relocation. Every `by (…)` / `without (…)` clause (the
//     keyword followed by a parenthesized label list) is lifted out of the
//     sequence into a clause list, keeping its keyword, its sorted labels, and
//     the remainder index it was lifted from. A bare `by` / `without` with no
//     list is NOT a clause and stays in the sequence as an ordinary token.
//     `on` / `ignoring` / `group_left` / `group_right` are never lifted — their
//     position decides which operator they modify, so they stay in the sequence
//     with their parens and labels as ordinary tokens. Clause positions are
//     compared through clauseSlot, which treats the two spellings of ONE
//     aggregation's modifier slot (`agg by (t) (X)` and `agg(X) by (t)`) as the
//     same slot — they are the same PromQL — and every other position
//     literally, so a clause still cannot move onto a different owner.
//   - W2, one new `sum` wrapper, and only over an original that had none. See
//     validateNewSumWrapper: exactly one orphaned clause on each side, the new
//     aggregator must be `sum`, the clause must belong to that wrapper, the
//     wrapper must open at the start of the term its orphaned clause followed
//     and close exactly where that clause sat, and stripping the three wrapper
//     tokens must reproduce the original sequence exactly. That makes the
//     wrapping of a given original unique: contradictory repairs of the same
//     original (aggregate-then-filter vs. filter-then-aggregate) can no longer
//     both be accepted.
//   - W3, matcher order inside one selector. The `label<op>value` triples of a
//     single `{…}` selector are collapsed into one token each and sorted among
//     themselves. Matchers of one selector apply conjunctively, so their order
//     cannot change what is selected; the braces, the commas and every other
//     token stay exactly where they were, and matchers are never pooled across
//     selectors (that would let two selectors swap label values unnoticed).
//
// Known false rejects, all in the fail-closed direction (the repair is dropped
// and the verification query simply does not run, per ADR-0043): an original
// with two orphaned clauses (`… by (x) + … by (y)`), which needs two new
// wrappers; redundant parentheses added around the wrapped term; a new wrapper
// that is not `sum` (`count`/`avg`/`max`/… answer a different question than an
// orphaned `by` asked, so they are not recognised repairs); wrapping a whole
// binary expression when the clause trails only its right operand; and moving a
// clause OUT of an existing aggregation's parentheses
// (`sum(increase(x[1h]) by (type))` → `sum by (type) (increase(x[1h]))`) —
// inside the parens is the aggregation's ARGUMENT, not its modifier slot, so
// that move is not one of the two spellings clauseSlot normalizes.
//
// The original is by construction INVALID PromQL, so there is no parse tree to
// compare against — only what the token stream says. That is enough in the
// fail-closed direction: any disagreement is a rejection.
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

	aggOriginal := appliedAggregators(originalCanon.tokens)
	aggRepaired := appliedAggregators(repairedCanon.tokens)
	switch {
	case len(aggOriginal) == len(aggRepaired):
		// No new wrapper: nothing may have moved at all. The sequence is
		// checked first so a changed token is reported by its own class
		// rather than by the clause shift it drags along.
		if err := firstCanonDivergence(originalCanon.tokens, repairedCanon.tokens); err != nil {
			return err
		}
		if !equalClauseSlots(originalCanon, aggOriginal, repairedCanon, aggRepaired) {
			return fmt.Errorf("prometheus: syntax repair changed a grouping label list")
		}
		return nil
	case len(aggOriginal) == 0 && len(aggRepaired) == 1:
		return validateNewSumWrapper(originalCanon, repairedCanon, aggRepaired[0])
	default:
		// Aggregation removed, a second one added, or one added to an
		// expression that already aggregated: none of those is a repair.
		return fmt.Errorf("prometheus: syntax repair changed an aggregation operator")
	}
}

// validateNewSumWrapper checks the one rewrite that may change the token
// sequence: the issue-62 repair, where an expression whose grouping clause had
// no aggregation to attach to gains the `sum` wrapper it was missing.
//
// The original must carry exactly one orphaned clause, and the repaired
// expression exactly one clause and one aggregator. The wrapper's extent is
// then fully determined by the original: it opens at the start of the term the
// orphaned clause immediately follows (termStart) and closes exactly where that
// clause sat. Since one original admits exactly one such wrapping, two
// contradictory repairs of it can never both be accepted.
func validateNewSumWrapper(original, repaired promqlCanonical, open int) error {
	aggErr := fmt.Errorf("prometheus: syntax repair changed an aggregation operator")
	if len(original.clauses) != 1 || len(repaired.clauses) != 1 {
		return aggErr
	}

	// The wrapper: `sum` and nothing else. count and group return a count
	// rather than the quantity, and avg/min/max/stddev/stdvar answer a
	// different question than the orphaned `by` asked.
	if repaired.tokens[open].typ != promqlparser.SUM {
		return aggErr
	}
	if open+1 >= len(repaired.tokens) || repaired.tokens[open+1].typ != promqlparser.LEFT_PAREN {
		return aggErr
	}
	// A wrapper must wrap something: `closing == open+2` is `sum(…)` around an
	// empty term, which is not a repair of anything (and does not parse).
	closing := matchingCloser(repaired.tokens, open+1)
	if closing < 0 || closing <= open+2 {
		return aggErr
	}

	// The clause must belong to THIS wrapper: `sum by (t) (X)` lifts it at
	// open+1, `sum(X) by (t)` at closing+1. Anywhere else and the clause is
	// grouping something the wrapper does not cover.
	if cr := repaired.clauses[0].index; cr != open+1 && cr != closing+1 {
		return fmt.Errorf("prometheus: syntax repair changed a grouping label list")
	}

	// Everything outside the three wrapper tokens must be the original,
	// token for token.
	stripped := make([]canonToken, 0, len(repaired.tokens)-3)
	for i, tok := range repaired.tokens {
		if i == open || i == open+1 || i == closing {
			continue
		}
		stripped = append(stripped, tok)
	}
	if err := firstCanonDivergence(original.tokens, stripped); err != nil {
		return err
	}

	// The wrapper's scope must be the term the orphaned clause followed:
	// closing at the clause's position (two tokens further along in the
	// repaired sequence, which carries the extra `sum` and `(`), opening at
	// that term's start.
	boundary := original.clauses[0].index
	if closing-2 != boundary {
		return aggErr
	}
	start, ok := termStart(original.tokens, boundary)
	if !ok || open != start {
		return aggErr
	}

	if original.clauses[0].text != repaired.clauses[0].text {
		return fmt.Errorf("prometheus: syntax repair changed a grouping label list")
	}
	return nil
}

// termStart returns the index at which the operand ending just before boundary
// begins — the tight-binding reading of `X by (t)`, where the clause groups the
// operand it immediately follows and nothing further left. It reports false if
// the sequence is too malformed to answer (an unbalanced group), so the caller
// can fail closed.
//
// Walking left: a balanced (…) / […] / {…} group is one unit and is jumped
// over, EXCEPT a parenthesized list belonging to a vector-matching or
// cardinality modifier (`on` / `ignoring` / `group_left` / `group_right`),
// which is part of the operator and not of the operand — the term starts after
// it. The walk stops at anything that cannot be inside a single operand: a
// binary or unary operator (but not `@`, a postfix modifier of the term it
// follows), a comma, `bool`, a vector-matching keyword, an unmatched opening
// bracket, or the start of the sequence. `offset`, `@`, durations, numbers,
// identifiers, `start`/`end` and balanced groups are all part of the term.
//
// The modifier-list exception is keyed on the SINGLE token before the `(`,
// which is exactly how the pinned grammar spells those clauses today. If a
// future PromQL ever puts something between the modifier keyword and its label
// list, this test would stop recognising the list and would silently widen the
// term (rather than fail closed), so it needs revisiting on a parser bump that
// changes that shape.
func termStart(tokens []canonToken, boundary int) (int, bool) {
	i := boundary - 1
	for i >= 0 {
		switch tokens[i].typ {
		case promqlparser.RIGHT_PAREN, promqlparser.RIGHT_BRACKET, promqlparser.RIGHT_BRACE:
			opener := matchingOpener(tokens, i)
			if opener < 0 {
				return 0, false
			}
			if tokens[i].typ == promqlparser.RIGHT_PAREN && opener > 0 && isVectorMatchingKeyword(tokens[opener-1].typ) {
				return i + 1, true
			}
			i = opener - 1
			continue
		}
		if isTermBoundary(tokens[i].typ) {
			return i + 1, true
		}
		i--
	}
	return 0, true
}

// isTermBoundary reports whether t, sitting to the LEFT of the operand being
// measured, ends that operand.
func isTermBoundary(t promqlparser.ItemType) bool {
	switch t {
	case promqlparser.COMMA, promqlparser.BOOL:
		return true
	// Reached directly rather than jumped over from a matching closer, an
	// opening bracket is unmatched — it encloses the clause, so the operand
	// starts inside it.
	case promqlparser.LEFT_PAREN, promqlparser.LEFT_BRACKET, promqlparser.LEFT_BRACE:
		return true
	}
	if isVectorMatchingKeyword(t) {
		return true
	}
	// `@` is a postfix modifier and belongs to the term it follows; every
	// other operator separates two operands.
	return t.IsOperator() && t != promqlparser.AT
}

// isVectorMatchingKeyword reports whether t opens a vector-matching or
// cardinality modifier, whose parenthesized label list belongs to the operator
// rather than to either operand.
func isVectorMatchingKeyword(t promqlparser.ItemType) bool {
	switch t {
	case promqlparser.ON, promqlparser.IGNORING, promqlparser.GROUP_LEFT, promqlparser.GROUP_RIGHT:
		return true
	}
	return false
}

// matchingOpener returns the index of the bracket that opens the balanced group
// closed at index i, or -1 if there is none. Only the closer's own kind is
// counted, so a malformed sequence cannot make two different bracket kinds
// cancel each other out.
func matchingOpener(tokens []canonToken, i int) int {
	var opener promqlparser.ItemType
	closer := tokens[i].typ
	switch closer {
	case promqlparser.RIGHT_PAREN:
		opener = promqlparser.LEFT_PAREN
	case promqlparser.RIGHT_BRACKET:
		opener = promqlparser.LEFT_BRACKET
	case promqlparser.RIGHT_BRACE:
		opener = promqlparser.LEFT_BRACE
	default:
		return -1
	}
	depth := 0
	for j := i; j >= 0; j-- {
		switch tokens[j].typ {
		case closer:
			depth++
		case opener:
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// matchingCloser returns the index of the RIGHT_PAREN closing the LEFT_PAREN at
// index i, or -1 if there is none.
func matchingCloser(tokens []canonToken, i int) int {
	if i >= len(tokens) || tokens[i].typ != promqlparser.LEFT_PAREN {
		return -1
	}
	depth := 0
	for j := i; j < len(tokens); j++ {
		switch tokens[j].typ {
		case promqlparser.LEFT_PAREN:
			depth++
		case promqlparser.RIGHT_PAREN:
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// appliedAggregators returns the indices of the aggregation keywords the
// expression actually aggregates with, in order.
//
// An `IsAggregator()` token counts wherever it appears, INCLUDING dangling at
// the end of the sequence: `avg by (x)` is a truncated aggregation — exactly
// the malformed input the repair path exists for — and reading it as a metric
// named `avg` would let the gate bless `sum by (x) (avg)`, which changes the
// aggregation operator and invents the operand.
//
// The single exception is a keyword used as a LABEL NAME inside a
// vector-matching or cardinality list, which PromQL's `maybe_label` rule
// admits: the SUM token in `foo / on(sum) bar` aggregates nothing, and counting
// it would make a legitimate repair look like a second aggregator being
// introduced. Those spans are tracked with a depth counter rather than a
// look-behind, so nesting inside such a list cannot escape it. Tokens inside a
// `{…}` selector are excluded for the same reason (today's lexer emits
// IDENTIFIER for every in-brace label name, but the guard does not rely on it).
func appliedAggregators(tokens []canonToken) []int {
	var found []int
	braceDepth, listDepth := 0, 0
	for i := range tokens {
		switch tokens[i].typ {
		case promqlparser.LEFT_BRACE:
			braceDepth++
		case promqlparser.RIGHT_BRACE:
			if braceDepth > 0 {
				braceDepth--
			}
		case promqlparser.LEFT_PAREN:
			switch {
			case listDepth > 0:
				listDepth++
			case i > 0 && isVectorMatchingKeyword(tokens[i-1].typ):
				listDepth = 1
			}
		case promqlparser.RIGHT_PAREN:
			if listDepth > 0 {
				listDepth--
			}
		}
		if braceDepth == 0 && listDepth == 0 && tokens[i].typ.IsAggregator() {
			found = append(found, i)
		}
	}
	return found
}

// equalClauseSlots reports whether the two clause lists name the same slots with
// the same labels, pairwise.
func equalClauseSlots(original promqlCanonical, aggOriginal []int, repaired promqlCanonical, aggRepaired []int) bool {
	if len(original.clauses) != len(repaired.clauses) {
		return false
	}
	for i, originalClause := range original.clauses {
		repairedClause := repaired.clauses[i]
		if originalClause.text != repairedClause.text {
			return false
		}
		if clauseSlot(original.tokens, aggOriginal, originalClause.index) !=
			clauseSlot(repaired.tokens, aggRepaired, repairedClause.index) {
			return false
		}
	}
	return true
}

// clauseSlot names the position a clause occupies, normalizing the two
// spellings of one aggregation's modifier slot.
//
// `agg by (t) (X)` lifts its clause at the aggregator's index + 1 and
// `agg(X) by (t)` at the index just past the aggregator's closing parenthesis;
// both are the same PromQL, so both report `owner:<aggregator index>` and a
// repair may respell one as the other. Every other position — including inside
// the aggregation's parentheses, which is its ARGUMENT rather than its modifier
// slot — reports its literal index, so a clause cannot drift onto a different
// owner or onto no owner at all without the comparison noticing.
func clauseSlot(tokens []canonToken, aggregators []int, index int) string {
	for _, k := range aggregators {
		if index == k+1 {
			return "owner:" + strconv.Itoa(k)
		}
		if k+1 < len(tokens) && tokens[k+1].typ == promqlparser.LEFT_PAREN {
			if closing := matchingCloser(tokens, k+1); closing >= 0 && index == closing+1 {
				return "owner:" + strconv.Itoa(k)
			}
		}
	}
	return "pos:" + strconv.Itoa(index)
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
// and by/without clauses lifted out with their positions (W1). Every other
// token is carried through verbatim and in place — nothing is dropped, because
// a token that leaves the sequence is a token whose change cannot be detected.
// It returns an error if expr cannot be fully tokenized.
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

		// A clause is the keyword AND its parenthesized label list. A bare
		// `by` / `without` — a truncated model output, or the keyword used as
		// a label name inside on(…) — is not a clause and must stay in the
		// sequence: lifting it out would drop it, and a dropped token is a
		// token whose appearance or disappearance cannot be detected. The
		// brace-depth guard makes the case independent of the lexer's habit of
		// emitting every in-brace label name as an IDENTIFIER.
		case braceDepth == 0 && isGroupClauseKeyword(it.Typ) &&
			i+1 < len(items) && items[i+1].Typ == promqlparser.LEFT_PAREN:
			var text string
			text, i = readGroupClause(items, i)
			canon.clauses = append(canon.clauses, promqlClause{index: len(canon.tokens), text: text})

		default:
			canon.tokens = append(canon.tokens, canonToken{typ: it.Typ, val: it.Val})
		}
	}

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
// untyped — PromQL's grammar accepts keywords and quoted strings as label names
// — but the value slot must be a quoted STRING, which every valid selector's
// value is. Without that check a degenerate `{a=}` would swallow the closing
// brace into the synthetic token and the selector would never close.
func matcherTripleAt(items []promqlparser.Item, i, braceDepth int) bool {
	return braceDepth > 0 && i+2 < len(items) &&
		isMatcherOp(items[i+1].Typ) && items[i+2].Typ == promqlparser.STRING
}

// isGroupClauseKeyword reports whether t opens an aggregation grouping clause
// (`by` / `without`) whose parenthesized label list readGroupClause lifts out
// of the token sequence.
//
// ON/IGNORING/GROUP_LEFT/GROUP_RIGHT are deliberately absent. Lifting a clause
// out of the sequence keeps only its lift index, and for a vector-matching or
// cardinality modifier that is not enough: an `on(…)` list can move between
// binary operators without changing which token index precedes it. Left in the
// sequence, their keyword, parens and labels are anchored as ordinary tokens,
// positions and all — and GROUP_LEFT/GROUP_RIGHT, whose label list is optional,
// need no list-shape guess at all.
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
// itself, which the caller has already checked is followed by a LEFT_PAREN) to
// its normalized text, and returns the index of the clause's last token so the
// caller's loop resumes just past it.
//
// The labels a clause names decide what the query groups over, so they are
// anchored; the whole balanced parenthesized list is consumed, and every
// depth-1 token other than the separating commas counts as a label, since
// PromQL's `maybe_label` rule admits keywords (`quantile`, `count`, `start`,
// ...) and quoted strings there, not just identifiers. Labels are sorted
// (`by (a,b)` and `by (b,a)` group identically) and the keyword is kept, so a
// by<->without swap — which inverts kept vs. excluded labels — is caught.
func readGroupClause(items []promqlparser.Item, i int) (string, int) {
	keyword := groupClauseKeyword(items[i].Typ)
	var labels []string
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
	sort.Strings(labels)
	return keyword + ":" + strings.Join(labels, ","), j - 1
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
