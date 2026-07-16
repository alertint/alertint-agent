// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/internal/store"
)

// ClassifierModel is the Anthropic model the shadow classifier runs on: Haiku,
// the cheapest tier, since it answers one small structured yes/no question. A
// second Anthropic client on the same key stays inside the no-multi-provider
// scope guard.
const ClassifierModel = "claude-haiku-4-5"

// Classifier modes, mirrored from config as plain strings so this package does
// not import config. The serve wiring passes config.ClassifierMode through.
const (
	classifierModeOff    = "off"
	classifierModeShadow = "shadow"
	classifierModeOn     = "on"
)

// ClassifierVerdict is the fail-open verdict of one shadow-classifier call
// (R25). Only VerdictMatched can route a render change; every failure — timeout,
// schema violation, HTTP error, or an unrecognized value — maps to an unsure
// variant, so a slow or broken call can never manufacture a match.
type ClassifierVerdict string

const (
	VerdictMatched       ClassifierVerdict = "matched"
	VerdictNoMatch       ClassifierVerdict = "no-match"
	VerdictUnsure        ClassifierVerdict = "unsure"         // the model's own "can't tell"
	VerdictUnsureTimeout ClassifierVerdict = "unsure-timeout" // the call timed out
	VerdictUnsureError   ClassifierVerdict = "unsure-error"   // the call errored / replied malformed
)

// classifierRequiredKeys is the single soft-typed key the classifier reply must
// carry; any Complete error (including a missing key) is mapped to unsure.
var classifierRequiredKeys = []string{"verdict"}

// maxClassifierSummaryChars caps the recalled prior's root-cause text in the
// delta prompt so the whole call stays within the ~200–300 token budget by
// construction (R22). Tighter than the recall render's 600 — the classifier only
// needs the gist to judge "same condition?".
const maxClassifierSummaryChars = 240

// classifierSystemPrompt frames the single yes/no judgment. It is deliberately
// terse: the classifier answers one structured question, never triages.
const classifierSystemPrompt = `You compare two alert incidents and judge whether they stem from the same underlying condition.
You are given the group-key label delta (shared labels, and the one label that differs) and a short summary of the prior incident's root-cause hypothesis.
Respond with ONLY a JSON object: {"verdict": "matched"} if they are the same underlying condition, {"verdict": "no-match"} if they are not, or {"verdict": "unsure"} if you cannot tell.
Do not add prose or markdown.`

// ClassifierResult is the outcome of one shadow-classifier call: the fail-open
// verdict, the evaluated prior-incident id (for the audit row and the
// per-installation graduation join), and the total token count.
type ClassifierResult struct {
	Verdict   ClassifierVerdict
	Candidate string // the prior incident id judged
	Tokens    int
}

// Classify asks the Haiku client whether the current incident shares an
// underlying condition with one rung-3a weak-signal candidate. It renders only
// the structured group-key delta plus a capped prior summary — never raw
// labels_json (R22) — and is fail-open: any failure maps to an unsure verdict,
// never a match (R25). The caller must bound ctx with the classifier's
// seconds-scale budget (maybeClassify does): the shared client retries 429/529,
// so the per-request HTTP timeout alone does not cap total wall time.
func Classify(ctx context.Context, client LLMClient, currentKey string, candidate RecalledEntry) ClassifierResult {
	res := ClassifierResult{Verdict: VerdictUnsureError, Candidate: candidate.IncidentID}
	if client == nil {
		return res
	}

	user := classifierUserPrompt(currentKey, candidate)
	comp, err := client.Complete(ctx, classifierSystemPrompt, llm.Prompt{Prefix: user}, classifierRequiredKeys)
	res.Tokens = comp.InputTokens + comp.OutputTokens
	if err != nil {
		// res.Verdict already holds VerdictUnsureError; only a timeout refines it.
		if isTimeout(err) {
			res.Verdict = VerdictUnsureTimeout
		}
		return res
	}

	var parsed struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(comp.Raw, &parsed); err != nil {
		res.Verdict = VerdictUnsureError
		return res
	}
	// Trust only a clean reply from the enum the prompt offers; the model's own
	// "unsure" is recorded distinctly from a broken call so the graduation dataset
	// stays honest. Any unrecognized value is unsure-error — never a match.
	switch strings.TrimSpace(parsed.Verdict) {
	case string(VerdictMatched):
		res.Verdict = VerdictMatched
	case string(VerdictNoMatch):
		res.Verdict = VerdictNoMatch
	case string(VerdictUnsure):
		res.Verdict = VerdictUnsure
	default:
		res.Verdict = VerdictUnsureError
	}
	return res
}

// maybeClassify runs the shadow classifier over the top rung-3a weak-signal
// candidate in memory when the classifier is enabled (mode shadow or on) and a
// candidate exists (R21). It audits the verdict either way; in `on` mode a match
// tags the candidate so the recall renders "LLM-matched, probably related". A
// no-op when the classifier is off/unwired or there are no rung-3a candidates.
func (s *Skill) maybeClassify(ctx context.Context, inc store.Incident, memory *MemoryEnrichment) {
	if s.cfg.Classifier == nil || memory == nil {
		return
	}
	if s.cfg.ClassifierMode != classifierModeShadow && s.cfg.ClassifierMode != classifierModeOn {
		return // off or empty: no call at all (AE7)
	}
	// The classifier judges the top rung-3a prefilter candidate. It is taken from
	// topPrefilter (retained pre-render-cap), not the rendered Weak slots, so a key
	// crowded with demoted same-key priors can't silently starve the call.
	if memory.topPrefilter == nil {
		return // no candidate → no call (R21)
	}

	// Hard-bound the whole call: the shared client retries 429/529, so without a
	// context deadline a slow endpoint could sit on the triage-critical path for
	// far longer than the operator's seconds-scale budget.
	if s.cfg.ClassifierTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.ClassifierTimeout)
		defer cancel()
	}

	result := Classify(ctx, s.cfg.Classifier, inc.GroupKey, *memory.topPrefilter)
	if s.auditor != nil {
		_ = s.auditor.Append(ctx, "skill:acute-triage", "memory.classifier_verdict", map[string]any{
			"incident_id": inc.ID,
			"verdict":     string(result.Verdict),
			"tokens":      result.Tokens,
			"candidates":  []string{result.Candidate},
		})
	}
	// `on` mode tags the rendered entry so the model sees "LLM-matched". If the
	// judged candidate was pushed out of the render cap, there is nothing to tag —
	// the verdict still lands in the audit log for graduation.
	if s.cfg.ClassifierMode == classifierModeOn && result.Verdict == VerdictMatched {
		for i := range memory.Weak {
			if memory.Weak[i].Weak && !memory.Weak[i].Superseded && memory.Weak[i].IncidentID == result.Candidate {
				memory.Weak[i].ClassifierMatched = true
				break
			}
		}
	}
}

// isTimeout reports whether err is a request-deadline timeout (the client's HTTP
// timeout or a cancelled context), so it maps to unsure-timeout rather than the
// generic unsure-error.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// classifierUserPrompt renders the delta-only prompt: the shared group-key pairs,
// the differing pair(s), and the capped prior summary. Mirrors the samples.md
// idea-5 shape.
func classifierUserPrompt(currentKey string, candidate RecalledEntry) string {
	shared, differing := groupKeyDelta(candidate.GroupKey, currentKey)

	var b strings.Builder
	b.WriteString("Candidate prior vs current incident:\n")
	if len(shared) > 0 {
		fmt.Fprintf(&b, "  shared:    %s\n", strings.Join(shared, ", "))
	}
	if len(differing) > 0 {
		b.WriteString("  differing: ")
		b.WriteString(strings.Join(differing, "\n             "))
		b.WriteString("\n")
	}
	// The prior's confidence stays (it signals how firm that hypothesis was); the
	// recall's human age is deliberately omitted — it does not inform "same
	// underlying condition?" and threading a clock purely for it would leak wall
	// time into an otherwise deterministic prompt.
	fmt.Fprintf(&b, "Prior finding summary: %q (conf %.2f)\n",
		capText(flattenRecalled(candidate.RootCause), maxClassifierSummaryChars),
		candidate.Confidence)
	b.WriteString("Same underlying condition? Answer: matched | no-match | unsure.")
	return b.String()
}

// groupKeyDelta splits two group_keys into the shared "k=v" pairs and the
// differing "k: priorV → currentV" lines. Keys present in only one side render as
// a differing pair with an empty value on the missing side.
func groupKeyDelta(priorKey, currentKey string) (shared, differing []string) {
	// Same parse the prefilter selects on (store.ParseGroupKey) — one source of
	// truth for the group_key format, so the rendered delta can never disagree with
	// the "one label off" gate that chose the candidate.
	prior := store.ParseGroupKey(priorKey)
	current := store.ParseGroupKey(currentKey)

	keys := make([]string, 0, len(current)+len(prior))
	seen := map[string]bool{}
	for k := range current {
		if !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	for k := range prior {
		if !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		pv, currentV := prior[k], current[k]
		if pv == currentV {
			shared = append(shared, fmt.Sprintf("%s=%s", k, currentV))
			continue
		}
		differing = append(differing, fmt.Sprintf("%s: %s → %s", k, pv, currentV))
	}
	return shared, differing
}
