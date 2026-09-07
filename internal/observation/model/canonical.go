// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// CanonicalPlanID derives Plan p's identity from cycleID plus its own
// canonical content: capability, phase, scope, canonicalized parameters, UTC
// window, limits, and purpose. It clears self-referential ID fields first
// (p.ID, p.CycleID) so identity is unaffected by whatever ID a caller
// happens to have already assigned, and canonicalizes Parameters (raw JSON
// bytes, so Go's automatic map-key sorting does not apply to it the way it
// does to native Go map fields like Scope.Labels, which json.Marshal always
// emits with sorted keys) so key reordering never changes a plan's identity.
// No UUID or retry timestamp ever enters this digest.
func CanonicalPlanID(cycleID string, p Plan) (string, error) {
	if cycleID == "" {
		return "", errors.New("observation/model: cycle id required")
	}
	if err := ValidatePlan(p); err != nil {
		return "", err
	}

	canon := p
	canon.ID = ""
	canon.CycleID = ""
	canon.Start = canon.Start.UTC()
	canon.End = canon.End.UTC()
	canon.EligibleAt = canon.EligibleAt.UTC()

	canonParams, err := canonicalJSON(p.Parameters)
	if err != nil {
		return "", fmt.Errorf("observation/model: canonicalize plan parameters: %w", err)
	}
	canon.Parameters = canonParams

	payload, err := json.Marshal(struct {
		Schema int    `json:"schema"`
		Cycle  string `json:"cycle"`
		Plan   Plan   `json:"plan"`
	}{planIDSchemaVersion, cycleID, canon})
	if err != nil {
		return "", fmt.Errorf("observation/model: marshal canonical plan: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "plan:sha256:" + hex.EncodeToString(sum[:]), nil
}

// ValidatePlan enforces the closed vocabularies and window/limit invariants
// every constructed Plan must satisfy before it can be planned, persisted,
// or dispatched. It never mutates p.
func ValidatePlan(p Plan) error {
	if !ValidCapability(p.Capability) {
		return fmt.Errorf("observation/model: unknown capability %q", p.Capability)
	}
	if !validPhase(p.Phase) {
		return fmt.Errorf("observation/model: unknown phase %q", p.Phase)
	}
	if p.Scope.GroupKey == "" {
		return errors.New("observation/model: plan scope requires a group key")
	}
	if p.Scope.Source == "" {
		return errors.New("observation/model: plan scope requires a source")
	}
	if p.Purpose == "" {
		return errors.New("observation/model: plan requires a purpose code")
	}
	if len(p.Parameters) > MaxPlanParametersBytes {
		return fmt.Errorf("observation/model: plan parameters exceed %d bytes", MaxPlanParametersBytes)
	}
	if p.Limit < 0 {
		return errors.New("observation/model: plan limit must be >= 0")
	}
	if p.MaxRequests < 0 {
		return errors.New("observation/model: plan max requests must be >= 0")
	}
	if p.Start.IsZero() || p.End.IsZero() || p.EligibleAt.IsZero() {
		return errors.New("observation/model: plan requires start, end, and eligible-at times")
	}
	if p.End.Before(p.Start) {
		return errors.New("observation/model: plan end precedes start")
	}
	if bound, ok := windowCapFor(p.Capability); ok {
		if p.End.Sub(p.Start) > bound {
			return fmt.Errorf("observation/model: plan window for capability %q exceeds the hard cap of %s", p.Capability, bound)
		}
	}
	return nil
}

// windowCapFor returns spec.md's hard window ceiling for capability's
// evidence class: at most 24h for metrics/logs, 7d for source/local event
// history. store_read's bound is a row LIMIT, not a wall-clock window, so it
// reports ok=false (unconstrained by this function).
func windowCapFor(capability Capability) (time.Duration, bool) {
	switch capability {
	case CapabilityPrometheusQuery, CapabilityLokiQuery, CapabilityZabbixMetricRange:
		return MaxWindowHoursMetricsLogs * time.Hour, true
	case CapabilityZabbixProblemHist, CapabilityChangeEvents, CapabilitySentryIssues:
		return MaxWindowDaysHistory * 24 * time.Hour, true
	case CapabilityStoreRead:
		return 0, false
	default:
		return 0, false
	}
}

// ValidateRun enforces the closed result/freshness vocabularies and the
// fixed per-run/per-fact caps (spec.md "Defaults and hard limits") every
// committed Run must satisfy. The 256 KiB normalized-data-per-cycle cap is
// NOT checked here: it is an aggregate across every run in a cycle, which
// this single-run validator cannot see — the store enforces it while
// accumulating a cycle's runs (Task 2).
func ValidateRun(r Run) error {
	if r.ID == "" || r.CycleID == "" || r.PlanID == "" {
		return errors.New("observation/model: run requires id, cycle id, and plan id")
	}
	if !ValidResultStatus(r.Status) {
		return fmt.Errorf("observation/model: unknown run status %q", r.Status)
	}
	if len(r.Facts) > MaxFactsPerRun {
		return fmt.Errorf("observation/model: run has %d facts, exceeds cap %d", len(r.Facts), MaxFactsPerRun)
	}
	if r.Coverage.End.Before(r.Coverage.Start) {
		return errors.New("observation/model: run coverage end precedes start")
	}
	if r.Coverage.Returned < 0 || r.Coverage.Omitted < 0 {
		return errors.New("observation/model: run coverage counts must be >= 0")
	}
	for _, f := range r.Facts {
		if f.RunID != "" && f.RunID != r.ID {
			return fmt.Errorf("observation/model: fact %s belongs to run %s, not %s", f.ID, f.RunID, r.ID)
		}
		if !ValidResultStatus(f.ResultStatus) {
			return fmt.Errorf("observation/model: fact %s has unknown result status %q", f.ID, f.ResultStatus)
		}
		if !validFreshness(f.Freshness) {
			return fmt.Errorf("observation/model: fact %s has unknown freshness %q", f.ID, f.Freshness)
		}
		if len(f.EvidenceRefs) > MaxEvidenceRefsPerFact {
			return fmt.Errorf("observation/model: fact %s has %d evidence refs, exceeds cap %d", f.ID, len(f.EvidenceRefs), MaxEvidenceRefsPerFact)
		}
		if len(f.Value) > MaxFactBytes {
			return fmt.Errorf("observation/model: fact %s value exceeds %d bytes", f.ID, MaxFactBytes)
		}
	}
	return nil
}

// materialDigestEntry is MaterialDigest's per-fact canonical shape: exactly
// the fields spec.md says materiality covers (normalized evidence content,
// completeness/result status, freshness/expiry class) and none of the
// fields it says to exclude (fact/run ID, ObservedAt/ExpiresAt collection
// clocks, and anything reservation- or trace-related, none of which this
// shape carries at all).
type materialDigestEntry struct {
	Kind          string          `json:"kind"`
	Subject       string          `json:"subject"`
	SchemaVersion int             `json:"schema_version"`
	Value         json.RawMessage `json:"value"`
	ResultStatus  ResultStatus    `json:"result_status"`
	Freshness     Freshness       `json:"freshness"`
}

// MaterialDigest hashes only facts.Material==true entries' normalized
// meaning and coverage class — never collection time, ID, generation,
// reservation count, or trace ID (none of which this digest ever reads).
// Facts are sorted by (Kind, Subject, canonical value) before hashing so
// digest order never depends on run/collection order.
func MaterialDigest(facts []Fact) (string, error) {
	entries := make([]materialDigestEntry, 0, len(facts))
	for _, f := range facts {
		if !f.Material {
			continue
		}
		canonVal, err := canonicalJSON(f.Value)
		if err != nil {
			return "", fmt.Errorf("observation/model: canonicalize fact %s value: %w", f.ID, err)
		}
		entries = append(entries, materialDigestEntry{
			Kind:          f.Kind,
			Subject:       f.Subject,
			SchemaVersion: f.SchemaVersion,
			Value:         canonVal,
			ResultStatus:  f.ResultStatus,
			Freshness:     f.Freshness,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		if entries[i].Subject != entries[j].Subject {
			return entries[i].Subject < entries[j].Subject
		}
		return string(entries[i].Value) < string(entries[j].Value)
	})

	payload, err := json.Marshal(struct {
		Schema  int                   `json:"schema"`
		Entries []materialDigestEntry `json:"entries"`
	}{MaterialHashVersion, entries})
	if err != nil {
		return "", fmt.Errorf("observation/model: marshal material digest: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "material:sha256:" + hex.EncodeToString(sum[:]), nil
}

// canonicalJSON re-encodes raw JSON bytes into a deterministic canonical
// form: object keys sorted (Go's encoding/json already sorts
// map[string]interface{} keys on Marshal), numeric literals preserved
// exactly (json.Number, never round-tripped through float64, which would
// silently corrupt a large or high-precision literal), and duplicate object
// keys rejected outright rather than silently keeping the last value — see
// rejectDuplicateKeys. Empty input canonicalizes to a JSON null so an absent
// Parameters/Value field never diverges from an explicit `null`.
func canonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("null"), nil
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("observation/model: decode json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("observation/model: trailing content after json value")
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("observation/model: marshal canonical json: %w", err)
	}
	return out, nil
}

type jsonFrameKind int

const (
	frameArray jsonFrameKind = iota
	frameObject
)

type jsonFrame struct {
	kind      jsonFrameKind
	seenKeys  map[string]bool
	expectKey bool // meaningful only for frameObject
}

// rejectDuplicateKeys performs a token-level scan of raw, failing if any
// JSON object in it repeats a key at the same nesting level. encoding/json's
// normal Unmarshal silently keeps the LAST value on a duplicate key, which
// would let two syntactically different inputs alias to the same canonical
// form and the same signature/plan identity — exactly the vocabulary
// collision spec.md requires refusing outright, never silently resolving.
func rejectDuplicateKeys(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*jsonFrame

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("observation/model: scan json tokens: %w", err)
		}

		if d, isDelim := tok.(json.Delim); isDelim {
			switch d {
			case '{':
				stack = append(stack, &jsonFrame{kind: frameObject, seenKeys: make(map[string]bool), expectKey: true})
			case '[':
				stack = append(stack, &jsonFrame{kind: frameArray})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				closeValue(stack)
			}
			continue
		}

		if n := len(stack); n > 0 && stack[n-1].kind == frameObject && stack[n-1].expectKey {
			key, ok := tok.(string)
			if !ok {
				return errors.New("observation/model: malformed json object key")
			}
			if stack[n-1].seenKeys[key] {
				return fmt.Errorf("observation/model: duplicate json key %q", key)
			}
			stack[n-1].seenKeys[key] = true
			stack[n-1].expectKey = false
			continue
		}

		// A scalar value (string/number/bool/null) at an array position or
		// an object's value position.
		closeValue(stack)
	}
	return nil
}

// closeValue marks the enclosing object frame (if any) as expecting its
// next key again, now that one complete value — scalar or a just-closed
// nested object/array — has been consumed for the current key.
func closeValue(stack []*jsonFrame) {
	if len(stack) == 0 {
		return
	}
	top := stack[len(stack)-1]
	if top.kind == frameObject {
		top.expectKey = true
	}
}
