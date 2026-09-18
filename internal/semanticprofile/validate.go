// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// ParseProfile decodes raw JSON into a Profile, failing closed on anything
// spec.md requires rejected outright rather than silently accepted or
// truncated: duplicate object keys (a naive json.Unmarshal keeps only the
// last value), any field the closed eight-field schema does not declare —
// including a nested policy/action field like "attention" or
// "apply_envelope" a malicious or malformed model response might add — and
// any bound ValidateProfile itself enforces. This is the one path both the
// inference worker (Task 8, parsing model output) and the MCP correction
// handler (Task 9, parsing operator input) must use; neither may unmarshal
// profile JSON any other way.
func ParseProfile(raw []byte) (profilemodel.Profile, error) {
	if err := rejectDuplicateKeys(raw); err != nil {
		return profilemodel.Profile{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p profilemodel.Profile
	if err := dec.Decode(&p); err != nil {
		return profilemodel.Profile{}, fmt.Errorf("semanticprofile: decode profile: %w", err)
	}
	if dec.More() {
		return profilemodel.Profile{}, errors.New("semanticprofile: trailing content after profile json")
	}
	if err := ValidateProfile(p); err != nil {
		return profilemodel.Profile{}, err
	}
	return p, nil
}

// ValidateProfile enforces every closed-schema bound spec.md's "Durable
// semantic-profile inference" section requires: non-empty, bounded meaning
// fields; array caps; the closed horizon-tier and capability-name
// vocabularies; and the whole-profile size cap. It never mutates p.
func ValidateProfile(p profilemodel.Profile) error {
	for _, f := range []struct {
		name, value string
	}{
		{"subject_kind", p.SubjectKind},
		{"event_kind", p.EventKind},
		{"possible_role", p.PossibleRole},
	} {
		if f.value == "" {
			return fmt.Errorf("semanticprofile: %s is required", f.name)
		}
		if len(f.value) > profilemodel.MaxMeaningFieldChars {
			return fmt.Errorf("semanticprofile: %s exceeds %d characters", f.name, profilemodel.MaxMeaningFieldChars)
		}
	}

	if !profilemodel.ValidHorizonTier(p.HorizonTier) {
		return fmt.Errorf("semanticprofile: unknown horizon_tier %q", p.HorizonTier)
	}

	if err := boundedMeaningArray("candidate_scope", p.CandidateScope); err != nil {
		return err
	}
	if err := boundedMeaningArray("companion_signal_kinds", p.CompanionSignalKinds); err != nil {
		return err
	}
	if len(p.UsefulCapabilities) > profilemodel.MaxArrayValues {
		return fmt.Errorf("semanticprofile: useful_capabilities has %d entries, exceeds cap %d", len(p.UsefulCapabilities), profilemodel.MaxArrayValues)
	}
	for _, c := range p.UsefulCapabilities {
		if !profilemodel.ValidCapabilityName(c) {
			return fmt.Errorf("semanticprofile: unknown capability %q", c)
		}
	}
	if len(p.Uncertainty) > profilemodel.MaxArrayValues {
		return fmt.Errorf("semanticprofile: uncertainty has %d entries, exceeds cap %d", len(p.Uncertainty), profilemodel.MaxArrayValues)
	}
	for _, u := range p.Uncertainty {
		if len(u) > profilemodel.MaxUncertaintyChars {
			return fmt.Errorf("semanticprofile: uncertainty entry exceeds %d characters", profilemodel.MaxUncertaintyChars)
		}
	}

	encoded, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("semanticprofile: marshal profile for size check: %w", err)
	}
	if len(encoded) > profilemodel.MaxProfileBytes {
		return fmt.Errorf("semanticprofile: profile exceeds %d bytes", profilemodel.MaxProfileBytes)
	}
	return nil
}

func boundedMeaningArray(field string, values []string) error {
	if len(values) > profilemodel.MaxArrayValues {
		return fmt.Errorf("semanticprofile: %s has %d entries, exceeds cap %d", field, len(values), profilemodel.MaxArrayValues)
	}
	for _, v := range values {
		if len(v) > profilemodel.MaxMeaningFieldChars {
			return fmt.Errorf("semanticprofile: %s entry exceeds %d characters", field, profilemodel.MaxMeaningFieldChars)
		}
	}
	return nil
}

// jsonFrameKind/jsonFrame/rejectDuplicateKeys duplicate
// internal/observation/model's identical helper. This package deliberately
// does not import internal/observation/model (both stay standard-library
// only, per plan.md), so the token-level duplicate-key scan is small enough
// to carry twice rather than introduce a shared-utility package for one
// function.
type jsonFrameKind int

const (
	frameArray jsonFrameKind = iota
	frameObject
)

type jsonFrame struct {
	kind      jsonFrameKind
	seenKeys  map[string]bool
	expectKey bool
}

func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*jsonFrame

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("semanticprofile: scan json tokens: %w", err)
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
				return errors.New("semanticprofile: malformed json object key")
			}
			if stack[n-1].seenKeys[key] {
				return fmt.Errorf("semanticprofile: duplicate json key %q", key)
			}
			stack[n-1].seenKeys[key] = true
			stack[n-1].expectKey = false
			continue
		}

		closeValue(stack)
	}
	return nil
}

func closeValue(stack []*jsonFrame) {
	if len(stack) == 0 {
		return
	}
	top := stack[len(stack)-1]
	if top.kind == frameObject {
		top.expectKey = true
	}
}
