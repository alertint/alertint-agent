// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ReduceFacts returns a detached canonical view of normalized observation
// facts. It never fetches evidence or mutates the supplied facts.
func ReduceFacts(in []observationmodel.Fact) ([]observationmodel.Fact, error) {
	out := make([]observationmodel.Fact, len(in))
	seen := make(map[string]struct{}, len(in))
	for i := range in {
		fact := in[i]
		if strings.TrimSpace(fact.ID) == "" || strings.TrimSpace(fact.Kind) == "" || strings.TrimSpace(fact.Subject) == "" ||
			fact.ObservedAt.IsZero() || strings.TrimSpace(fact.Digest) == "" {
			return nil, errors.New("situation: fact requires id, kind, subject, observed time, and digest")
		}
		if _, ok := seen[fact.ID]; ok {
			return nil, fmt.Errorf("situation: duplicate fact id %q", fact.ID)
		}
		seen[fact.ID] = struct{}{}
		value, err := canonicalRawJSON(fact.Value)
		if err != nil {
			return nil, fmt.Errorf("situation: canonicalize fact %q value: %w", fact.ID, err)
		}
		fact.Value = value
		fact.ObservedAt = fact.ObservedAt.UTC()
		fact.EvidenceRefs = canonicalStrings(fact.EvidenceRefs)
		out[i] = fact
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Digest < out[j].Digest
	})
	return out, nil
}

func canonicalRawJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("normalized value is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("normalized value must be valid json")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("normalized value must contain one json value")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("normalized value cannot be canonicalized")
	}
	return json.RawMessage(canonical), nil
}

func canonicalStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func canonicalLimitations(in []model.Limitation) []model.Limitation {
	out := make([]model.Limitation, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, limitation := range in {
		limitation.Code = strings.TrimSpace(limitation.Code)
		limitation.Detail = strings.TrimSpace(limitation.Detail)
		if limitation.Code == "" {
			continue
		}
		key := limitation.Code + "\x1f" + limitation.Detail
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, limitation)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}
