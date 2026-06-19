// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// changeRequest is the canonical, source-agnostic change webhook body. Any
// emitter (a one-line curl at the end of a deploy) can POST this shape.
type changeRequest struct {
	Source     string            `json:"source"`
	Kind       string            `json:"kind"`
	Title      string            `json:"title"`
	Labels     map[string]string `json:"labels"`
	Version    string            `json:"version"`
	Link       string            `json:"link"`
	OccurredAt time.Time         `json:"occurred_at"`
}

// ParseChange validates and normalizes one change body. It returns a one-element
// slice (the slice return keeps batch ingest a trivial later extension). ID is
// left empty for the receiver to stamp; ReceivedAt is set to now.
//
// occurred_at is accept-and-normalize, never reject (push APIs stay lenient,
// per the never-5xx spirit): effective occurrence = occurred_at if present and
// NOT in the future relative to now, else now. A future timestamp is clock skew
// — exactly what degrades mid-incident — and would otherwise pollute every later
// window and render a nonsense "Δ before incident" hint, so it collapses to the
// received_at fallback. Ancient timestamps are trusted (legitimate backfill;
// they self-correct by falling outside the window/retention). This is stricter
// than the alert path (which trusts StartsAt un-clamped) on purpose: changes are
// append-only and flow straight into the LLM prompt.
func ParseChange(body []byte, now time.Time) ([]store.Change, error) {
	var req changeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("change: invalid JSON: %w", err)
	}
	if strings.TrimSpace(req.Kind) == "" {
		return nil, errors.New("change: kind is required")
	}
	if len(req.Labels) == 0 {
		return nil, errors.New("change: labels must contain at least one key")
	}

	received := now.UTC()
	occurred := received
	if !req.OccurredAt.IsZero() && !req.OccurredAt.After(received) {
		occurred = req.OccurredAt.UTC()
	}

	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "unknown"
	}
	kind := strings.TrimSpace(req.Kind)
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = synthTitle(kind, req.Labels, req.Version)
	}

	return []store.Change{{
		Source:     source,
		Kind:       kind,
		Title:      title,
		Labels:     req.Labels,
		Version:    strings.TrimSpace(req.Version),
		Link:       strings.TrimSpace(req.Link),
		OccurredAt: occurred,
		ReceivedAt: received,
	}}, nil
}

// synthTitle builds a human summary when the emitter omits title: "<kind>
// <service-ish label> <version>", e.g. "deploy checkout v9".
func synthTitle(kind string, labels map[string]string, version string) string {
	parts := []string{kind}
	for _, k := range []string{"service", "app", "namespace"} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			parts = append(parts, v)
			break
		}
	}
	if v := strings.TrimSpace(version); v != "" {
		parts = append(parts, v)
	}
	return strings.Join(parts, " ")
}
