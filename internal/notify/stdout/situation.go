// SPDX-License-Identifier: FSL-1.1-ALv2

package stdout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// situationStateSchemaVersion is the current wire schema for
// SituationStateEvent. Bump it, never silently reinterpret an older line.
const situationStateSchemaVersion = 1

// SituationStateEvent is the one versioned, machine-readable stdout unit
// that replaces the legacy per-L1-finding JSON line. It is emitted once
// after each newly authoritative Assessment or material lifecycle
// transition, including a silent Situation (no Slack trace): Slack
// publication and Interruption priority are separate fields elsewhere and
// must never be inferred from stdout presence alone.
type SituationStateEvent struct {
	SchemaVersion      int                     `json:"schema_version"`
	EventID            string                  `json:"event_id"`
	SituationID        string                  `json:"situation_id"`
	Handle             *string                 `json:"handle"`
	GroupKey           string                  `json:"group_key"`
	Lifecycle          model.Lifecycle         `json:"lifecycle"`
	Attention          model.Attention         `json:"attention"`
	AssessmentSequence int                     `json:"assessment_sequence"`
	SufficientReason   *model.SufficientReason `json:"sufficient_reason,omitempty"`
	ActionContract     model.ActionContract    `json:"action_contract"`
	Limitations        []string                `json:"limitations"`
	IncidentIDs        []string                `json:"incident_ids"`
	Drill              bool                    `json:"drill"`
	OccurredAt         time.Time               `json:"occurred_at"`
}

// EmitSituationState writes one SituationStateEvent line, always (never
// verbose-gated — this is the primary machine-readable Situation output,
// unlike the legacy debug-only Finding line). event_id is the durable
// transition/Assessment identity, so a consumer can deduplicate after a
// process restart; a retry or stale attempt must never call this a second
// time for the same event_id (those emit action-trail audit records
// instead, not a duplicate state line — the caller's responsibility).
func (n *Notifier) EmitSituationState(ctx context.Context, ev SituationStateEvent) error {
	if ev.EventID == "" || ev.SituationID == "" || ev.OccurredAt.IsZero() {
		return errors.New("stdout notifier: situation state event requires event id, situation id, and occurred_at")
	}
	if ev.SchemaVersion == 0 {
		ev.SchemaVersion = situationStateSchemaVersion
	}
	if ev.Limitations == nil {
		ev.Limitations = []string{}
	}
	if ev.IncidentIDs == nil {
		ev.IncidentIDs = []string{}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("stdout notifier: marshal situation state: %w", err)
	}
	if _, err := fmt.Fprintf(n.w, "%s\n", b); err != nil {
		return fmt.Errorf("stdout notifier: write situation state: %w", err)
	}
	if n.auditor != nil {
		_ = n.auditor.Append(ctx, "notify.stdout", "notify.situation_state", map[string]any{
			"event_id":     ev.EventID,
			"situation_id": ev.SituationID,
			"lifecycle":    string(ev.Lifecycle),
			"attention":    string(ev.Attention),
			"drill":        ev.Drill,
		})
	}
	return nil
}
