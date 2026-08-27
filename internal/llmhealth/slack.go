// SPDX-License-Identifier: FSL-1.1-ALv2

package llmhealth

import (
	"context"
	"fmt"
	"time"
)

// Publisher posts and edits the one plain-text AlertINT system Slack root per
// Outage episode. Implementations never thread, never add blocks, and never
// go through the Finding notification path.
type Publisher interface {
	PostSystemMessage(ctx context.Context, text string) (channel, ts string, err error)
	UpdateSystemMessage(ctx context.Context, channel, ts, text string) error
}

// RenderOutage renders the root/edit copy for a sustained unhealthy state.
// Copy never claims uninterrupted Alert intake and never mentions Situations.
func RenderOutage(state State, down time.Duration) string {
	switch state {
	case StateDegraded:
		return fmt.Sprintf("⚠️ AlertINT system · LLM degraded for %s. Verification re-judgment is failing; draft Findings continue with reduced confidence.", FormatDuration(down))
	case StateHealthy, StateUnavailable:
		return fmt.Sprintf("⚠️ AlertINT system · LLM unavailable for %s. New Incident triage is retrying; correlation may be delayed.", FormatDuration(down))
	default:
		return fmt.Sprintf("⚠️ AlertINT system · LLM unavailable for %s. New Incident triage is retrying; correlation may be delayed.", FormatDuration(down))
	}
}

// RenderRecovery renders the in-place recovery edit that closes an episode.
func RenderRecovery(down time.Duration) string {
	return fmt.Sprintf("✅ AlertINT system · LLM recovered after %s. Pending triage retries continue automatically.", FormatDuration(down))
}

// FormatDuration renders a duration the way Slack copy wants it: sub-minute
// collapses to "<1m", otherwise whole minutes/hours only.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	default:
		return fmt.Sprintf("%dh %dm", h, m)
	}
}

type deliverOp int

const (
	deliverNone deliverOp = iota
	deliverPost
	deliverUpdateState
	deliverUpdateRecovery
)

// deliveryPlan is computed under the tracker lock and executed unlocked, so
// the Slack HTTP call never happens under mu.
type deliveryPlan struct {
	op         deliverOp
	text       string
	channel    string
	ts         string
	generation int64
	state      State
}

// Deliver drives the Slack system-message state machine one step: post the
// root once an episode has been unhealthy for broadcastAfter, edit it in
// place on every degraded↔unavailable change inside the episode, and edit it
// once more to the recovery copy when the episode ends. pub == nil (Slack
// disabled) is a no-op — the episode still lives in state/audit/logs only.
func (t *Tracker) Deliver(ctx context.Context, pub Publisher) {
	if pub == nil {
		return
	}
	plan := t.planDelivery()
	// applyDeliveryResult persists with its own bounded context.Background()
	// by design: a Slack delivery result must be recorded even if ctx is
	// canceled between the HTTP call returning and the state update.
	switch plan.op {
	case deliverNone:
		return
	case deliverPost:
		channel, ts, err := pub.PostSystemMessage(ctx, plan.text)
		t.applyDeliveryResult(plan, channel, ts, err) //nolint:contextcheck
	case deliverUpdateState, deliverUpdateRecovery:
		err := pub.UpdateSystemMessage(ctx, plan.channel, plan.ts, plan.text)
		t.applyDeliveryResult(plan, plan.channel, plan.ts, err) //nolint:contextcheck
	}
}

func (t *Tracker) planDelivery() deliveryPlan {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	state := State(t.rec.State)
	gen := t.rec.SlackGeneration

	switch {
	case state != StateHealthy && (t.rec.SlackDelivery == DeliveryNone || t.rec.SlackDelivery == DeliveryPending):
		if t.rec.UnhealthySince == nil || now.Sub(*t.rec.UnhealthySince) < t.broadcastAfter {
			return deliveryPlan{}
		}
		return deliveryPlan{op: deliverPost, text: RenderOutage(state, now.Sub(*t.rec.UnhealthySince)), generation: gen, state: state}

	case state != StateHealthy && t.rec.SlackDelivery == DeliveryDelivered && t.rec.SlackState != string(state):
		var down time.Duration
		if t.rec.UnhealthySince != nil {
			down = now.Sub(*t.rec.UnhealthySince)
		}
		return deliveryPlan{op: deliverUpdateState, text: RenderOutage(state, down), channel: t.rec.SlackChannel, ts: t.rec.SlackTS, generation: gen, state: state}

	case state == StateHealthy && t.rec.SlackDelivery == DeliveryRecoveryPending:
		var down time.Duration
		if t.rec.RecoveredAt != nil && t.rec.UnhealthySince != nil {
			down = t.rec.RecoveredAt.Sub(*t.rec.UnhealthySince)
		}
		return deliveryPlan{op: deliverUpdateRecovery, text: RenderRecovery(down), channel: t.rec.SlackChannel, ts: t.rec.SlackTS, generation: gen}
	}
	return deliveryPlan{}
}

// applyDeliveryResult re-locks and applies the outcome of a Slack call, but
// only if the outage generation is still the one the plan was computed for —
// the episode may have already moved on while the HTTP call was in flight.
func (t *Tracker) applyDeliveryResult(plan deliveryPlan, channel, ts string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if plan.generation != t.rec.SlackGeneration {
		return
	}

	switch plan.op {
	case deliverNone:
		// Deliver never calls applyDeliveryResult for deliverNone.
		return
	case deliverPost:
		if err != nil {
			t.rec.SlackDelivery = DeliveryPending
			t.logger.Warn("llm health: slack system message delivery failed; will retry")
			t.auditAppend("llm.health.slack_failed", map[string]any{"generation": plan.generation, "op": "post"})
			return
		}
		t.rec.SlackDelivery = DeliveryDelivered
		t.rec.SlackTS = ts
		t.rec.SlackChannel = channel
		t.rec.SlackState = string(plan.state)
		t.auditAppend("llm.health.slack_posted", map[string]any{"generation": plan.generation, "state": string(plan.state)})

	case deliverUpdateState:
		if err != nil {
			t.logger.Warn("llm health: slack system message delivery failed; will retry")
			return
		}
		t.rec.SlackState = string(plan.state)
		t.auditAppend("llm.health.slack_updated", map[string]any{"generation": plan.generation, "state": string(plan.state)})

	case deliverUpdateRecovery:
		if err != nil {
			t.logger.Warn("llm health: slack system message delivery failed; will retry")
			return
		}
		t.rec.SlackDelivery = DeliveryRecovered
		t.auditAppend("llm.health.slack_updated", map[string]any{"generation": plan.generation, "state": "recovered"})
	}
	t.persist()
}
