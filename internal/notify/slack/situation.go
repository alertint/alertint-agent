// SPDX-License-Identifier: FSL-1.1-ALv2

// Package slack implements the Situation-owned Slack surface: one immutable
// public root per Situation, its non-broadcast thread, occasional broadcast
// replies on genuine handoff, and the two installation-level surfaces
// (dependency health, envelope review) that carry no Situation identity.
//
// Legacy per-Incident card renderers remain in this package only for
// old-card fixture tests; they are never reachable from serve after
// cutover (Task 13).
package slack

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// alertintSlackNamespace is the one fixed AlertINT Slack namespace every
// client_msg_id derives from. It is computed deterministically at init from
// a constant name, not a hand-typed magic literal, but its value is fixed
// across every build and process: the same idempotency_key always yields
// the same UUIDv5 client_msg_id, so a retry after timeout or restart reuses
// the exact identity Slack already saw.
var alertintSlackNamespace = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("notifications.slack.alertint.dev"))

// ClientMessageID computes the deterministic client_msg_id Slack dedupes
// retried posts on: UUIDv5 over the fixed AlertINT Slack namespace and the
// notification intent's own idempotency_key. The same intent therefore
// generates the same valid UUID on every retry.
func ClientMessageID(idempotencyKey string) string {
	return uuid.NewSHA1(alertintSlackNamespace, []byte(idempotencyKey)).String()
}

// RootState is one of the spec's seven published Situation root states.
// Text is authoritative; color/icon is supplementary.
type RootState string

const (
	RootStateInvestigating     RootState = "investigating"
	RootStateJudgmentRequested RootState = "judgment_requested"
	RootStateActionRequired    RootState = "action_required"
	RootStateExpectedActive    RootState = "expected_active"
	RootStateRecoveryPending   RootState = "recovery_pending"
	RootStateRecovered         RootState = "recovered"
	RootStateClosedUnknown     RootState = "closed_unknown"
)

// RenderInput is everything RenderSituationRoot needs. It carries no store
// or Slack I/O — a caller (Task 13 wiring) assembles it from the committed
// transition, the current envelope evaluation, and the durable root
// coordinates.
type RenderInput struct {
	Handle         string
	GroupKey       string
	Lifecycle      model.Lifecycle
	Attention      model.Attention
	ActionContract model.ActionContract
	// EnvelopeExpected is true when a deterministic active envelope match
	// with quieting authority covers the current active episode — the
	// "expected active" root state, distinct from a genuinely silent
	// Situation that never gets a root at all.
	EnvelopeExpected bool
	ReasonSummary    string
	CheckedEvidence  []string
	NextWork         string
	Actor            string
	RenderedAt       time.Time
	Drill            bool
}

// RenderedMessage is one rendered Slack surface: Blocks for a real post,
// Fallback for the plain-text notification/no-block-support path, and
// Color naming the state's supplementary treatment (never authoritative on
// its own — Fallback text always states the state in words too).
type RenderedMessage struct {
	Blocks   []slacklib.Block
	Fallback string
	Color    string
}

// rootPresentation is the closed per-state text/color pair. Recovery
// pending intentionally never reuses recovered's color: a Slack surface
// that cannot render a lighter-green shade still needs pending and
// recovered to read as visibly different states.
type rootPresentation struct {
	label string
	emoji string
	color string
}

var rootPresentations = map[RootState]rootPresentation{
	RootStateInvestigating:     {label: "AlertINT investigating — no operator action", emoji: ":large_orange_circle:", color: "#E8A33D"},
	RootStateJudgmentRequested: {label: "Operator judgment requested — still monitoring", emoji: ":large_yellow_circle:", color: "#F2C744"},
	RootStateActionRequired:    {label: "Operator action required — monitoring continues", emoji: ":red_circle:", color: "#D64545"},
	RootStateExpectedActive:    {label: "Expected for this episode — no operator action", emoji: ":white_circle:", color: "#9AA5B1"},
	RootStateRecoveryPending:   {label: "Recovery observed — confirming stability", emoji: ":large_green_circle:", color: "#8FD19E"},
	RootStateRecovered:         {label: "Recovered — no further action", emoji: ":white_check_mark:", color: "#2E7D32"},
	RootStateClosedUnknown:     {label: "Closed with uncertainty — review reason in MCP", emoji: ":black_circle:", color: "#6B7280"},
}

// DeriveRootState maps the current lifecycle/Attention/action-contract view
// deterministically onto one of the seven published root states. Terminal
// lifecycles win outright; while active, an explicit operator action beats
// an explicit operator judgment beats a matching expected-episode envelope
// beats the default "AlertINT investigating" state.
func DeriveRootState(in RenderInput) RootState {
	switch in.Lifecycle {
	case model.LifecycleRecoveryPending:
		return RootStateRecoveryPending
	case model.LifecycleRecovered:
		return RootStateRecovered
	case model.LifecycleClosedUnknown:
		return RootStateClosedUnknown
	}
	if nonEmptyPtr(in.ActionContract.OperatorActionRequired) {
		return RootStateActionRequired
	}
	if nonEmptyPtr(in.ActionContract.OperatorJudgmentRequested) {
		return RootStateJudgmentRequested
	}
	if in.EnvelopeExpected {
		return RootStateExpectedActive
	}
	return RootStateInvestigating
}

func nonEmptyPtr(s *string) bool {
	return s != nil && strings.TrimSpace(*s) != ""
}

// RenderSituationRoot renders the Situation's one public root: reason,
// checked evidence, next work, actor, relative/localized next update, and
// the immutable MCP handle. next_update_at is required for a nonterminal
// state; a terminal root instead states its terminal time via
// CheckedEvidence/ReasonSummary supplied by the caller (recovered/closed
// Situations promise no further update).
func RenderSituationRoot(in RenderInput) RenderedMessage {
	state := DeriveRootState(in)
	presentation := rootPresentations[state]

	var b strings.Builder
	fmt.Fprintf(&b, "%s%s *%s*", drillPrefix(in.Drill), presentation.emoji, presentation.label)
	if in.ReasonSummary != "" {
		fmt.Fprintf(&b, "\n*Why:* %s", in.ReasonSummary)
	}
	if len(in.CheckedEvidence) > 0 {
		fmt.Fprintf(&b, "\n*Checked:* %s", strings.Join(in.CheckedEvidence, ", "))
	}
	if in.NextWork != "" {
		fmt.Fprintf(&b, "\n*Next:* %s", in.NextWork)
	}
	if in.Actor != "" {
		fmt.Fprintf(&b, "\n*Actor:* %s", in.Actor)
	}
	if in.ActionContract.NextUpdateAt != nil && !in.RenderedAt.IsZero() {
		fmt.Fprintf(&b, "\n%s", NextUpdateText(in.RenderedAt, *in.ActionContract.NextUpdateAt, in.ActionContract.NextUpdateOn))
	}
	if in.Handle != "" {
		fmt.Fprintf(&b, "\n*Handle:* `%s`", in.Handle)
	}

	fallback := b.String()
	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(slacklib.NewTextBlockObject(slacklib.MarkdownType, fallback, false, false), nil, nil),
	}
	return RenderedMessage{Blocks: blocks, Fallback: fallback, Color: presentation.color}
}

// ThreadReplyInput is one non-broadcast thread reply: routine evidence,
// retries, limitations, judgments, or Assessment history.
type ThreadReplyInput struct {
	Text  string
	Drill bool
}

// RenderThreadReply renders one non-broadcast thread reply.
func RenderThreadReply(in ThreadReplyInput) RenderedMessage {
	fallback := drillPrefix(in.Drill) + in.Text
	return RenderedMessage{
		Blocks:   []slacklib.Block{slacklib.NewSectionBlock(slacklib.NewTextBlockObject(slacklib.MarkdownType, fallback, false, false), nil, nil)},
		Fallback: fallback,
	}
}

// BroadcastReplyInput is one broadcast (reply_broadcast) thread reply — used
// only for a genuine handoff: root edit first, then exactly one of these.
type BroadcastReplyInput struct {
	Text  string
	Drill bool
}

// RenderBroadcastReply renders the one broadcast reply a handoff adds after
// the root edit.
func RenderBroadcastReply(in BroadcastReplyInput) RenderedMessage {
	fallback := drillPrefix(in.Drill) + in.Text
	return RenderedMessage{
		Blocks:   []slacklib.Block{slacklib.NewSectionBlock(slacklib.NewTextBlockObject(slacklib.MarkdownType, fallback, false, false), nil, nil)},
		Fallback: fallback,
	}
}

// RecurrenceMilestone reports whether count is a recurrence-collapse
// milestone worth a thread-only reply — 5, 10, 25, 50, 100, then every 100 —
// and the text to render. Cap/ceiling changes stay silent by never calling
// this at all; recurrence_mode: off disables recurrence output entirely by
// the caller never invoking it.
func RecurrenceMilestone(count int) (text string, ok bool) {
	milestones := map[int]bool{5: true, 10: true, 25: true, 50: true, 100: true}
	if milestones[count] || (count > 100 && count%100 == 0) {
		return fmt.Sprintf(":repeat: recurred ×%d", count), true
	}
	return "", false
}

// EnvelopeReviewInput is the standalone, high-priority envelope review
// reminder — it carries no Situation ID and never creates or reuses a
// Situation thread.
type EnvelopeReviewInput struct {
	EnvelopeName string
	ReviewDueAt  time.Time
	MatchCount   int
	MCPHandle    string
}

// RenderEnvelopeReview renders the sparse confirmation reminder: the
// envelope's name, its viewer-local review date, the match count since the
// last confirmation, and the MCP handle to act on it.
func RenderEnvelopeReview(in EnvelopeReviewInput) RenderedMessage {
	fallback := fmt.Sprintf(":clipboard: *Expected-behaviour review due* — %s\n*Review by:* %s\n*Matches since last confirmation:* %d\n*MCP:* `%s`",
		in.EnvelopeName, LocalizedInstant(in.ReviewDueAt), in.MatchCount, in.MCPHandle)
	return RenderedMessage{
		Blocks:   []slacklib.Block{slacklib.NewSectionBlock(slacklib.NewTextBlockObject(slacklib.MarkdownType, fallback, false, false), nil, nil)},
		Fallback: fallback,
	}
}

// DependencyHealthInput is one installation-level shared-dependency health
// surface — a sustained outage's single root, or its one recovery update.
type DependencyHealthInput struct {
	Dependency string
	Degraded   bool
}

// RenderDependencyHealth renders the one health root a sustained shared
// outage produces, or the one recovery update that follows it.
func RenderDependencyHealth(in DependencyHealthInput) RenderedMessage {
	var fallback string
	if in.Degraded {
		fallback = fmt.Sprintf(":warning: *%s degraded* — AlertINT's shared dependency is unavailable; affected Situations remain visible in MCP", in.Dependency)
	} else {
		fallback = fmt.Sprintf(":white_check_mark: *%s recovered* — the shared dependency is healthy again", in.Dependency)
	}
	return RenderedMessage{
		Blocks:   []slacklib.Block{slacklib.NewSectionBlock(slacklib.NewTextBlockObject(slacklib.MarkdownType, fallback, false, false), nil, nil)},
		Fallback: fallback,
	}
}

func drillPrefix(drill bool) string {
	if drill {
		return ":test_tube: *DRILL* — "
	}
	return ""
}
