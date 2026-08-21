// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// situationDeliverer performs the one outward effect a durable notification
// intent already promised. It is the ONLY Slack authority in the cut-over
// runtime: no other path posts, edits, or replies.
//
// It renders from durable state at delivery time rather than carrying a
// rendered payload on the intent, so a retry after a restart renders the
// Situation as it actually is — while reusing the intent's own
// client_msg_id, which makes the retry idempotent on Slack's side.
type situationDeliverer struct {
	runtime *store.SituationRuntime
	slack   notifyslack.APIClient
	channel string
	clock   func() time.Time
}

var _ situation.NotificationDeliverer = (*situationDeliverer)(nil)

func newSituationDeliverer(runtime *store.SituationRuntime, client notifyslack.APIClient, channel string, clock func() time.Time) *situationDeliverer {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &situationDeliverer{runtime: runtime, slack: client, channel: channel, clock: clock}
}

// slackRetryTiming adapts Slack's own Retry-After to the worker's retry
// contract, so a rate-limited intent honors the server's timing instead of
// guessing at a backoff.
type slackRetryTiming struct {
	err   error
	after time.Duration
}

func (e *slackRetryTiming) Error() string                         { return e.err.Error() }
func (e *slackRetryTiming) Unwrap() error                         { return e.err }
func (e *slackRetryTiming) NotificationRetryAfter() time.Duration { return e.after }

// Deliver renders and sends one intent. Every failure returns an error so the
// intent stays durably pending (or dead-letters on its budget) — a dropped
// effect is never silently forgotten.
func (d *situationDeliverer) Deliver(ctx context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	if d.slack == nil || strings.TrimSpace(d.channel) == "" {
		return situation.NotificationDelivery{}, fmt.Errorf("%w: no slack channel is configured", situation.ErrNotificationUnroutable)
	}
	rendered, target, err := d.render(ctx, intent)
	if err != nil {
		return situation.NotificationDelivery{}, err
	}

	metadata := notifyslack.MessageMetadata{
		EventType: string(intent.Kind),
		EventPayload: map[string]any{
			"subject_kind": string(intent.SubjectKind),
			"subject_id":   intent.SubjectID,
			"intent_id":    intent.ID,
		},
	}

	if target.edit {
		err := d.slack.Update(ctx, notifyslack.UpdateRequest{
			Channel: target.channel, TS: target.messageTS,
			Text: rendered.Fallback, Blocks: rendered.Blocks, Metadata: metadata,
		})
		if err != nil {
			return situation.NotificationDelivery{}, classifySlackError(err)
		}
		return situation.NotificationDelivery{Channel: target.channel, MessageTS: target.messageTS}, nil
	}

	channel, ts, err := d.slack.Post(ctx, notifyslack.PostRequest{
		Channel: d.channel, Text: rendered.Fallback, Blocks: rendered.Blocks,
		ThreadTS: target.threadTS, ReplyBroadcast: target.broadcast,
		ClientMsgID: intent.ClientMessageID, Metadata: metadata,
	})
	if err != nil {
		return situation.NotificationDelivery{}, classifySlackError(err)
	}
	return situation.NotificationDelivery{Channel: channel, MessageTS: ts}, nil
}

// deliveryTarget names where one intent lands: a fresh post, a thread reply,
// or an in-place edit of the persisted root coordinates.
type deliveryTarget struct {
	edit      bool
	broadcast bool
	channel   string
	messageTS string
	threadTS  string
}

func (d *situationDeliverer) render(ctx context.Context, intent model.NotificationIntent) (notifyslack.RenderedMessage, deliveryTarget, error) {
	switch intent.Kind {
	case model.NotificationHealthRoot, model.NotificationHealthUpdate:
		return d.renderDependencyHealth(ctx, intent)
	case model.NotificationEnvelopeReview:
		return d.renderEnvelopeReview(ctx, intent)
	}
	return d.renderSituation(ctx, intent)
}

func (d *situationDeliverer) renderSituation(ctx context.Context, intent model.NotificationIntent) (notifyslack.RenderedMessage, deliveryTarget, error) {
	var target deliveryTarget
	if intent.SituationID == nil {
		return notifyslack.RenderedMessage{}, target, fmt.Errorf("%w: situation intent carries no situation id", situation.ErrNotificationUnroutable)
	}
	situationID := *intent.SituationID
	st := d.runtime.Store()
	sit, err := st.GetSituation(ctx, situationID)
	if err != nil {
		return notifyslack.RenderedMessage{}, target, err
	}
	channel, messageTS, published, err := st.SituationRootCoordinates(ctx, situationID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return notifyslack.RenderedMessage{}, target, err
	}
	if intent.Kind != model.NotificationSituationRootCreate && !published {
		// The root this effect depends on has not been delivered yet. Keeping
		// the intent pending preserves ordering: the root create is claimed
		// first (main-channel pokes sort ahead) and this retries after it.
		return notifyslack.RenderedMessage{}, target, errors.New("situation root is not published yet")
	}

	incidents, err := st.SituationMemberIncidents(ctx, situationID)
	if err != nil {
		return notifyslack.RenderedMessage{}, target, err
	}
	drill, err := situationIsDrill(ctx, st, incidents)
	if err != nil {
		return notifyslack.RenderedMessage{}, target, err
	}
	assessment, err := currentAssessment(ctx, st, situationID)
	if err != nil {
		return notifyslack.RenderedMessage{}, target, err
	}

	switch intent.Kind {
	case model.NotificationSituationRootCreate:
		return d.renderRoot(sit, assessment, drill), deliveryTarget{}, nil
	case model.NotificationSituationRootEdit:
		return d.renderRoot(sit, assessment, drill), deliveryTarget{edit: true, channel: channel, messageTS: messageTS}, nil
	case model.NotificationSituationBroadcastReply:
		return notifyslack.RenderBroadcastReply(notifyslack.BroadcastReplyInput{
			Text: handoffText(assessment), Drill: drill,
		}), deliveryTarget{broadcast: true, channel: channel, threadTS: messageTS}, nil
	case model.NotificationSituationThreadReply:
		return notifyslack.RenderThreadReply(notifyslack.ThreadReplyInput{
			Text: threadReplyText(intent), Drill: drill,
		}), deliveryTarget{channel: channel, threadTS: messageTS}, nil
	}
	return notifyslack.RenderedMessage{}, target, fmt.Errorf("%w: unknown situation notification kind %q", situation.ErrNotificationUnroutable, intent.Kind)
}

func (d *situationDeliverer) renderRoot(sit model.Situation, assessment *model.Assessment, drill bool) notifyslack.RenderedMessage {
	in := notifyslack.RenderInput{
		GroupKey: sit.GroupKey, Lifecycle: sit.Lifecycle, Attention: sit.Attention,
		RenderedAt: d.clock().UTC(), Drill: drill,
	}
	if sit.PublicHandle != nil {
		in.Handle = *sit.PublicHandle
	}
	if assessment != nil {
		in.ActionContract = assessment.ActionContract
		if assessment.SufficientReason != nil {
			in.ReasonSummary = assessment.SufficientReason.Summary
			in.CheckedEvidence = assessment.SufficientReason.EvidenceRefs
		}
		in.NextWork = nextWorkText(assessment.ActionContract)
		in.Actor = string(assessment.ActionContract.NextActor)
	}
	return notifyslack.RenderSituationRoot(in)
}

func (d *situationDeliverer) renderDependencyHealth(ctx context.Context, intent model.NotificationIntent) (notifyslack.RenderedMessage, deliveryTarget, error) {
	rendered := notifyslack.RenderDependencyHealth(notifyslack.DependencyHealthInput{
		Dependency: intent.SubjectID,
		Degraded:   intent.Kind == model.NotificationHealthRoot,
	})
	if intent.Kind == model.NotificationHealthRoot {
		return rendered, deliveryTarget{}, nil
	}
	health, ok, err := d.runtime.Store().DependencyHealthState(ctx, intent.SubjectID)
	if err != nil {
		return notifyslack.RenderedMessage{}, deliveryTarget{}, err
	}
	if !ok || health.SlackChannel == nil || health.SlackMessageTS == nil {
		// No prior health root: post the update as its own message rather than
		// silently dropping the recovery notice.
		return rendered, deliveryTarget{}, nil
	}
	return rendered, deliveryTarget{channel: *health.SlackChannel, threadTS: *health.SlackMessageTS}, nil
}

func (d *situationDeliverer) renderEnvelopeReview(ctx context.Context, intent model.NotificationIntent) (notifyslack.RenderedMessage, deliveryTarget, error) {
	envelope, err := d.runtime.Store().Envelope(ctx, intent.SubjectID)
	if err != nil {
		return notifyslack.RenderedMessage{}, deliveryTarget{}, err
	}
	if envelope == nil || envelope.Version == nil {
		return notifyslack.RenderedMessage{}, deliveryTarget{}, fmt.Errorf("%w: envelope %s no longer exists", situation.ErrNotificationUnroutable, intent.SubjectID)
	}
	matches, err := d.runtime.Store().EnvelopeMatchCount(ctx, envelope.ID)
	if err != nil {
		return notifyslack.RenderedMessage{}, deliveryTarget{}, err
	}
	return notifyslack.RenderEnvelopeReview(notifyslack.EnvelopeReviewInput{
		EnvelopeName: envelope.Version.Scope.GroupKey,
		ReviewDueAt:  envelope.Version.ReviewDueAt,
		MatchCount:   matches,
		MCPHandle:    "alertint_expected_behavior_confirm " + envelope.ID,
	}), deliveryTarget{}, nil
}

// nextWorkText states what happens next in the operator's terms.
func nextWorkText(contract model.ActionContract) string {
	switch {
	case contract.OperatorActionRequired != nil && strings.TrimSpace(*contract.OperatorActionRequired) != "":
		return *contract.OperatorActionRequired
	case contract.OperatorJudgmentRequested != nil && strings.TrimSpace(*contract.OperatorJudgmentRequested) != "":
		return *contract.OperatorJudgmentRequested
	case contract.AlertintAction != nil && strings.TrimSpace(*contract.AlertintAction) != "":
		return *contract.AlertintAction
	default:
		return ""
	}
}

// handoffText is the one broadcast reply a genuine handoff adds after the
// root edit — it states the work, never restates the whole root.
func handoffText(assessment *model.Assessment) string {
	if assessment == nil {
		return "Operator attention is now required — see the Situation root above."
	}
	if work := nextWorkText(assessment.ActionContract); work != "" {
		return "Operator attention is now required: " + work
	}
	return "Operator attention is now required — see the Situation root above."
}

// threadReplyText derives the recurrence reply from the intent's own
// idempotency key, which already names the exact rung or milestone that
// earned it (situation:<id>:transition:<id>:root:recurrence:<suffix>).
func threadReplyText(intent model.NotificationIntent) string {
	_, suffix, ok := strings.Cut(intent.IdempotencyKey, ":root:recurrence:")
	if !ok {
		return "Situation update"
	}
	if rung, found := strings.CutPrefix(suffix, "rung:"); found {
		return "Recurrence: " + strings.ReplaceAll(rung, "_", " ") + " changed since the last judgment"
	}
	if count, found := strings.CutPrefix(suffix, "milestone:"); found {
		if text, ok := recurrenceMilestoneText(count); ok {
			return text
		}
	}
	return "Situation update"
}

func recurrenceMilestoneText(count string) (string, bool) {
	var n int
	if _, err := fmt.Sscanf(count, "%d", &n); err != nil {
		return "", false
	}
	return notifyslack.RecurrenceMilestone(n)
}

// situationIsDrill reports whether any member Incident carries the
// sender-asserted Drill marker. The marker is presentation only: it grants no
// Attention or publication authority.
func situationIsDrill(ctx context.Context, st *store.Store, incidents []store.Incident) (bool, error) {
	if len(incidents) == 0 {
		return false, nil
	}
	ids := make([]string, 0, len(incidents))
	for _, incident := range incidents {
		ids = append(ids, incident.ID)
	}
	flags, err := st.IncidentDrillFlags(ctx, ids)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if flags[id] {
			return true, nil
		}
	}
	return false, nil
}

// currentAssessment reads the Situation's current authoritative Assessment.
func currentAssessment(ctx context.Context, st *store.Store, situationID string) (*model.Assessment, error) {
	attempts, err := st.SituationAssessmentAttempts(ctx, situationID)
	if err != nil {
		return nil, err
	}
	for i := len(attempts) - 1; i >= 0; i-- {
		if attempts[i].Status != store.AssessmentStatusAuthoritative || len(attempts[i].Validated) == 0 {
			continue
		}
		var assessment model.Assessment
		if err := json.Unmarshal(attempts[i].Validated, &assessment); err != nil {
			return nil, fmt.Errorf("alertint: decode current situation assessment: %w", err)
		}
		return &assessment, nil
	}
	return nil, nil
}

// classifySlackError maps a Slack failure onto the worker's retry contract.
func classifySlackError(err error) error {
	var rateLimited *notifyslack.RateLimitError
	if errors.As(err, &rateLimited) && rateLimited.RetryAfter > 0 {
		return &slackRetryTiming{err: err, after: rateLimited.RetryAfter}
	}
	for _, permanent := range []string{"channel_not_found", "not_in_channel", "is_archived", "invalid_auth", "account_inactive"} {
		if strings.Contains(err.Error(), permanent) {
			return fmt.Errorf("%w: %s", situation.ErrNotificationUnroutable, err.Error())
		}
	}
	return err
}
