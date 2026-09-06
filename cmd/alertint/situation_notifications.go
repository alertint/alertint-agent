// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Plan 3 Task 6: the concrete Slack deliverer adapter. It makes no
// publication decision (that authority lives entirely in
// internal/situation's BuildTransitions/PlanNotificationIntents, Task 4)
// and never writes Store state itself — given one already-selected
// model.NotificationIntent, it loads the exact durable records it
// references through Task 5's bounded Store readers, renders them (pure
// internal/notify/slack functions), makes exactly one Slack call, and
// returns the result. Claim/lease ownership, retry/backoff, Delivery-gap
// tracking, and acknowledging the result back into the Store are Task 7's
// notification worker, not this file.
//
// Task 7 alignment: the delivery result and deliverer contract now live
// where the plan's Cross-Task Contracts put them —
// situation.NotificationDelivery and situation.NotificationDeliverer — and
// the gap-rendering snapshot is store.GapSnapshot; this file's own
// placeholders for all three are retired. SituationDeliverer's rendering
// and Slack-call logic is unchanged by that alignment. What it gained is
// classifyDeliveryError below, which translates one failed call into the
// closed situation.DeliveryFailure classification the worker resolves its
// retry / configuration-block / fail outcome from. That translation lives
// here on purpose: this package already owns the Slack wire, so
// internal/situation stays free of any Slack dependency.
// ----------------------------------------------------------------------

// Compile-time proof of the assembly this task closes: the Slack adapter is
// a situation.NotificationDeliverer, and *store.Store satisfies both this
// file's reader contract and the worker's whole durable contract.
var (
	_ situation.NotificationDeliverer = (*SituationDeliverer)(nil)
	_ DelivererStore                  = (*store.Store)(nil)
	_ situation.NotificationStore     = (*store.Store)(nil)
)

// DelivererStore is exactly what SituationDeliverer reads. The first three
// methods are Task 5's bounded readers (internal/store/situation_views.go);
// the last two are Task 7's (internal/store/situation_notifications.go and
// internal/store/notification_gaps.go). *store.Store satisfies all five —
// asserted above.
type DelivererStore interface {
	GetSituationEpisodeView(ctx context.Context, situationID string) (store.SituationEpisodeView, error)
	GetSituationTransition(ctx context.Context, transitionID string) (model.Transition, error)
	ListSituationTransitions(ctx context.Context, situationID string, cursor store.TransitionCursor, limit int) ([]model.Transition, error)

	// GetSituationRootCoordinates reads the Situation's current durable
	// root coordinates (migration 0018's situations.slack_channel /
	// slack_root_ts). ok is false when no root has been delivered yet.
	GetSituationRootCoordinates(ctx context.Context, situationID string) (channel, messageTS string, ok bool, err error)

	// GetDeliveryGap reads one durable gap generation's rendering facts.
	GetDeliveryGap(ctx context.Context, gapGeneration string) (store.GapSnapshot, error)
}

// slackDeliveryAPI is exactly what SituationDeliverer calls on the narrow
// Slack Web API client (internal/notify/slack.Client already satisfies
// it). Narrowed to an interface so tests can inject a fake without an
// httptest.Server.
type slackDeliveryAPI interface {
	PostMessage(ctx context.Context, req slack.PostMessageRequest) (slack.MessageResult, error)
	UpdateMessage(ctx context.Context, req slack.UpdateMessageRequest) (slack.MessageResult, error)
	AuthTest(ctx context.Context) error
}

// maxLedgerScanPages bounds SituationDeliverer's own defensive scan of a
// Situation's Transition ledger (recoveryEverObserved) — a safety cap, not
// a realistic ceiling: a Situation's material Transition count is bounded
// by how many times its state actually changed, not by wall-clock time.
const maxLedgerScanPages = 1000

// SituationDeliverer is the concrete Slack NotificationDeliverer adapter
// (R7, Task 6). It reads durable state and calls Slack; it never writes
// Store state.
type SituationDeliverer struct {
	store   DelivererStore
	api     slackDeliveryAPI
	channel string
	now     func() time.Time
}

// NewSituationDeliverer constructs a SituationDeliverer. channel is the
// resolved Situation Slack channel (config.NotifyConfig.Slack.Channel);
// now defaults to time.Now when nil.
func NewSituationDeliverer(delivererStore DelivererStore, api slackDeliveryAPI, channel string, now func() time.Time) *SituationDeliverer {
	if now == nil {
		now = time.Now
	}
	return &SituationDeliverer{store: delivererStore, api: api, channel: channel, now: now}
}

// Probe verifies Slack readiness (auth.test) — the readiness check Task 7's
// gap lifecycle drives before recovery replay and before reactivating
// configuration-blocked intents.
func (d *SituationDeliverer) Probe(ctx context.Context) error {
	return d.api.AuthTest(ctx)
}

// Deliver renders and sends exactly one Slack call for intent, loading the
// exact durable records it references through DelivererStore. It never
// decides whether a root is durably delivered before a reply is claimable
// (Task 7's ordering) and never writes Store state itself.
func (d *SituationDeliverer) Deliver(ctx context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	delivery, err := d.deliver(ctx, intent)
	if err != nil {
		return situation.NotificationDelivery{}, classifyDeliveryError(err)
	}
	return delivery, nil
}

// deliver is Deliver's undecorated body: it renders and sends, and returns
// raw errors that Deliver classifies on the way out.
func (d *SituationDeliverer) deliver(ctx context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	if err := intent.Validate(); err != nil {
		return situation.NotificationDelivery{}, invalidDelivery("invalid_intent",
			fmt.Errorf("cmd/alertint: situation deliverer: %w", err))
	}
	switch intent.EffectClass {
	case model.EffectRootSync:
		return d.deliverRootSync(ctx, intent)
	case model.EffectThreadAppend:
		return d.deliverThreadAppend(ctx, intent)
	case model.EffectBroadcastHandoff:
		return d.deliverBroadcastHandoff(ctx, intent)
	case model.EffectInstallationGapRecovery:
		return d.deliverGapRecovery(ctx, intent)
	default:
		return situation.NotificationDelivery{}, invalidDelivery("unknown_effect_class",
			fmt.Errorf("cmd/alertint: situation deliverer: unknown effect class %q", intent.EffectClass))
	}
}

// deliverRootSync posts a first root or edits an existing one in place
// (including the R4 deadline refresh, which is a plain chat.update): the
// selected Episode-summary version renders only from GetSituationEpisodeView's
// own coherent (summary, source Transition) pair.
func (d *SituationDeliverer) deliverRootSync(ctx context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	if intent.SituationID == nil || intent.SummaryVersion == nil {
		return situation.NotificationDelivery{}, invalidDelivery("incomplete_intent",
			errors.New("cmd/alertint: situation deliverer: root_sync intent missing situation_id/summary_version"))
	}
	view, err := d.store.GetSituationEpisodeView(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load episode view: %w", err)
	}
	if view.Summary.Version != *intent.SummaryVersion {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: intent names summary version %d, current is %d",
			*intent.SummaryVersion, view.Summary.Version)
	}

	recoveryEverObserved, err := d.recoveryEverObserved(ctx, view)
	if err != nil {
		return situation.NotificationDelivery{}, err
	}

	rendered, err := slack.RenderSituationRoot(slack.SituationRootInput{
		Summary:              view.Summary,
		SourceTransition:     view.SourceTransition,
		ContractDeadlineAt:   intent.ContractDeadlineAt,
		Now:                  d.now().UTC(),
		RecoveryEverObserved: recoveryEverObserved,
	})
	if err != nil {
		return situation.NotificationDelivery{}, invalidDelivery("render_failed",
			fmt.Errorf("cmd/alertint: situation deliverer: render root: %w", err))
	}

	channel, ts, ok, err := d.store.GetSituationRootCoordinates(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load root coordinates: %w", err)
	}
	if !ok {
		res, err := d.api.PostMessage(ctx, slack.PostMessageRequest{
			Channel:     d.channel,
			Text:        rendered.Text,
			Blocks:      rendered.Blocks,
			ClientMsgID: intent.ClientMessageID,
		})
		if err != nil {
			return situation.NotificationDelivery{}, err
		}
		return situation.NotificationDelivery{Channel: res.Channel, MessageTS: res.TS, DeliveredAs: "root"}, nil
	}
	res, err := d.api.UpdateMessage(ctx, slack.UpdateMessageRequest{
		Channel:     channel,
		TS:          ts,
		Text:        rendered.Text,
		Blocks:      rendered.Blocks,
		ClientMsgID: intent.ClientMessageID,
	})
	if err != nil {
		return situation.NotificationDelivery{}, err
	}
	return situation.NotificationDelivery{Channel: res.Channel, MessageTS: res.TS, DeliveredAs: "root"}, nil
}

// deliverThreadAppend appends one immutable journal entry to the
// Situation's existing root thread, rendering only from its own referenced
// Transition.
func (d *SituationDeliverer) deliverThreadAppend(ctx context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	if intent.SituationID == nil || intent.TransitionID == nil {
		return situation.NotificationDelivery{}, invalidDelivery("incomplete_intent",
			errors.New("cmd/alertint: situation deliverer: thread_append intent missing situation_id/transition_id"))
	}
	tr, err := d.store.GetSituationTransition(ctx, *intent.TransitionID)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load transition: %w", err)
	}
	channel, rootTS, ok, err := d.store.GetSituationRootCoordinates(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load root coordinates: %w", err)
	}
	if !ok {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: situation %s has no delivered root to reply under", *intent.SituationID)
	}
	rendered, err := slack.RenderSituationJournal(tr)
	if err != nil {
		return situation.NotificationDelivery{}, invalidDelivery("render_failed",
			fmt.Errorf("cmd/alertint: situation deliverer: render journal: %w", err))
	}
	res, err := d.api.PostMessage(ctx, slack.PostMessageRequest{
		Channel:     channel,
		Text:        rendered.Text,
		Blocks:      rendered.Blocks,
		ThreadTS:    rootTS,
		ClientMsgID: intent.ClientMessageID,
	})
	if err != nil {
		return situation.NotificationDelivery{}, err
	}
	return situation.NotificationDelivery{Channel: res.Channel, MessageTS: res.TS, DeliveredAs: "thread"}, nil
}

// deliverBroadcastHandoff optionally broadcasts a current handoff.
// Immediately before external I/O it reloads whether the referenced
// Transition is still the Situation's latest (spec.md "Recovery replay":
// "Immediately before external I/O, reload handoff relevance"); when a
// newer Transition has since superseded it, the same Transition is
// delivered instead as a plain, delayed, no-longer-current thread reply —
// never a channel broadcast.
func (d *SituationDeliverer) deliverBroadcastHandoff(ctx context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	if intent.SituationID == nil || intent.TransitionID == nil {
		return situation.NotificationDelivery{}, invalidDelivery("incomplete_intent",
			errors.New("cmd/alertint: situation deliverer: broadcast_handoff intent missing situation_id/transition_id"))
	}
	tr, err := d.store.GetSituationTransition(ctx, *intent.TransitionID)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load transition: %w", err)
	}
	channel, rootTS, ok, err := d.store.GetSituationRootCoordinates(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load root coordinates: %w", err)
	}
	if !ok {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: situation %s has no delivered root to reply under", *intent.SituationID)
	}
	view, err := d.store.GetSituationEpisodeView(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load episode view: %w", err)
	}
	current := view.Summary.SourceTransitionSequence == tr.Sequence

	renderTr := tr // a local copy: the durable ledger row is never mutated.
	if !current {
		renderTr.Journal.Delayed = true
		renderTr.Journal.NoLongerCurrent = true
	}
	rendered, err := slack.RenderSituationJournal(renderTr)
	if err != nil {
		return situation.NotificationDelivery{}, invalidDelivery("render_failed",
			fmt.Errorf("cmd/alertint: situation deliverer: render journal: %w", err))
	}

	res, err := d.api.PostMessage(ctx, slack.PostMessageRequest{
		Channel:        channel,
		Text:           rendered.Text,
		Blocks:         rendered.Blocks,
		ThreadTS:       rootTS,
		ReplyBroadcast: current,
		ClientMsgID:    intent.ClientMessageID,
	})
	if err != nil {
		return situation.NotificationDelivery{}, err
	}
	deliveredAs := "broadcast"
	if !current {
		deliveredAs = "delayed_thread"
	}
	return situation.NotificationDelivery{Channel: res.Channel, MessageTS: res.TS, DeliveredAs: deliveredAs}, nil
}

// deliverGapRecovery posts the one bounded installation recovery notice for
// gap generation intent.GapGeneration names, rendering only from that
// generation's own durable facts.
func (d *SituationDeliverer) deliverGapRecovery(ctx context.Context, intent model.NotificationIntent) (situation.NotificationDelivery, error) {
	if intent.GapGeneration == nil {
		return situation.NotificationDelivery{}, invalidDelivery("incomplete_intent",
			errors.New("cmd/alertint: situation deliverer: installation_gap_recovery intent missing gap_generation"))
	}
	gap, err := d.store.GetDeliveryGap(ctx, *intent.GapGeneration)
	if err != nil {
		return situation.NotificationDelivery{}, fmt.Errorf("cmd/alertint: situation deliverer: load delivery gap: %w", err)
	}
	rendered, err := slack.RenderDeliveryGapNotice(slack.GapNoticeInput{
		GapID:                  gap.ID,
		OpenedAt:               gap.OpenedAt,
		RecoveredAt:            gap.RecoveredAt,
		AffectedSituationCount: gap.AffectedSituationCount,
		DelayedEffectCount:     gap.DelayedEffectCount,
	})
	if err != nil {
		return situation.NotificationDelivery{}, invalidDelivery("render_failed",
			fmt.Errorf("cmd/alertint: situation deliverer: render gap notice: %w", err))
	}
	res, err := d.api.PostMessage(ctx, slack.PostMessageRequest{
		Channel:     d.channel,
		Text:        rendered.Text,
		Blocks:      rendered.Blocks,
		ClientMsgID: intent.ClientMessageID,
	})
	if err != nil {
		return situation.NotificationDelivery{}, err
	}
	return situation.NotificationDelivery{Channel: res.Channel, MessageTS: res.TS, DeliveredAs: "system"}, nil
}

// recoveryEverObserved answers SituationRootInput.RecoveryEverObserved: it
// only ever needs the ledger scan for a closed_unknown source Transition
// whose OWN projection carries no recovery observation (see situation.go's
// doc comment on SituationRootInput for why every other case is decided
// without one).
func (d *SituationDeliverer) recoveryEverObserved(ctx context.Context, view store.SituationEpisodeView) (bool, error) {
	if view.SourceTransition.Lifecycle != model.LifecycleClosedUnknown {
		return false, nil
	}
	if view.SourceTransition.Projection.RecoveryObservedAt != nil {
		return true, nil
	}
	cursor := store.TransitionCursor{}
	for page := 0; page < maxLedgerScanPages; page++ {
		transitions, err := d.store.ListSituationTransitions(ctx, view.Summary.SituationID, cursor, 0)
		if err != nil {
			return false, fmt.Errorf("cmd/alertint: situation deliverer: scan transition ledger: %w", err)
		}
		if len(transitions) == 0 {
			return false, nil
		}
		for _, tr := range transitions {
			if tr.Reason == model.ReasonRecoveryObserved {
				return true, nil
			}
		}
		last := transitions[len(transitions)-1]
		cursor = store.TransitionCursor{Sequence: last.Sequence, ID: last.ID}
	}
	return false, fmt.Errorf("cmd/alertint: situation deliverer: transition ledger for %s exceeds %d pages",
		view.Summary.SituationID, maxLedgerScanPages)
}

// ----------------------------------------------------------------------
// Failure classification (Task 7 alignment).
// ----------------------------------------------------------------------

// deliveryAdapterError carries one classified delivery failure across the
// package boundary as a situation.DeliveryFailure, so the notification
// worker resolves retry / configuration-block / fail without ever
// importing internal/notify/slack.
type deliveryAdapterError struct {
	class      situation.DeliveryErrorClass
	code       string
	retryAfter time.Duration
	err        error
}

func (e *deliveryAdapterError) Error() string { return e.err.Error() }
func (e *deliveryAdapterError) Unwrap() error { return e.err }

func (e *deliveryAdapterError) DeliveryErrorClass() situation.DeliveryErrorClass { return e.class }
func (e *deliveryAdapterError) DeliveryErrorCode() string                        { return e.code }
func (e *deliveryAdapterError) DeliveryRetryAfter() time.Duration                { return e.retryAfter }

// invalidDelivery marks one of this adapter's own errors as a
// non-recoverable programming/data error: a durable intent this build
// cannot render or send at all, however many times it retries.
func invalidDelivery(code string, err error) error {
	return &deliveryAdapterError{class: situation.DeliveryInvalid, code: code, err: err}
}

// classifyDeliveryError resolves one failed Deliver call into the closed
// situation.DeliveryFailure classification.
//
// Slack's own typed classification (slack.APIError) passes straight
// through: retryable transport/5xx/rate-limit/uncertain outcomes keep their
// Retry-After, definite token/scope/channel rejections block on
// configuration, and a malformed payload this build sent is invalid.
// Anything this adapter already proved invalid keeps that verdict. EVERY
// other error — a Store read failure, a stale summary version, a reply
// whose root is not published yet — stays retryable: none of them proves a
// permanent condition, and only a proven one may ever close a durable
// delivery obligation.
func classifyDeliveryError(err error) error {
	var adapterErr *deliveryAdapterError
	if errors.As(err, &adapterErr) {
		return adapterErr
	}
	var apiErr *slack.APIError
	if errors.As(err, &apiErr) {
		class := situation.DeliveryRetryable
		switch apiErr.Class {
		case slack.ErrorClassConfiguration:
			class = situation.DeliveryConfigurationBlocking
		case slack.ErrorClassInvalid:
			class = situation.DeliveryInvalid
		case slack.ErrorClassRetryable:
		}
		return &deliveryAdapterError{class: class, code: apiErr.Code, retryAfter: apiErr.RetryAfter, err: err}
	}
	return &deliveryAdapterError{class: situation.DeliveryRetryable, code: "delivery_failed", err: err}
}
