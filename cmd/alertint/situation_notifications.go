// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"

	"github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/notify/stdout"
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

// Probe verifies TOKEN readiness (auth.test) — the readiness check Task 7's
// gap lifecycle drives before recovery replay and before reactivating
// configuration-blocked intents. It proves the token can reach Slack and
// nothing about chat.postMessage/chat.update, so the worker never treats a
// successful probe as delivery health (NotificationWorker.probe).
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
		return situation.NotificationDelivery{}, localDelivery("episode_view_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load episode view: %w", err))
	}
	if view.Summary.Version != *intent.SummaryVersion {
		return situation.NotificationDelivery{}, localDelivery("stale_summary_version",
			fmt.Errorf("cmd/alertint: situation deliverer: intent names summary version %d, current is %d",
				*intent.SummaryVersion, view.Summary.Version))
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
		return situation.NotificationDelivery{}, localDelivery("root_coordinates_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load root coordinates: %w", err))
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
		return situation.NotificationDelivery{}, localDelivery("transition_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load transition: %w", err))
	}
	channel, rootTS, ok, err := d.store.GetSituationRootCoordinates(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, localDelivery("root_coordinates_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load root coordinates: %w", err))
	}
	if !ok {
		return situation.NotificationDelivery{}, localDelivery("root_not_published",
			fmt.Errorf("cmd/alertint: situation deliverer: situation %s has no delivered root to reply under", *intent.SituationID))
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
		return situation.NotificationDelivery{}, localDelivery("transition_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load transition: %w", err))
	}
	channel, rootTS, ok, err := d.store.GetSituationRootCoordinates(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, localDelivery("root_coordinates_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load root coordinates: %w", err))
	}
	if !ok {
		return situation.NotificationDelivery{}, localDelivery("root_not_published",
			fmt.Errorf("cmd/alertint: situation deliverer: situation %s has no delivered root to reply under", *intent.SituationID))
	}
	view, err := d.store.GetSituationEpisodeView(ctx, *intent.SituationID)
	if err != nil {
		return situation.NotificationDelivery{}, localDelivery("episode_view_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load episode view: %w", err))
	}
	// Revalidate the ACTION, not equality with the latest sequence: an
	// annotation advances the sequence without changing what the operator
	// is asked to do (situation.HandoffStillCurrent).
	current := situation.HandoffStillCurrent(tr, view.Summary)

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
		return situation.NotificationDelivery{}, localDelivery("delivery_gap_unavailable",
			fmt.Errorf("cmd/alertint: situation deliverer: load delivery gap: %w", err))
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
			return false, localDelivery("transition_ledger_unavailable",
				fmt.Errorf("cmd/alertint: situation deliverer: scan transition ledger: %w", err))
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

// localDelivery marks one of this adapter's own errors as a LOCAL
// data-state condition that stopped the attempt before any Slack call was
// made: a Store read that failed, an intent whose summary version is no
// longer current, or a reply whose root is not published yet. It retries
// exactly like any other retryable outcome — none of these proves a
// permanent condition — but it is not a Slack answer, so it must never move
// the dependency-health window or the Delivery-gap machinery. Reporting
// "Slack delivery failing" for a purely local mismatch would name an outage
// that is not happening.
func localDelivery(code string, err error) error {
	return &deliveryAdapterError{class: situation.DeliveryLocalRetryable, code: code, err: err}
}

// classifyDeliveryError resolves one failed Deliver call into the closed
// situation.DeliveryFailure classification.
//
// Slack's own typed classification (slack.APIError) passes straight
// through: retryable transport/5xx/rate-limit/uncertain outcomes keep their
// Retry-After, definite token/scope/channel rejections block on
// configuration, and a malformed payload this build sent is invalid. That
// is the ONLY source of a Slack-attributed outcome here: internal/notify/
// slack wraps every wire result — including a failed round trip — in a
// *slack.APIError, so an error that is not one never reached Slack.
// Anything this adapter already classified keeps its verdict. EVERY other
// error is therefore local: it retries (none of them proves a permanent
// condition, and only a proven one may ever close a durable delivery
// obligation) without being attributed to Slack health.
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
	return &deliveryAdapterError{class: situation.DeliveryLocalRetryable, code: "delivery_failed", err: err}
}

// ----------------------------------------------------------------------
// Situation notification runtime (Plan 3 Task 9)
//
// notificationRuntime bundles the two Plan 3 consumers of already-committed
// history — the Situation notification worker (the single reachable Slack
// writer) and the stdout Transition-stream worker — plus the startup-only
// recovery pass both depend on having already run.
//
// It is a THIRD runtime alongside foundationRuntime and controllerRuntime
// rather than an extension of either, and deliberately so. controllerRuntime
// exposes Drain, because its workers are producers whose queued work
// shutdown must drain to quiescence; these two workers must never be
// drained (R6: an external Slack outage would spin the bounded drain loop to
// its round cap and hold the whole process open). Giving them a Drain they
// may never be called with would make that guarantee a comment; leaving them
// in their own runtime with only Start/Stop makes it structural. The second
// reason is construction: the notification worker exists only when Situation
// Slack is configured, while the stdout stream always runs, and folding an
// optional Slack dependency into the always-present controller runtime would
// leak that optionality into every controller call site.
//
// main constructs exactly one per process and composes it into
// foundationSequence (recoverNotificationWork, startNotificationWorkers) and
// foundationStopSequence (stopNotificationWorkers, last).
// ----------------------------------------------------------------------

// notificationStartupStore is exactly the durable surface the startup pass
// drives. *store.Store satisfies it — asserted below.
type notificationStartupStore interface {
	RecoverExpiredNotificationClaims(ctx context.Context, now time.Time) (int, error)
	RecoverExpiredTransitionStreamClaims(ctx context.Context, now time.Time) (int, error)
	ScheduleSituationsMissingFirstTransition(ctx context.Context, now time.Time) (int, error)
	ScheduleSituationsWithStaleRootProjection(ctx context.Context, now time.Time) (int, error)
	GetSlackDeliveryState(ctx context.Context) (situation.SlackDeliveryState, error)
	RecoverDeliveryGap(ctx context.Context, now time.Time) (string, bool, error)
}

// slackConfigurationProbe is the readiness check startup step 4 runs.
// *SituationDeliverer satisfies it; it is nil when Slack is not configured.
type slackConfigurationProbe interface {
	Probe(ctx context.Context) error
}

// situationNotificationWorker is exactly what this runtime drives on the
// notification worker. *situation.NotificationWorker satisfies it.
type situationNotificationWorker interface {
	Start(ctx context.Context)
	Stop(ctx context.Context) error
	ReactivateConfiguration(ctx context.Context) (int, error)
}

// transitionStreamWorker is exactly what this runtime drives on the stdout
// stream worker. *stdout.TransitionStreamWorker satisfies it.
type transitionStreamWorker interface {
	Start(ctx context.Context)
	Stop(ctx context.Context) error
}

var (
	_ notificationStartupStore     = (*store.Store)(nil)
	_ stdout.TransitionStreamStore = (*store.Store)(nil)
)

// notificationRuntime owns the Slack notification worker (nil when
// Situation Slack is not configured) and the stdout Transition-stream
// worker (always present — the state stream is not Slack-gated).
type notificationRuntime struct {
	store  notificationStartupStore
	probe  slackConfigurationProbe
	worker situationNotificationWorker
	stream transitionStreamWorker
	logger *slog.Logger
}

// newNotificationRuntime wires the runtime. worker/probe may both be nil
// (Situation Slack disabled or unconfigured), in which case durable blocked
// intents are retained untouched and only the stdout stream runs. stream may
// be nil only in tests that exercise the startup pass alone.
func newNotificationRuntime(st notificationStartupStore, probe slackConfigurationProbe,
	worker situationNotificationWorker, stream transitionStreamWorker, logger *slog.Logger) *notificationRuntime {
	if logger == nil {
		logger = slog.Default()
	}
	return &notificationRuntime{store: st, probe: probe, worker: worker, stream: stream, logger: logger}
}

// notificationRecovery is the startup pass's report, for
// logNotificationRecoveryReport's sibling logging call.
type notificationRecovery struct {
	NotificationClaimsRecovered  int
	StreamClaimsRecovered        int
	ScheduledMissingHistory      int
	ScheduledStaleRoot           int
	SlackConfigurationValid      bool
	ConfigurationGeneration      int64
	Reactivated                  int
	BlockedConfigurationRetained int
	GapReplayResumed             bool
	GapGeneration                string
}

// RecoverAndReactivate runs spec.md's own startup steps 2 through 6, in that
// exact order, after Plan 1/2 reconstruction and Plan 2's controller
// recovery and BEFORE any worker or Receiver starts:
//
//  2. recover expired notification and stdout-stream claims;
//  3. schedule every nonterminal Situation missing its first Transition;
//  4. validate the Slack configuration and record its generation;
//  5. reactivate eligible configuration-blocked intents; and
//  6. perform stale-root supersession and resume ordered recovery replay.
//
// Step 6's supersession half runs unconditionally; step 5 and step 6's replay
// half are the only two pieces that require the Slack probe to have
// succeeded, because only a corrected configuration may reactivate a blocked
// intent and only a live Slack may move a gap generation into replay.
//
// It publishes nothing. Steps 3 and 6 only pull a Situation's next
// assessment forward, so the ordinary controller path decides — under the
// ordinary materiality and publication rules — whether anything is committed
// at all; a restart on unchanged truth therefore creates no Transition and
// no Slack effect ("Startup never publishes merely because the binary
// restarted").
//
// A failed Slack probe is NOT an error: an unreachable or misconfigured
// Slack at boot is an ordinary delay, so step 5 and step 6's REPLAY half are
// skipped — step 6's stale-root supersession still runs — every blocked
// intent stays durably blocked, and the process still starts. Only a genuine
// Store failure returns an error, and then the caller must not start
// Receivers.
func (r *notificationRuntime) RecoverAndReactivate(ctx context.Context, now time.Time) (notificationRecovery, error) {
	var report notificationRecovery

	recovered, err := r.store.RecoverExpiredNotificationClaims(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation notifications: recover expired notification claims: %w", err)
	}
	report.NotificationClaimsRecovered = recovered

	recoveredStream, err := r.store.RecoverExpiredTransitionStreamClaims(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation notifications: recover expired transition stream claims: %w", err)
	}
	report.StreamClaimsRecovered = recoveredStream

	scheduled, err := r.store.ScheduleSituationsMissingFirstTransition(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation notifications: schedule situations missing a first transition: %w", err)
	}
	report.ScheduledMissingHistory = scheduled

	report.SlackConfigurationValid = r.validateSlackConfiguration(ctx)

	state, err := r.store.GetSlackDeliveryState(ctx)
	if err != nil {
		return report, fmt.Errorf("situation notifications: read slack delivery state: %w", err)
	}
	report.ConfigurationGeneration = state.ConfigurationGeneration
	report.BlockedConfigurationRetained = state.BlockedConfigurationCount

	// Step 5 — gated: only a CORRECTED Slack configuration may return a
	// blocked intent to pending, and a failed probe has not corrected
	// anything. The worker's own first successful probe applies it later if
	// Slack comes back within this process's lifetime.
	if report.SlackConfigurationValid {
		if err := r.reactivateConfiguration(ctx, &report); err != nil {
			return report, err
		}
	}

	// Step 6a — UNCONDITIONAL. Stale-root supersession scheduling is
	// publication-free and touches only durable root-supersession state, so
	// it needs no reachable Slack at all. It is also startup-only with no
	// steady-state equivalent, so gating it on the probe would let one
	// transient boot-time Slack blip skip it for the whole process lifetime.
	staleRoots, err := r.store.ScheduleSituationsWithStaleRootProjection(ctx, now)
	if err != nil {
		return report, fmt.Errorf("situation notifications: schedule situations with a stale root projection: %w", err)
	}
	report.ScheduledStaleRoot = staleRoots

	// Step 6b — gated: a gap generation may only move to replaying once
	// Slack actually answers again. Unlike step 6a this HAS a steady-state
	// equivalent — the worker's probe loop calls RecoverDeliveryGap on every
	// successful probe — so skipping it here costs latency, never coverage.
	if report.SlackConfigurationValid {
		if err := r.resumeGapReplay(ctx, now, &report); err != nil {
			return report, err
		}
	}
	return report, nil
}

// validateSlackConfiguration is startup step 4. No probe at all (Slack
// disabled) and a failed probe are both "not validated": neither may
// reactivate a blocked intent, since only a corrected configuration may, and
// neither is a startup failure.
func (r *notificationRuntime) validateSlackConfiguration(ctx context.Context) bool {
	if r.probe == nil {
		return false
	}
	if err := r.probe.Probe(ctx); err != nil {
		r.logger.Warn("situation notifications: slack configuration did not validate at startup; "+
			"blocked effects are retained and delivery is delayed", slog.String("err", err.Error()))
		return false
	}
	return true
}

// reactivateConfiguration is startup step 5: return every eligible
// configuration-blocked intent to pending under a fresh configuration
// generation, exactly once per process (the worker's own one-shot guard makes
// this idempotent against its first steady-state probe, whichever runs
// first). A no-Slack build has no worker and nothing to reactivate.
func (r *notificationRuntime) reactivateConfiguration(ctx context.Context, report *notificationRecovery) error {
	if r.worker == nil {
		return nil
	}
	n, err := r.worker.ReactivateConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("situation notifications: reactivate configuration-blocked intents: %w", err)
	}
	report.Reactivated = n
	if n > 0 && report.BlockedConfigurationRetained >= n {
		report.BlockedConfigurationRetained -= n
	}
	return nil
}

// resumeGapReplay is startup step 6's replay half: move a generation left
// open by the previous process into replaying now that Slack has answered,
// rather than waiting for the worker's first steady-state probe.
func (r *notificationRuntime) resumeGapReplay(ctx context.Context, now time.Time, report *notificationRecovery) error {
	generation, resumed, err := r.store.RecoverDeliveryGap(ctx, now)
	if err != nil {
		return fmt.Errorf("situation notifications: resume delivery gap replay: %w", err)
	}
	report.GapReplayResumed = resumed
	report.GapGeneration = generation
	return nil
}

// Start launches the notification worker, then the stdout stream worker,
// each on its own background schedule. Call only after RecoverAndReactivate
// has succeeded, and after the controller/Triage workers have started.
func (r *notificationRuntime) Start(ctx context.Context) {
	if r.worker != nil {
		r.worker.Start(ctx)
	}
	if r.stream != nil {
		r.stream.Start(ctx)
	}
}

// Stop stops the stdout stream worker, then the notification worker — the
// reverse of Start, mirroring the other two runtimes' stop-in-reverse
// discipline. Each runs its own ONE bounded final pass under ctx and then
// releases every claim it still holds (R6). Neither ever joins the shutdown
// drain rounds, so an unreachable Slack cannot hold the process open past
// the shutdown context's own deadline; whatever stays pending is reclaimed
// at the next startup.
func (r *notificationRuntime) Stop(ctx context.Context) error {
	var errs []error
	if r.stream != nil {
		if err := r.stream.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("transition stream worker stop: %w", err))
		}
	}
	if r.worker != nil {
		if err := r.worker.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("notification worker stop: %w", err))
		}
	}
	return errors.Join(errs...)
}

// logNotificationRecoveryReport logs one RecoverAndReactivate pass at
// startup — the sibling of logReconstructionReport and
// logControllerRecoveryReport.
func logNotificationRecoveryReport(logger *slog.Logger, report notificationRecovery) {
	logger.Info("situation notifications recovered",
		slog.Int("notification_claims_recovered", report.NotificationClaimsRecovered),
		slog.Int("transition_stream_claims_recovered", report.StreamClaimsRecovered),
		slog.Int("situations_scheduled_for_first_transition", report.ScheduledMissingHistory),
		slog.Int("situations_scheduled_for_stale_root", report.ScheduledStaleRoot),
		slog.Bool("slack_configuration_valid", report.SlackConfigurationValid),
		slog.Int64("slack_configuration_generation", report.ConfigurationGeneration),
		slog.Int("configuration_blocked_reactivated", report.Reactivated),
		slog.Int("configuration_blocked_retained", report.BlockedConfigurationRetained),
		slog.Bool("gap_replay_resumed", report.GapReplayResumed),
	)
	if report.BlockedConfigurationRetained > 0 {
		logger.Warn("situation notifications: durable effects remain blocked on Slack configuration; "+
			"they are retained, never failed, and reactivate after a restart with corrected configuration",
			slog.Int("blocked_effects", report.BlockedConfigurationRetained))
	}
}

// runNotificationRecovery runs one notificationRuntime.RecoverAndReactivate
// pass and logs its report — the recoverNotificationWork step of runServe's
// own startupSeq. A named function, not a closure, for the same
// gocyclo reason runFoundationReconstruction and runControllerRecovery are.
func runNotificationRecovery(ctx context.Context, nrt *notificationRuntime, logger *slog.Logger) error {
	report, err := nrt.RecoverAndReactivate(ctx, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("situation notification recovery: %w", err)
	}
	logNotificationRecoveryReport(logger, report)
	return nil
}

// buildSituationNotificationRuntime assembles the process's one
// notificationRuntime from configuration.
//
// The stdout Transition-stream worker is ALWAYS built: spec.md makes
// Situation Transition events the authoritative outward state stream, and a
// silent, floor-withheld, or Slack-disabled installation still emits its
// complete history there. `notify.stdout` gates the legacy Finding JSON
// lines only, never this stream.
//
// The Slack notification worker is built only when Situation Slack is
// actually usable: enabled, with a resolvable bot token and a channel. When
// it is not, no Slack credential is constructed on this path at all and
// every durable blocked intent is retained untouched — never failed, never
// silently dropped — so a restart with corrected configuration reactivates
// it. Together with buildNotifier's System-message-only Slack notifier
// (ADR-0042/ADR-0046), these are the only two places in production that
// receive a Slack credential.
func buildSituationNotificationRuntime(cfg *config.Config, st *store.Store, auditor *audit.Auditor,
	owner string, logger *slog.Logger) *notificationRuntime {
	// TRUE nil interfaces, never typed nils: a nil *audit.Auditor stored in
	// an interface is non-nil and would panic on its first Append (the same
	// typed-nil trap sentryErrorSource/zabbixContextSource guard against).
	var streamAudit stdout.TransitionStreamAuditSink
	var deliveryAudit situation.AuditSink
	if auditor != nil {
		streamAudit = auditor
		deliveryAudit = auditor
	}
	stream := stdout.NewTransitionStreamWorker(os.Stdout, st,
		stdout.TransitionStreamConfig{Owner: owner + ":transition-stream"}, streamAudit,
		func() time.Time { return time.Now().UTC() }, logger)

	probe, worker := buildSituationSlackWorker(cfg, st, owner, deliveryAudit, logger)
	if worker == nil {
		logger.Info("situation notifications: slack delivery is not configured; "+
			"Situation history is complete in the store, MCP, audit, and the stdout Transition stream",
			slog.Bool("slack_enabled", cfg.Notify.Slack.Enabled))
	} else {
		logger.Info("situation notifications: slack delivery ready",
			slog.String("slack_channel", cfg.Notify.Slack.Channel))
	}
	return newNotificationRuntime(st, probe, worker, stream, logger)
}

// buildSituationSlackWorker resolves the Slack credential and, when it is
// usable, constructs the deliverer and the single notification worker. It
// returns (nil, nil) — TRUE nil interfaces, never typed nils — whenever
// Situation Slack cannot be used.
func buildSituationSlackWorker(cfg *config.Config, st *store.Store, owner string,
	auditSink situation.AuditSink, logger *slog.Logger) (slackConfigurationProbe, situationNotificationWorker) {
	if !cfg.Notify.Slack.Enabled || strings.TrimSpace(cfg.Notify.Slack.Channel) == "" {
		return nil, nil
	}
	token, err := cfg.SlackBotToken()
	if err != nil || strings.TrimSpace(token) == "" {
		logger.Warn("situation notifications: slack is enabled but no bot token resolved; " +
			"Situation Slack delivery stays off and durable effects are retained")
		return nil, nil
	}
	api := slack.NewClient(slack.Config{BotToken: token})
	deliverer := NewSituationDeliverer(st, api, cfg.Notify.Slack.Channel, func() time.Time { return time.Now().UTC() })
	worker := situation.NewNotificationWorker(st, deliverer,
		situation.NotificationWorkerConfig{
			// Lease/heartbeat reuse Plan 2's existing situations.* settings
			// (plan.md: "Plan 3 adds no duplicate notification knobs"); Poll,
			// Batch, the retry schedule, and the five-minute gap threshold are
			// the protocol's own constants, not operator knobs.
			Owner:     owner + ":notifications",
			Lease:     time.Duration(cfg.Situations.LeaseSeconds) * time.Second,
			Heartbeat: time.Duration(cfg.Situations.HeartbeatSeconds) * time.Second,
			Poll:      time.Duration(cfg.Situations.ReconcilePollSeconds) * time.Second,
		},
		func() time.Time { return time.Now().UTC() }, logger)
	worker.SetAuditSink(auditSink)
	return deliverer, worker
}
