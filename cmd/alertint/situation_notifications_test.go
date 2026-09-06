// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------

const sdSituationID = "1f0f5a0c-0000-4000-8000-0000000000d1"

func sdMustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm.UTC()
}

func sdTimePtr(t time.Time) *time.Time { return &t }

func sdRunningTriageContract(next time.Time) model.ActionContract {
	action := model.AlertINTActionRunAcuteTriage
	status := model.AlertINTStatusRunning
	return model.ActionContract{
		NextActor:      model.NextActorAlertINT,
		AlertINTAction: &action,
		AlertINTStatus: &status,
		NextUpdateAt:   sdTimePtr(next),
		NextUpdateOn:   []model.NextUpdateOn{model.NextUpdateOnTriageOutcome},
	}
}

func sdTerminalContract() model.ActionContract {
	return model.ActionContract{NextActor: model.NextActorNone}
}

func sdTransition(seq int, lifecycle model.Lifecycle, contract model.ActionContract,
	reason model.TransitionReason, journalKind model.JournalKind, journal model.JournalData,
	projection model.ProjectionFacts, createdAt time.Time) model.Transition {
	return model.Transition{
		ID:               fmt.Sprintf("transition-%03d", seq),
		SituationID:      sdSituationID,
		Sequence:         seq,
		InputVersion:     seq,
		MaterialFactHash: "sha256:abc123",
		Lifecycle:        lifecycle,
		Attention:        model.AttentionInvestigate,
		ActionContract:   contract,
		Reason:           reason,
		JournalKind:      journalKind,
		Journal:          journal,
		Projection:       projection,
		EvidenceRefs:     []string{"evidence-1"},
		Actor:            model.ActorDeterministicController,
		CreatedAt:        createdAt,
	}
}

func sdSummary(seq int, contract model.ActionContract, startedAt, updatedAt time.Time) model.EpisodeSummary {
	return model.EpisodeSummary{
		SituationID:              sdSituationID,
		Version:                  seq,
		SourceTransitionSequence: seq,
		Title:                    "Situation checkout-001",
		CurrentAttention:         model.AttentionInvestigate,
		PeakAttention:            model.AttentionInvestigate,
		ActionContract:           contract,
		EffectiveStartedAt:       startedAt,
		UpdatedAt:                updatedAt,
		InvestigationWork:        []string{},
		RecordedOperatorContext:  []string{},
	}
}

func sdRootSyncIntent(transitionID string, summaryVersion int, deadline *time.Time, now time.Time) model.NotificationIntent {
	situationID := sdSituationID
	return model.NotificationIntent{
		ID:                 "intent-root-1",
		IdempotencyKey:     "root_sync:1",
		EffectClass:        model.EffectRootSync,
		SituationID:        &situationID,
		TransitionID:       &transitionID,
		SummaryVersion:     &summaryVersion,
		ClientMessageID:    "client-msg-root-1",
		Status:             model.IntentPending,
		CreatedAt:          now,
		ContractDeadlineAt: deadline,
	}
}

func sdThreadIntent(class model.EffectClass, transitionID string, seq int, now time.Time) model.NotificationIntent {
	s := seq
	situationID := sdSituationID
	return model.NotificationIntent{
		ID:                 "intent-thread-1",
		IdempotencyKey:     "thread:1",
		EffectClass:        class,
		SituationID:        &situationID,
		TransitionID:       &transitionID,
		TransitionSequence: &s,
		RequiresRoot:       true,
		ClientMessageID:    "client-msg-thread-1",
		Status:             model.IntentPending,
		CreatedAt:          now,
	}
}

func sdGapIntent(gapGeneration string, now time.Time) model.NotificationIntent {
	return model.NotificationIntent{
		ID:              "intent-gap-1",
		IdempotencyKey:  "gap:1",
		EffectClass:     model.EffectInstallationGapRecovery,
		GapGeneration:   &gapGeneration,
		ClientMessageID: "client-msg-gap-1",
		Status:          model.IntentPending,
		CreatedAt:       now,
	}
}

// sdBlocksText flattens a rendered Block Kit body's text content for
// substring assertions, mirroring internal/notify/slack's own test helper.
func sdBlocksText(t *testing.T, blocks []slacklib.Block) string {
	t.Helper()
	var b strings.Builder
	for _, blk := range blocks {
		switch v := blk.(type) {
		case *slacklib.SectionBlock:
			if v.Text != nil {
				b.WriteString(v.Text.Text)
				b.WriteString("\n")
			}
		case *slacklib.ContextBlock:
			for _, el := range v.ContextElements.Elements {
				if txt, ok := el.(*slacklib.TextBlockObject); ok {
					b.WriteString(txt.Text)
					b.WriteString("\n")
				}
			}
		}
	}
	return b.String()
}

// ----------------------------------------------------------------------
// Fakes
// ----------------------------------------------------------------------

type fakeDelivererStore struct {
	episode    store.SituationEpisodeView
	episodeErr error

	transitions   map[string]model.Transition
	transitionErr error

	ledger    []model.Transition
	ledgerErr error
	listCalls int

	rootChannel string
	rootTS      string
	rootOK      bool
	rootErr     error

	gap    store.GapSnapshot
	gapErr error
}

func (f *fakeDelivererStore) GetSituationEpisodeView(context.Context, string) (store.SituationEpisodeView, error) {
	if f.episodeErr != nil {
		return store.SituationEpisodeView{}, f.episodeErr
	}
	return f.episode, nil
}

func (f *fakeDelivererStore) GetSituationTransition(_ context.Context, transitionID string) (model.Transition, error) {
	if f.transitionErr != nil {
		return model.Transition{}, f.transitionErr
	}
	tr, ok := f.transitions[transitionID]
	if !ok {
		return model.Transition{}, store.ErrNotFound
	}
	return tr, nil
}

func (f *fakeDelivererStore) ListSituationTransitions(_ context.Context, _ string, cursor store.TransitionCursor, _ int) ([]model.Transition, error) {
	f.listCalls++
	if f.ledgerErr != nil {
		return nil, f.ledgerErr
	}
	var out []model.Transition
	for _, tr := range f.ledger {
		if tr.Sequence > cursor.Sequence || (tr.Sequence == cursor.Sequence && tr.ID > cursor.ID) {
			out = append(out, tr)
		}
	}
	return out, nil
}

func (f *fakeDelivererStore) GetSituationRootCoordinates(context.Context, string) (string, string, bool, error) {
	if f.rootErr != nil {
		return "", "", false, f.rootErr
	}
	return f.rootChannel, f.rootTS, f.rootOK, nil
}

func (f *fakeDelivererStore) GetDeliveryGap(context.Context, string) (store.GapSnapshot, error) {
	if f.gapErr != nil {
		return store.GapSnapshot{}, f.gapErr
	}
	return f.gap, nil
}

type fakeSlackAPI struct {
	postErr      error
	updateErr    error
	authErr      error
	posts        []slack.PostMessageRequest
	updates      []slack.UpdateMessageRequest
	postResult   slack.MessageResult
	updateResult slack.MessageResult
	authCalls    int
}

func (f *fakeSlackAPI) PostMessage(_ context.Context, req slack.PostMessageRequest) (slack.MessageResult, error) {
	f.posts = append(f.posts, req)
	if f.postErr != nil {
		return slack.MessageResult{}, f.postErr
	}
	if f.postResult != (slack.MessageResult{}) {
		return f.postResult, nil
	}
	return slack.MessageResult{Channel: "C-posted", TS: "9.9"}, nil
}

func (f *fakeSlackAPI) UpdateMessage(_ context.Context, req slack.UpdateMessageRequest) (slack.MessageResult, error) {
	f.updates = append(f.updates, req)
	if f.updateErr != nil {
		return slack.MessageResult{}, f.updateErr
	}
	if f.updateResult != (slack.MessageResult{}) {
		return f.updateResult, nil
	}
	return slack.MessageResult{Channel: req.Channel, TS: req.TS}, nil
}

func (f *fakeSlackAPI) AuthTest(context.Context) error {
	f.authCalls++
	return f.authErr
}

// ----------------------------------------------------------------------
// root_sync
// ----------------------------------------------------------------------

func TestSituationDelivererRootSyncPostsFirstRoot(t *testing.T) {
	started := sdMustTime(t, "2026-09-05T09:00:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	deadline := now.Add(time.Minute)
	contract := sdRunningTriageContract(deadline)
	tr := sdTransition(1, model.LifecycleActive, contract, model.ReasonFirstAuthoritativeState,
		model.JournalPublication, model.JournalData{Headline: "Situation published", OccurredAt: started},
		model.ProjectionFacts{EffectiveStartedAt: started, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	summary := sdSummary(1, contract, started, now)

	fs := &fakeDelivererStore{
		episode: store.SituationEpisodeView{Summary: summary, SourceTransition: tr},
		rootOK:  false,
	}
	api := &fakeSlackAPI{postResult: slack.MessageResult{Channel: "C-root", TS: "100.1"}}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdRootSyncIntent(tr.ID, 1, &deadline, now)
	got, err := d.Deliver(context.Background(), intent)
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if got != (situation.NotificationDelivery{Channel: "C-root", MessageTS: "100.1", DeliveredAs: "root"}) {
		t.Fatalf("Deliver() = %+v, want the posted root coordinates", got)
	}
	if len(api.posts) != 1 || len(api.updates) != 0 {
		t.Fatalf("want exactly one PostMessage and zero UpdateMessage calls; got posts=%d updates=%d", len(api.posts), len(api.updates))
	}
	if api.posts[0].Channel != "C-default" {
		t.Fatalf("PostMessage channel = %q, want the configured default channel", api.posts[0].Channel)
	}
	if api.posts[0].ClientMsgID != intent.ClientMessageID {
		t.Fatalf("PostMessage client msg id = %q, want %q", api.posts[0].ClientMsgID, intent.ClientMessageID)
	}
}

func TestSituationDelivererRootSyncUpdatesExistingRoot(t *testing.T) {
	started := sdMustTime(t, "2026-09-05T09:00:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	deadline := now.Add(time.Minute)
	contract := sdRunningTriageContract(deadline)
	tr := sdTransition(2, model.LifecycleActive, contract, model.ReasonInvestigationStarted,
		model.JournalInvestigationStarted, model.JournalData{Headline: "AlertINT investigation started", OccurredAt: started},
		model.ProjectionFacts{EffectiveStartedAt: started, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	summary := sdSummary(2, contract, started, now)

	fs := &fakeDelivererStore{
		episode:     store.SituationEpisodeView{Summary: summary, SourceTransition: tr},
		rootOK:      true,
		rootChannel: "C-existing",
		rootTS:      "50.5",
	}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdRootSyncIntent(tr.ID, 2, &deadline, now)
	got, err := d.Deliver(context.Background(), intent)
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if got.DeliveredAs != "root" || got.Channel != "C-existing" || got.MessageTS != "50.5" {
		t.Fatalf("Deliver() = %+v, want the existing root's own coordinates echoed back", got)
	}
	if len(api.updates) != 1 || len(api.posts) != 0 {
		t.Fatalf("want exactly one UpdateMessage and zero PostMessage calls; got updates=%d posts=%d", len(api.updates), len(api.posts))
	}
	if api.updates[0].Channel != "C-existing" || api.updates[0].TS != "50.5" {
		t.Fatalf("UpdateMessage coordinates = %+v, want the existing root's own", api.updates[0])
	}
}

func TestSituationDelivererRootSyncRejectsStaleSummaryVersion(t *testing.T) {
	started := sdMustTime(t, "2026-09-05T09:00:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	deadline := now.Add(time.Minute)
	contract := sdRunningTriageContract(deadline)
	tr := sdTransition(3, model.LifecycleActive, contract, model.ReasonInvestigationStarted,
		model.JournalInvestigationStarted, model.JournalData{Headline: "x", OccurredAt: started},
		model.ProjectionFacts{EffectiveStartedAt: started, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	summary := sdSummary(3, contract, started, now) // current version is 3

	fs := &fakeDelivererStore{episode: store.SituationEpisodeView{Summary: summary, SourceTransition: tr}}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdRootSyncIntent(tr.ID, 1, &deadline, now) // stale: names version 1
	if _, err := d.Deliver(context.Background(), intent); err == nil {
		t.Fatal("Deliver() error = nil, want an error for a stale summary version")
	}
	if len(api.posts) != 0 || len(api.updates) != 0 {
		t.Fatal("a stale-version root_sync must never reach Slack")
	}
}

// ----------------------------------------------------------------------
// thread_append
// ----------------------------------------------------------------------

func TestSituationDelivererThreadAppendPostsUnderRoot(t *testing.T) {
	occurred := sdMustTime(t, "2026-09-05T09:15:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	tr := sdTransition(4, model.LifecycleActive, sdRunningTriageContract(now.Add(time.Hour)),
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "AlertINT investigation started", OccurredAt: occurred},
		model.ProjectionFacts{EffectiveStartedAt: occurred, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, occurred)

	fs := &fakeDelivererStore{
		transitions: map[string]model.Transition{tr.ID: tr},
		rootOK:      true, rootChannel: "C-existing", rootTS: "50.5",
	}
	api := &fakeSlackAPI{postResult: slack.MessageResult{Channel: "C-existing", TS: "60.6"}}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)
	got, err := d.Deliver(context.Background(), intent)
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if got.DeliveredAs != "thread" {
		t.Fatalf("DeliveredAs = %q, want thread", got.DeliveredAs)
	}
	if len(api.posts) != 1 {
		t.Fatalf("want exactly one PostMessage call, got %d", len(api.posts))
	}
	if api.posts[0].ThreadTS != "50.5" {
		t.Fatalf("ThreadTS = %q, want the root's own ts", api.posts[0].ThreadTS)
	}
	if api.posts[0].ReplyBroadcast {
		t.Fatal("a plain thread_append must never broadcast")
	}
	if !strings.Contains(api.posts[0].Text, "AlertINT investigation started") {
		t.Fatalf("posted text = %q, want the Transition's own headline", api.posts[0].Text)
	}
}

func TestSituationDelivererThreadAppendRequiresExistingRoot(t *testing.T) {
	occurred := sdMustTime(t, "2026-09-05T09:15:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	tr := sdTransition(5, model.LifecycleActive, sdRunningTriageContract(now.Add(time.Hour)),
		model.ReasonInvestigationStarted, model.JournalInvestigationStarted,
		model.JournalData{Headline: "x", OccurredAt: occurred},
		model.ProjectionFacts{EffectiveStartedAt: occurred, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, occurred)

	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr}, rootOK: false}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)
	if _, err := d.Deliver(context.Background(), intent); err == nil {
		t.Fatal("Deliver() error = nil, want an error: a root must be delivered before a reply is claimable")
	}
	if len(api.posts) != 0 {
		t.Fatal("must never post a reply without an existing root")
	}
}

// ----------------------------------------------------------------------
// broadcast_handoff
// ----------------------------------------------------------------------

func TestSituationDelivererBroadcastHandoffCurrentBroadcasts(t *testing.T) {
	occurred := sdMustTime(t, "2026-09-05T09:15:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	action := model.OperatorActionInvestigateSituation
	contract := model.ActionContract{
		NextActor: model.NextActorOperator, OperatorActionRequired: &action,
		NextUpdateAt: sdTimePtr(now.Add(time.Hour)), NextUpdateOn: []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
	}
	tr := sdTransition(6, model.LifecycleActive, contract, model.ReasonOperatorContractChanged,
		model.JournalOperatorContractChanged, model.JournalData{Headline: "Operator action required: investigate_situation", OccurredAt: occurred},
		model.ProjectionFacts{EffectiveStartedAt: occurred, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, occurred)
	summary := sdSummary(6, contract, occurred, now) // SourceTransitionSequence == 6: still current

	fs := &fakeDelivererStore{
		episode:     store.SituationEpisodeView{Summary: summary, SourceTransition: tr},
		transitions: map[string]model.Transition{tr.ID: tr},
		rootOK:      true, rootChannel: "C-existing", rootTS: "50.5",
	}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdThreadIntent(model.EffectBroadcastHandoff, tr.ID, tr.Sequence, now)
	got, err := d.Deliver(context.Background(), intent)
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if got.DeliveredAs != "broadcast" {
		t.Fatalf("DeliveredAs = %q, want broadcast", got.DeliveredAs)
	}
	if len(api.posts) != 1 || !api.posts[0].ReplyBroadcast {
		t.Fatalf("want exactly one broadcast PostMessage call; got %+v", api.posts)
	}
	if strings.Contains(sdBlocksText(t, api.posts[0].Blocks), "no longer current") {
		t.Fatal("a still-current handoff must not render as no-longer-current")
	}
}

func TestSituationDelivererBroadcastHandoffStaleDemotesToDelayedThread(t *testing.T) {
	occurred := sdMustTime(t, "2026-09-05T09:15:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	action := model.OperatorActionInvestigateSituation
	handoffContract := model.ActionContract{
		NextActor: model.NextActorOperator, OperatorActionRequired: &action,
		NextUpdateAt: sdTimePtr(now.Add(time.Hour)), NextUpdateOn: []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
	}
	handoffTr := sdTransition(7, model.LifecycleActive, handoffContract, model.ReasonOperatorContractChanged,
		model.JournalOperatorContractChanged, model.JournalData{Headline: "Operator action required: investigate_situation", OccurredAt: occurred},
		model.ProjectionFacts{EffectiveStartedAt: occurred, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, occurred)

	// A LATER Transition has since superseded it: the current summary's
	// source sequence has moved on to 8.
	laterContract := sdRunningTriageContract(now.Add(time.Hour))
	laterTr := sdTransition(8, model.LifecycleActive, laterContract, model.ReasonInvestigationStarted,
		model.JournalInvestigationStarted, model.JournalData{Headline: "AlertINT investigation started", OccurredAt: now},
		model.ProjectionFacts{EffectiveStartedAt: occurred, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, now)
	summary := sdSummary(8, laterContract, occurred, now)

	fs := &fakeDelivererStore{
		episode:     store.SituationEpisodeView{Summary: summary, SourceTransition: laterTr},
		transitions: map[string]model.Transition{handoffTr.ID: handoffTr},
		rootOK:      true, rootChannel: "C-existing", rootTS: "50.5",
	}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdThreadIntent(model.EffectBroadcastHandoff, handoffTr.ID, handoffTr.Sequence, now)
	got, err := d.Deliver(context.Background(), intent)
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if got.DeliveredAs != "delayed_thread" {
		t.Fatalf("DeliveredAs = %q, want delayed_thread", got.DeliveredAs)
	}
	if len(api.posts) != 1 || api.posts[0].ReplyBroadcast {
		t.Fatalf("a stale handoff must post a plain (non-broadcast) reply; got %+v", api.posts)
	}
	if !strings.Contains(sdBlocksText(t, api.posts[0].Blocks), "no longer current") {
		t.Fatalf("posted body = %q, want a no-longer-current marker", sdBlocksText(t, api.posts[0].Blocks))
	}
	// The durable ledger row itself is never mutated.
	if handoffTr.Journal.Delayed || handoffTr.Journal.NoLongerCurrent {
		t.Fatal("the original Transition value must never be mutated")
	}
}

// ----------------------------------------------------------------------
// installation_gap_recovery
// ----------------------------------------------------------------------

func TestSituationDelivererGapRecoveryPostsSystemNotice(t *testing.T) {
	opened := sdMustTime(t, "2026-09-05T09:00:00Z")
	recovered := sdMustTime(t, "2026-09-05T09:10:00Z")
	now := recovered

	fs := &fakeDelivererStore{gap: store.GapSnapshot{
		ID: "gap-1", OpenedAt: opened, RecoveredAt: recovered, AffectedSituationCount: 2, DelayedEffectCount: 5,
	}}
	api := &fakeSlackAPI{postResult: slack.MessageResult{Channel: "C-default", TS: "70.7"}}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

	intent := sdGapIntent("gap-1", now)
	got, err := d.Deliver(context.Background(), intent)
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if got != (situation.NotificationDelivery{Channel: "C-default", MessageTS: "70.7", DeliveredAs: "system"}) {
		t.Fatalf("Deliver() = %+v, want the posted system notice coordinates", got)
	}
	if len(api.posts) != 1 || api.posts[0].Channel != "C-default" {
		t.Fatalf("want exactly one PostMessage to the default channel; got %+v", api.posts)
	}
	if api.posts[0].ThreadTS != "" || api.posts[0].ReplyBroadcast {
		t.Fatal("the installation gap notice is a root post, never a thread reply")
	}
	if !strings.Contains(api.posts[0].Text, "2 Situation(s)") {
		t.Fatalf("posted text = %q, want the affected-Situation count", api.posts[0].Text)
	}
}

// ----------------------------------------------------------------------
// Probe
// ----------------------------------------------------------------------

func TestSituationDelivererProbeCallsAuthTest(t *testing.T) {
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(&fakeDelivererStore{}, api, "C-default", nil)
	if err := d.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if api.authCalls != 1 {
		t.Fatalf("auth.test calls = %d, want 1", api.authCalls)
	}
}

func TestSituationDelivererProbePropagatesFailure(t *testing.T) {
	wantErr := &slack.APIError{Class: slack.ErrorClassConfiguration, Code: "invalid_auth"}
	api := &fakeSlackAPI{authErr: wantErr}
	d := NewSituationDeliverer(&fakeDelivererStore{}, api, "C-default", nil)
	err := d.Probe(context.Background())
	if !errors.Is(err, wantErr) {
		var apiErr *slack.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != "invalid_auth" {
			t.Fatalf("Probe() error = %v, want it to propagate the configuration-blocking failure", err)
		}
	}
}

// ----------------------------------------------------------------------
// recoveryEverObserved ledger scan
// ----------------------------------------------------------------------

func TestSituationDelivererRootSyncScansLedgerOnlyForClosedUnknownWithoutOwnRecovery(t *testing.T) {
	started := sdMustTime(t, "2026-09-05T09:00:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	terminalReason := model.TerminalReasonObservationDeadline

	cases := []struct {
		name             string
		lifecycle        model.Lifecycle
		ownRecoveryAt    *time.Time
		ledgerHasRecover bool
		wantScan         bool
	}{
		{
			name:      "nonterminal: never scans",
			lifecycle: model.LifecycleActive,
			wantScan:  false,
		},
		{
			name:             "closed_unknown with its own recovery observation: never scans",
			lifecycle:        model.LifecycleClosedUnknown,
			ownRecoveryAt:    sdTimePtr(started.Add(time.Hour)),
			ledgerHasRecover: true, // irrelevant; must not even be consulted
			wantScan:         false,
		},
		{
			name:             "closed_unknown with no own recovery: scans the ledger",
			lifecycle:        model.LifecycleClosedUnknown,
			ledgerHasRecover: true,
			wantScan:         true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			contract := sdTerminalContract()
			deadlinePtr := (*time.Time)(nil)
			if c.lifecycle == model.LifecycleActive {
				d := now.Add(time.Minute)
				deadlinePtr = &d
				contract = sdRunningTriageContract(d)
			}
			proj := model.ProjectionFacts{EffectiveStartedAt: started, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}
			if c.lifecycle == model.LifecycleClosedUnknown {
				proj.RecoveryObservedAt = c.ownRecoveryAt
				proj.TerminalAt = &now
				proj.TerminalReason = &terminalReason
			}
			tr := sdTransition(9, c.lifecycle, contract, model.ReasonClosedUnknown,
				model.JournalClosedUnknown, model.JournalData{Headline: "x", OccurredAt: now}, proj, now)
			if c.lifecycle == model.LifecycleActive {
				tr.Reason = model.ReasonInvestigationStarted
				tr.JournalKind = model.JournalInvestigationStarted
			}
			summary := sdSummary(9, contract, started, now)
			if c.lifecycle == model.LifecycleClosedUnknown {
				summary.TerminalAt = &now
				summary.FinalOutcome = "Closed with uncertainty (observation_deadline)"
			}

			var ledger []model.Transition
			if c.ledgerHasRecover {
				recoveredAt := started.Add(30 * time.Minute)
				ledger = append(ledger, sdTransition(2, model.LifecycleRecoveryPending, contract,
					model.ReasonRecoveryObserved, model.JournalRecoveryPending,
					model.JournalData{Headline: "Recovery observed", OccurredAt: recoveredAt},
					model.ProjectionFacts{EffectiveStartedAt: started, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload,
						RecoveryObservedAt: &recoveredAt}, recoveredAt))
			}

			fs := &fakeDelivererStore{
				episode: store.SituationEpisodeView{Summary: summary, SourceTransition: tr},
				ledger:  ledger,
			}
			api := &fakeSlackAPI{}
			deliverer := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })

			intent := sdRootSyncIntent(tr.ID, 9, deadlinePtr, now)
			if _, err := deliverer.Deliver(context.Background(), intent); err != nil {
				t.Fatalf("Deliver() error = %v", err)
			}
			scanned := fs.listCalls > 0
			if scanned != c.wantScan {
				t.Fatalf("ledger scanned = %v, want %v (listCalls=%d)", scanned, c.wantScan, fs.listCalls)
			}
		})
	}
}

// ----------------------------------------------------------------------
// Deliver never writes Store state — a compile-time property of
// DelivererStore's own shape (read-only methods only), asserted here by
// confirming the fake's read methods are the only ones Deliver ever calls
// across every effect class exercised above (no method on
// fakeDelivererStore records a "write"; if Deliver ever needed one, this
// interface satisfaction would not compile).
func TestSituationDelivererNeverWritesStoreState(t *testing.T) {
	var _ DelivererStore = (*fakeDelivererStore)(nil)
}

// ----------------------------------------------------------------------
// Deliver validates the intent up front.
// ----------------------------------------------------------------------

func TestSituationDelivererDeliverRejectsInvalidIntent(t *testing.T) {
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(&fakeDelivererStore{}, api, "C-default", nil)
	if _, err := d.Deliver(context.Background(), model.NotificationIntent{}); err == nil {
		t.Fatal("Deliver() error = nil, want an error for an invalid intent")
	}
	if len(api.posts) != 0 || len(api.updates) != 0 {
		t.Fatal("an invalid intent must never reach Slack")
	}
}

// ----------------------------------------------------------------------
// notificationRuntime: startup recovery, worker lifecycle, shutdown (Task 9)
// ----------------------------------------------------------------------

// nrTracer records the exact order the startup pass drives its steps in.
type nrTracer struct {
	mu    sync.Mutex
	trace []string
}

func (n *nrTracer) add(s string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.trace = append(n.trace, s)
}

func (n *nrTracer) snapshot() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, len(n.trace))
	copy(out, n.trace)
	return out
}

type nrFakeStore struct {
	tr      *nrTracer
	state   situation.SlackDeliveryState
	gapID   string
	gapDone bool
}

func (f *nrFakeStore) RecoverExpiredNotificationClaims(context.Context, time.Time) (int, error) {
	f.tr.add("recover_notification_claims")
	return 2, nil
}

func (f *nrFakeStore) RecoverExpiredTransitionStreamClaims(context.Context, time.Time) (int, error) {
	f.tr.add("recover_transition_stream_claims")
	return 1, nil
}

func (f *nrFakeStore) ScheduleSituationsMissingFirstTransition(context.Context, time.Time) (int, error) {
	f.tr.add("schedule_situations_missing_first_transition")
	return 3, nil
}

func (f *nrFakeStore) ScheduleSituationsWithStaleRootProjection(context.Context, time.Time) (int, error) {
	f.tr.add("schedule_stale_root_projections")
	return 1, nil
}

func (f *nrFakeStore) GetSlackDeliveryState(context.Context) (situation.SlackDeliveryState, error) {
	f.tr.add("read_slack_delivery_state")
	return f.state, nil
}

func (f *nrFakeStore) RecoverDeliveryGap(context.Context, time.Time) (string, bool, error) {
	f.tr.add("resume_gap_replay")
	return f.gapID, f.gapDone, nil
}

type nrFakeProbe struct {
	tr  *nrTracer
	err error
}

func (p *nrFakeProbe) Probe(context.Context) error {
	p.tr.add("validate_slack_configuration")
	return p.err
}

type nrFakeWorker struct {
	tr            *nrTracer
	reactivated   int
	stopBlocks    bool
	started       bool
	stopCallCount int
}

func (w *nrFakeWorker) Start(context.Context) {
	w.tr.add("start_notification_worker")
	w.started = true
}

func (w *nrFakeWorker) Stop(ctx context.Context) error {
	w.tr.add("stop_notification_worker")
	w.stopCallCount++
	if w.stopBlocks {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (w *nrFakeWorker) ReactivateConfiguration(context.Context) (int, error) {
	w.tr.add("reactivate_configuration_blocked")
	w.reactivated++
	return 2, nil
}

type nrFakeStream struct{ tr *nrTracer }

func (s *nrFakeStream) Start(context.Context) { s.tr.add("start_transition_stream_worker") }
func (s *nrFakeStream) Stop(context.Context) error {
	s.tr.add("stop_transition_stream_worker")
	return nil
}

// nrRuntime takes its probe/worker as INTERFACES so a test can pass a true
// nil (Slack disabled) rather than a typed-nil pointer that would read as a
// present dependency.
func nrRuntime(tr *nrTracer, st *nrFakeStore, probe slackConfigurationProbe, worker situationNotificationWorker) *notificationRuntime {
	return &notificationRuntime{
		store:  st,
		probe:  probe,
		worker: worker,
		stream: &nrFakeStream{tr: tr},
		logger: slog.New(slog.DiscardHandler),
	}
}

// TestSituationNotificationRuntimeStartupFollowsTheSpecOrder pins spec.md's
// own startup steps 2-6, in order, between Plan 1/2 reconstruction and the
// workers starting: recover abandoned notification and stream claims;
// schedule every nonterminal Situation missing its first Transition;
// validate the Slack configuration and read back its durable generation;
// reactivate configuration-blocked intents; then schedule stale root
// projections and resume any interrupted gap replay.
func TestSituationNotificationRuntimeStartupFollowsTheSpecOrder(t *testing.T) {
	tr := &nrTracer{}
	generation := int64(7)
	st := &nrFakeStore{tr: tr, state: situation.SlackDeliveryState{
		ConfigurationGeneration: generation, BlockedConfigurationCount: 2,
	}, gapID: "gap-1", gapDone: true}
	worker := &nrFakeWorker{tr: tr}
	rt := nrRuntime(tr, st, &nrFakeProbe{tr: tr}, worker)

	report, err := rt.RecoverAndReactivate(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("RecoverAndReactivate: %v", err)
	}
	want := []string{
		"recover_notification_claims",
		"recover_transition_stream_claims",
		"schedule_situations_missing_first_transition",
		"validate_slack_configuration",
		"read_slack_delivery_state",
		"reactivate_configuration_blocked",
		"schedule_stale_root_projections",
		"resume_gap_replay",
	}
	got := tr.snapshot()
	if len(got) != len(want) {
		t.Fatalf("startup trace = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("startup trace = %v, want %v", got, want)
		}
	}
	if report.ConfigurationGeneration != generation {
		t.Errorf("configuration generation = %d, want %d", report.ConfigurationGeneration, generation)
	}
	if report.Reactivated != 2 || report.NotificationClaimsRecovered != 2 || report.StreamClaimsRecovered != 1 {
		t.Errorf("report = %+v, want the fakes' own counts", report)
	}
	if !report.GapReplayResumed {
		t.Error("an interrupted gap replay was not reported as resumed")
	}
	if worker.reactivated != 1 {
		t.Errorf("ReactivateConfiguration called %d times, want exactly 1", worker.reactivated)
	}
}

// TestSituationNotificationRuntimeStartupKeepsBlockedIntentsWhenSlackFails
// proves a Slack configuration that does not validate at boot is an ordinary
// delay, never a startup failure and never a reactivation: blocked intents
// stay durably blocked, no gap is recovered, and the process still starts.
func TestSituationNotificationRuntimeStartupKeepsBlockedIntentsWhenSlackFails(t *testing.T) {
	tr := &nrTracer{}
	st := &nrFakeStore{tr: tr, state: situation.SlackDeliveryState{BlockedConfigurationCount: 4}}
	worker := &nrFakeWorker{tr: tr}
	rt := nrRuntime(tr, st, &nrFakeProbe{tr: tr, err: errors.New("invalid_auth")}, worker)

	report, err := rt.RecoverAndReactivate(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("RecoverAndReactivate must not fail on an unreachable Slack: %v", err)
	}
	if report.SlackConfigurationValid {
		t.Error("report claims a valid Slack configuration after a failed probe")
	}
	if report.BlockedConfigurationRetained != 4 {
		t.Errorf("retained blocked intents = %d, want 4", report.BlockedConfigurationRetained)
	}
	if worker.reactivated != 0 {
		t.Error("configuration-blocked intents were reactivated on a failed probe")
	}
	for _, phase := range tr.snapshot() {
		if phase == "resume_gap_replay" {
			t.Error("a gap was recovered while Slack was still unreachable")
		}
	}
	// Finding #4: the stale-root sweep is publication-free and touches only
	// durable root-supersession state, so it must NOT be gated on the probe.
	// It is startup-only with no steady-state equivalent, so skipping it on a
	// transient boot-time Slack blip would mean it never runs again for this
	// whole process lifetime.
	sawStaleRootSweep := false
	for _, phase := range tr.snapshot() {
		if phase == "schedule_stale_root_projections" {
			sawStaleRootSweep = true
		}
	}
	if !sawStaleRootSweep {
		t.Error("the stale-root sweep was skipped because the Slack probe failed; it needs no Slack at all")
	}
	if report.ScheduledStaleRoot != 1 {
		t.Errorf("stale roots scheduled = %d, want 1 even with Slack unreachable", report.ScheduledStaleRoot)
	}
}

// TestSituationNotificationRuntimeStartupWithoutSlackRetainsDurableWork
// proves the Slack-disabled assembly: no worker and no probe exist at all,
// the claim-recovery and scheduling steps still run, and every durable
// blocked intent is retained rather than failed.
func TestSituationNotificationRuntimeStartupWithoutSlackRetainsDurableWork(t *testing.T) {
	tr := &nrTracer{}
	st := &nrFakeStore{tr: tr, state: situation.SlackDeliveryState{BlockedConfigurationCount: 3}}
	rt := nrRuntime(tr, st, nil, nil)

	report, err := rt.RecoverAndReactivate(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("RecoverAndReactivate: %v", err)
	}
	if report.SlackConfigurationValid {
		t.Error("report claims a valid Slack configuration with Slack disabled")
	}
	if report.BlockedConfigurationRetained != 3 {
		t.Errorf("retained blocked intents = %d, want 3", report.BlockedConfigurationRetained)
	}
	want := []string{
		"recover_notification_claims",
		"recover_transition_stream_claims",
		"schedule_situations_missing_first_transition",
		"read_slack_delivery_state",
		// Publication-free and Slack-independent: it runs even with Slack
		// switched off entirely (finding #4).
		"schedule_stale_root_projections",
	}
	got := tr.snapshot()
	if len(got) != len(want) {
		t.Fatalf("startup trace = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("startup trace = %v, want %v", got, want)
		}
	}
}

// TestSituationNotificationRuntimeStartsAndStopsInMirroredOrder pins the
// lifecycle order: the notification worker starts first and stops last, with
// the stdout stream worker inside it.
func TestSituationNotificationRuntimeStartsAndStopsInMirroredOrder(t *testing.T) {
	tr := &nrTracer{}
	st := &nrFakeStore{tr: tr}
	rt := nrRuntime(tr, st, &nrFakeProbe{tr: tr}, &nrFakeWorker{tr: tr})

	rt.Start(context.Background())
	if err := rt.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	want := []string{
		"start_notification_worker", "start_transition_stream_worker",
		"stop_transition_stream_worker", "stop_notification_worker",
	}
	got := tr.snapshot()
	if len(got) != len(want) {
		t.Fatalf("lifecycle trace = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lifecycle trace = %v, want %v", got, want)
		}
	}
}

// TestSituationNotificationRuntimeStopEndsWithinTheShutdownContext is R6's
// operational guarantee: a final delivery pass wedged on an unreachable
// Slack ends when the shutdown context does. The runtime reports the
// deadline rather than hanging, and its committed intents stay pending for
// the next startup to reclaim — they are never failed.
func TestSituationNotificationRuntimeStopEndsWithinTheShutdownContext(t *testing.T) {
	tr := &nrTracer{}
	st := &nrFakeStore{tr: tr}
	worker := &nrFakeWorker{tr: tr, stopBlocks: true}
	rt := nrRuntime(tr, st, &nrFakeProbe{tr: tr}, worker)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rt.Stop(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Stop err = %v, want the shutdown context's deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop never returned: a Slack outage held shutdown open")
	}
	if worker.stopCallCount != 1 {
		t.Fatalf("notification worker stopped %d times, want exactly one bounded final pass", worker.stopCallCount)
	}
}

// TestSituationNotificationRuntimeRestartAlonePublishesNothing is the
// spec's "startup never publishes merely because the binary restarted"
// invariant, against a real store: two full startup passes over a Situation
// that has no history yet create no Transition, no Episode summary, and no
// notification intent — they only make it due, so the ordinary controller
// path decides, under the ordinary materiality rules, what (if anything) to
// commit.
func TestSituationNotificationRuntimeRestartAlonePublishesNothing(t *testing.T) {
	st := newTestFoundationStore(t)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	sitID := seedControllerRuntimeSituation(t, st, "group-restart", now)

	rt := newNotificationRuntime(st, nil, nil, nil, slog.New(slog.DiscardHandler))
	for pass := range 2 {
		if _, err := rt.RecoverAndReactivate(context.Background(), now); err != nil {
			t.Fatalf("RecoverAndReactivate pass %d: %v", pass+1, err)
		}
		for _, q := range []struct {
			table string
			query string
		}{
			{"situation_transitions", `SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`},
			{"situation_episode_summaries", `SELECT COUNT(*) FROM situation_episode_summaries WHERE situation_id = ?`},
			{"notification_intents", `SELECT COUNT(*) FROM notification_intents WHERE situation_id = ?`},
			{"situation_transition_stream", `SELECT COUNT(*) FROM situation_transition_stream WHERE situation_id = ?`},
		} {
			var n int
			if err := st.DB().QueryRowContext(context.Background(), q.query, sitID).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", q.table, err)
			}
			if n != 0 {
				t.Fatalf("pass %d created %d %s rows; a restart alone must publish nothing", pass+1, n, q.table)
			}
		}
	}
}

// TestSituationDelivererAnnotationDoesNotInvalidateUnchangedHandoff pins
// review round 1, R1-F5: a broadcast_handoff is revalidated against the
// durable ACTION basis, never against equality with the latest Transition
// sequence. An attributed annotation necessarily advances the sequence
// while changing neither Attention, lifecycle, nor the required operator
// action — it must not demote a still-current handoff.
func TestSituationDelivererAnnotationDoesNotInvalidateUnchangedHandoff(t *testing.T) {
	occurred := sdMustTime(t, "2026-09-05T09:15:00Z")
	now := sdMustTime(t, "2026-09-05T10:00:00Z")
	action := model.OperatorActionInvestigateSituation
	contract := model.ActionContract{
		NextActor: model.NextActorOperator, OperatorActionRequired: &action,
		NextUpdateAt: sdTimePtr(now.Add(time.Hour)), NextUpdateOn: []model.NextUpdateOn{model.NextUpdateOnMaterialInput},
	}
	handoff := sdTransition(6, model.LifecycleActive, contract, model.ReasonOperatorContractChanged, model.JournalOperatorContractChanged,
		model.JournalData{Headline: "Operator action required: investigate_situation", OccurredAt: occurred},
		model.ProjectionFacts{EffectiveStartedAt: occurred, EffectiveStartedAtBasis: model.SourceTimeBasisSourcePayload}, occurred)
	note := handoff
	note.ID = "annotation-transition"
	note.Sequence = 7
	note.Reason = model.ReasonOperatorArtifactRecorded
	note.JournalKind = model.JournalOperatorNote
	note.Actor = model.ActorAttributedOperator
	artifact := "annotation-input"
	note.OperatorArtifactInputID = &artifact
	note.Journal = model.JournalData{Headline: "Added context", AttributedActor: "operator", OccurredAt: now}

	fs := &fakeDelivererStore{
		episode:     store.SituationEpisodeView{Summary: sdSummary(7, contract, occurred, now), SourceTransition: note},
		transitions: map[string]model.Transition{handoff.ID: handoff},
		rootOK:      true, rootChannel: "C-existing", rootTS: "50.5",
	}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C-default", func() time.Time { return now })
	got, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectBroadcastHandoff, handoff.ID, handoff.Sequence, now))
	if err != nil {
		t.Fatal(err)
	}
	if got.DeliveredAs != "broadcast" {
		t.Fatalf("annotation with identical Attention/lifecycle/operator action suppressed a still-current handoff: delivered_as=%s", got.DeliveredAs)
	}
}
