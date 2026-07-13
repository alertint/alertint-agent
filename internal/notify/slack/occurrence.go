// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// occEditThrottle is the minimum spacing between in-place card edits for one
// incident (R10): a burst of attaches produces at most one edit per window plus
// a single trailing flush carrying the final count.
const occEditThrottle = 60 * time.Second

// recurrenceMode selects how recurrence re-fires resurface (ADR-0020).
// change-gated posts thread replies for real-world-change rungs + milestones
// (thread-only — never sent to the channel); off is the count-bump-only escape
// (no replies). Enum so a future digest/every mode is a non-breaking addition.
type recurrenceMode string

const (
	recurrenceChangeGated recurrenceMode = "change-gated"
	recurrenceOff         recurrenceMode = "off"
)

// stopper is the minimal timer seam (satisfied by *time.Timer) so the trailing
// flush is testable without real waits.
type stopper interface{ Stop() bool }

// occThrottle is the per-incident edit state: when the last edit landed, the
// coalesced pending edit (nil = nothing pending), and the armed trailing timer.
type occThrottle struct {
	last    time.Time
	pending *pendingEdit
	timer   stopper
}

type pendingEdit struct {
	ts       string
	channel  string
	fallback string
	blocks   []slacklib.Block
}

// OnOccurrenceAttached surfaces one recurrence-collapse attach. Single-writer
// rule (ADR-0019): a plain attach (trigger "none") edits the card in place
// (throttled) and may post a milestone thread reply; a re-judging attach
// (severity/new_alertname/cadence/cap/ceiling) leaves the card to the
// re-judgment's Notify, posts the "why" for a real-world change as a thread
// reply, and cancels any pending count-edit so a stale coalesced render can't
// overwrite the fresh finding. All recurrence replies stay in the thread —
// nothing is sent to the channel. A gate-suppressed incident (no thread) is a
// silent no-op. Zero LLM tokens.
func (n *Notifier) OnOccurrenceAttached(ctx context.Context, ev notify.RecurrenceEvent) error {
	if n.store == nil {
		return nil
	}
	ts, ch, err := n.store.GetIncidentSlackThread(ctx, ev.Incident.ID)
	if err != nil {
		// ErrNotFound is the normal "no card" case (gate-suppressed or never
		// posted) — a silent no-op. A different error (e.g. a transient DB
		// failure) is logged, but the attach still self-corrects on the next one.
		if !errors.Is(err, store.ErrNotFound) {
			slog.Default().Warn("slack: occurrence thread lookup failed; skipping recurrence surface", "incident_id", ev.Incident.ID, "err", err)
		}
		return nil
	}

	if isRejudgeTrigger(ev.Trigger) {
		// The re-judgment's Notify writes the card; the occurrence path must not,
		// in any mode. Cancel a pending trailing count-edit so it can't land after
		// the fresh finding edit.
		n.cancelPendingOcc(ev.Incident.ID)
		if n.recurrenceMode == recurrenceOff {
			return nil
		}
		return n.postRungReply(ctx, ev, ts, ch)
	}

	// Plain attach: edit the card in place (throttled), then post a thread reply
	// iff the episode count crossed a milestone. The card edit runs in every mode.
	occurrences := ev.Stats.Episodes()
	if err := n.editOccurrenceCard(ctx, ev, ts, ch); err != nil {
		return err
	}
	if n.recurrenceMode != recurrenceOff && milestoneHit(occurrences) {
		return n.postMilestoneReply(ctx, ev, ts, ch, occurrences)
	}
	return nil
}

// isRejudgeTrigger reports whether a trigger runs a re-judgment (every non-"none"
// trigger does), which owns the card write for that attach.
func isRejudgeTrigger(trigger string) bool {
	switch trigger {
	case "severity", "new_alertname", "cadence", "cap", "ceiling":
		return true
	}
	return false
}

// milestoneHit reports whether an episode count crosses a recurrence milestone:
// x5, x10, x25, x50, x100, then every x100. Sparse, roughly logarithmic — a
// flapper resurfaces a bounded handful of times (ADR-0020).
func milestoneHit(episodes int) bool {
	switch episodes {
	case 5, 10, 25, 50:
		return true
	}
	return episodes >= 100 && episodes%100 == 0
}

// cancelPendingOcc drops any armed trailing count-edit for an incident so a
// coalesced stale render can't land after a re-judgment's fresh finding edit
// (single-writer hygiene, ADR-0019). A flush already in flight is an accepted,
// self-correcting residual.
func (n *Notifier) cancelPendingOcc(incidentID string) {
	n.occMu.Lock()
	defer n.occMu.Unlock()
	st := n.occ[incidentID]
	if st == nil {
		return
	}
	st.pending = nil
	if st.timer != nil {
		st.timer.Stop()
		st.timer = nil
	}
}

// postThreadReply posts a recurrence update as a plain thread reply. It stays
// inside the incident's thread — deliberately never sent to the channel
// (no reply_broadcast), so recurrence can't spam the channel.
func (n *Notifier) postThreadReply(ctx context.Context, channel, ts, fallback string, blocks []slacklib.Block) error {
	if channel == "" {
		channel = n.channel
	}
	if _, _, err := n.client.PostMessageContext(ctx, channel,
		slacklib.MsgOptionText(fallback, false),
		slacklib.MsgOptionTS(ts),
		slacklib.MsgOptionBlocks(blocks...),
	); err != nil {
		return fmt.Errorf("channel %s: recurrence thread reply: %w", channel, err)
	}
	return nil
}

// postRungReply emits the self-explaining "why" for a real-world-change re-fire.
func (n *Notifier) postRungReply(ctx context.Context, ev notify.RecurrenceEvent, ts, ch string) error {
	headline, rung := rungHeadline(ev)
	if headline == "" {
		return nil // unknown trigger: nothing to say (defensive)
	}
	occ := ev.Stats.Episodes()
	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType, drillMarker(ev.Drill)+headline, false, false),
			nil, nil),
		recurrenceFooter(ev, occ, rung),
	}
	fallback := fmt.Sprintf("%srecurred ×%d (why: %s)", drillPlainMarker(ev.Drill), occ, rung)
	return n.postThreadReply(ctx, ch, ts, fallback, blocks)
}

// postMilestoneReply emits the "still recurring" nudge on a plain re-fire that
// crossed the milestone schedule.
func (n *Notifier) postMilestoneReply(ctx context.Context, ev notify.RecurrenceEvent, ts, ch string, occurrences int) error {
	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType, drillMarker(ev.Drill)+milestoneHeadline(ev, occurrences), false, false),
			nil, nil),
		recurrenceFooter(ev, occurrences, "milestone"),
	}
	fallback := fmt.Sprintf("%sstill recurring ×%d (why: milestone)", drillPlainMarker(ev.Drill), occurrences)
	return n.postThreadReply(ctx, ch, ts, fallback, blocks)
}

// rungHeadline renders the self-explaining "why" headline for a real-world-change
// reply and the rung token used in the footer. Pure function of the event's
// trigger + delta facts — zero LLM, no store reads.
func rungHeadline(ev notify.RecurrenceEvent) (headline, rung string) {
	switch ev.Trigger {
	case "severity":
		// PriorSeverity is "" when every current member's severity is off the
		// ladder (empty or unrecognized) — memberBaselines only records a label
		// when a member's rank strictly exceeds the running max. Drop the "(was
		// ...)" clause rather than render a blank prior value.
		if ev.PriorSeverity == "" {
			return fmt.Sprintf(":arrow_up: *Escalated* — severity now %s",
				strings.ToUpper(ev.NewSeverity)), "severity"
		}
		return fmt.Sprintf(":arrow_up: *Escalated* — severity now %s (was %s)",
			strings.ToUpper(ev.NewSeverity), strings.ToUpper(ev.PriorSeverity)), "severity"
	case "new_alertname":
		return fmt.Sprintf(":new: *New symptom* — %s joined", ev.NewAlertname), "new_alertname"
	case "cadence":
		return fmt.Sprintf(":zap: *Firing faster* — now ~%s apart (was ~%s)",
			formatDuration(ev.NewInterval), formatDuration(ev.PriorMedian)), "cadence"
	default:
		return "", ev.Trigger
	}
}

// milestoneHeadline renders the milestone nudge: count, span, and (when derivable)
// the average cadence — all computed facts from occurrence timestamps.
func milestoneHeadline(ev notify.RecurrenceEvent, occurrences int) string {
	head := fmt.Sprintf(":repeat: *Still recurring* — ×%d", occurrences)
	// Anchor the span on the incident's true start (FirstAlertAt), not the first
	// occurrence row (FirstOccurredAt) — a re-fire can arrive long after the
	// original firing, and FirstOccurredAt would understate how long the
	// incident has actually been open. Matches the resolved card's convention
	// (resolvedMainBlocks: duration anchored on f.FirstAlertAt).
	if span := ev.Stats.LastSeen.Sub(ev.Incident.FirstAlertAt); span > 0 {
		head += " over " + formatDuration(span)
	}
	if cad := averageCadence(ev.Stats); cad != "" {
		head += " · ~" + cad + " apart"
	}
	return head
}

// recurrenceFooter is the required "why" line on every recurrence reply: it
// literally names the rung that produced the re-fire surface.
func recurrenceFooter(ev notify.RecurrenceEvent, occurrences int, rung string) slacklib.Block {
	return slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			fmt.Sprintf("Incident `%s` · recurred ×%d · last %s UTC · why: %s",
				shortID(ev.Incident.ID), occurrences, ev.Stats.LastSeen.UTC().Format("15:04"), rung),
			false, false),
	)
}

// averageCadence returns a rounded human phrasing of the average inter-occurrence
// interval, or "" when there are too few occurrences. Mirrors the re-judgment
// prompt's cadence so the channel and the prompt agree.
func averageCadence(s store.OccurrenceStats) string {
	if s.Count < 2 || !s.LastSeen.After(s.FirstOccurredAt) {
		return ""
	}
	avg := s.LastSeen.Sub(s.FirstOccurredAt) / time.Duration(s.Count-1)
	return formatDuration(avg.Round(time.Minute))
}

// editOccurrenceCard performs the throttled, coalesced in-place card edit for a
// plain (non-rejudging) occurrence attach. Edits are throttled to one per
// incident per occEditThrottle, coalesced, with a trailing flush that lands the
// final count.
func (n *Notifier) editOccurrenceCard(ctx context.Context, ev notify.RecurrenceEvent, ts, ch string) error {
	occurrences := ev.Stats.Episodes()
	edit := pendingEdit{
		ts:       ts,
		channel:  ch,
		fallback: occurrenceFallback(occurrences, ev.Stats.LastSeen),
		blocks:   occurrenceEditBlocks(ev.Incident, occurrences, ev.Stats.LastSeen, ev.Drill),
	}

	n.occMu.Lock()
	st := n.occ[ev.Incident.ID]
	if st == nil {
		st = &occThrottle{}
		n.occ[ev.Incident.ID] = st
	}
	now := n.now()
	if now.Sub(st.last) >= occEditThrottle {
		// Outside the throttle window: edit immediately.
		st.last = now
		st.pending = nil
		n.occMu.Unlock()
		return n.editCard(ctx, edit)
	}
	// Inside the window: coalesce to the latest edit and arm a trailing flush.
	st.pending = &edit
	if st.timer == nil {
		wait := occEditThrottle - now.Sub(st.last)
		id := ev.Incident.ID
		// The trailing flush is detached from this request ctx (it fires up to
		// occEditThrottle later, after ctx is likely canceled), so it uses
		// context.Background() by design.
		st.timer = n.after(wait, func() { n.flushOccurrence(id) }) //nolint:contextcheck
	}
	n.occMu.Unlock()
	return nil
}

// flushOccurrence lands the coalesced trailing edit after the throttle window.
// It runs on the timer goroutine, so it re-takes the lock and reads the latest
// pending edit (a newer attach may have superseded it).
func (n *Notifier) flushOccurrence(incidentID string) {
	n.occMu.Lock()
	st := n.occ[incidentID]
	if st == nil {
		n.occMu.Unlock()
		return
	}
	st.timer = nil
	edit := st.pending
	st.pending = nil
	if edit == nil {
		delete(n.occ, incidentID) // nothing pending: the burst is over, reclaim
		n.occMu.Unlock()
		return
	}
	st.last = n.now()
	n.occMu.Unlock()

	err := n.editCard(context.Background(), *edit)

	// Reclaim the entry once the burst has drained (no new attach re-armed a
	// timer while we edited). This bounds the throttle map for high-frequency
	// bursts; a single-attach recurrence leaves one small entry until the next
	// burst for its incident (an accepted, bounded residual).
	n.occMu.Lock()
	if cur := n.occ[incidentID]; cur != nil && cur.pending == nil && cur.timer == nil {
		delete(n.occ, incidentID)
	}
	n.occMu.Unlock()

	if err != nil {
		slog.Default().Warn("slack: trailing occurrence edit failed", "incident_id", incidentID, "err", err)
	}
}

// editCard performs one in-place card update. Errors are returned (sync path) or
// logged (trailing flush); never retried in a loop — the next attach
// self-corrects.
func (n *Notifier) editCard(ctx context.Context, e pendingEdit) error {
	channel := e.channel
	if channel == "" {
		channel = n.channel
	}
	if _, _, _, err := n.client.UpdateMessageContext(ctx, channel, e.ts,
		slacklib.MsgOptionText(e.fallback, false),
		slacklib.MsgOptionBlocks(e.blocks...),
	); err != nil {
		return fmt.Errorf("channel %s: update occurrence card: %w", channel, err)
	}
	return nil
}

// occurrenceEditBlocks re-renders the incident's firing card from its persisted
// finding plus the live recurrence line, via the shared firingCardBlocks path.
func occurrenceEditBlocks(inc store.Incident, occurrences int, lastSeen time.Time, drill bool) []slacklib.Block {
	f := findingFromIncident(inc, drill)
	f.Recurrence = &notify.Recurrence{Episodes: occurrences, LastSeen: lastSeen}
	return firingCardBlocks(f)
}

func occurrenceFallback(occurrences int, lastSeen time.Time) string {
	return fmt.Sprintf("recurred ×%d · last %s UTC", occurrences, lastSeen.UTC().Format("15:04"))
}

// findingFromIncident reconstructs the notify.Finding fields the firing main
// card renders from a persisted incident row (the occurrence edit has no live
// Finding). Severity/correlation details are omitted — the main card does not
// use them.
func findingFromIncident(inc store.Incident, drill bool) notify.Finding {
	return notify.Finding{
		IncidentID:   inc.ID,
		GroupKey:     inc.GroupKey,
		AnalysisName: inc.Summary,
		OverallIssue: inc.RootCause,
		Confidence:   inc.Confidence,
		AlertCount:   inc.AlertCount,
		FirstAlertAt: inc.FirstAlertAt,
		Drill:        drill,
	}
}
