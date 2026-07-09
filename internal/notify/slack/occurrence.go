// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// occEditThrottle is the minimum spacing between in-place card edits for one
// incident (R10): a burst of attaches produces at most one edit per window plus
// a single trailing flush carrying the final count.
const occEditThrottle = 60 * time.Second

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

// OnOccurrenceAttached edits the incident's existing Slack card in place to show
// "recurred ×N · last HH:MM" — deterministic, zero LLM tokens. It is a no-op
// when no thread was recorded (the firing card was gate-suppressed or never
// posted), so belowMinSeverity is never re-consulted here and R9 stays
// self-enforcing. Edits are throttled to one per incident per occEditThrottle,
// coalesced, with a trailing flush that lands the final count.
func (n *Notifier) OnOccurrenceAttached(ctx context.Context, inc store.Incident, stats store.OccurrenceStats, drill bool) error {
	if n.store == nil {
		return nil
	}
	ts, ch, err := n.store.GetIncidentSlackThread(ctx, inc.ID)
	if err != nil {
		// ErrNotFound is the normal "no card" case (gate-suppressed or never
		// posted) — a silent no-op. A different error (e.g. a transient DB
		// failure) is logged, but the attach still self-corrects on the next one.
		if !errors.Is(err, store.ErrNotFound) {
			slog.Default().Warn("slack: occurrence thread lookup failed; skipping card edit", "incident_id", inc.ID, "err", err)
		}
		return nil
	}

	occurrences := stats.Episodes()
	edit := pendingEdit{
		ts:       ts,
		channel:  ch,
		fallback: occurrenceFallback(occurrences, stats.LastSeen),
		blocks:   occurrenceEditBlocks(inc, occurrences, stats.LastSeen, drill),
	}

	n.occMu.Lock()
	st := n.occ[inc.ID]
	if st == nil {
		st = &occThrottle{}
		n.occ[inc.ID] = st
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
		id := inc.ID
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
// finding and appends a recurrence context line. The main card needs no
// severity, so it rebuilds cleanly from the incident's denormalized fields plus
// the drill flag.
func occurrenceEditBlocks(inc store.Incident, occurrences int, lastSeen time.Time, drill bool) []slacklib.Block {
	f := findingFromIncident(inc, drill)
	blocks := firingMainBlocks(f)
	blocks = append(blocks, slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			fmt.Sprintf(":repeat: *recurred ×%d* · last %s UTC", occurrences, lastSeen.UTC().Format("15:04")),
			false, false),
	))
	return blocks
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
