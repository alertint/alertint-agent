// SPDX-License-Identifier: FSL-1.1-ALv2

// Package slack implements a Notifier that uses the Slack Bot Token API to
// post structured Block Kit messages with a clear per-incident timeline:
//
//	Channel (main):  🔴 INCIDENT DETECTED — name + root cause (brief, scannable)
//	Thread:          Analysis details — severity, confidence, findings, MCP hint
//	Channel (main):  ✅ INCIDENT RESOLVED — updated in-place, adds duration
//	Thread:          Resolution details — duration, alert count, resolved time
package slack

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/severity"
	"github.com/alertint/alertint-agent/internal/store"
)

// ThreadStore persists Slack thread coordinates (ts + channel) keyed by incident ID.
type ThreadStore interface {
	GetIncidentSlackThread(ctx context.Context, incidentID string) (ts, channel string, err error)
	SetIncidentSlackThread(ctx context.Context, incidentID, ts, channel string) error
}

// SlackClient is the subset of slacklib.Client used by the notifier. Exposed
// so test packages can inject a mock via NewWithClient.
type SlackClient interface {
	PostMessageContext(ctx context.Context, channelID string, options ...slacklib.MsgOption) (string, string, error)
	UpdateMessageContext(ctx context.Context, channelID, timestamp string, options ...slacklib.MsgOption) (string, string, string, error)
}

// Notifier posts and updates Slack messages via the Bot Token API.
type Notifier struct {
	client         SlackClient
	channel        string
	store          ThreadStore
	auditor        *audit.Auditor
	minSeverity    string         // findings below this severity are not posted ("" = low = post everything)
	recurrenceMode recurrenceMode // change-gated (default) | off (ADR-0020)

	// Occurrence card-edit throttle (recurrence collapse, R10): at most one edit
	// per incident per occEditThrottle, coalesced, with a trailing flush. now and
	// after are seams so the throttle is deterministic in tests; occ holds
	// in-memory per-incident state (lost on restart — the next attach
	// self-corrects, an accepted gap).
	now   func() time.Time
	after func(d time.Duration, fn func()) stopper
	occMu sync.Mutex
	occ   map[string]*occThrottle

	// Root-card writes are serialized per incident so a trailing occurrence
	// edit that is already in flight must finish before a later resolved or
	// re-judged finding writes the authoritative card state.
	cardWritesMu sync.Mutex
	cardWrites   map[string]*cardWriteState
}

type cardWriteState struct {
	mu   sync.Mutex
	refs int
}

// Probe verifies the bot token against the Slack auth.test API. Used by
// the integration health check; a failure means the token is invalid,
// revoked, or Slack is unreachable.
func Probe(ctx context.Context, botToken string) error {
	_, err := slacklib.New(botToken).AuthTestContext(ctx)
	return err
}

// New constructs a Slack Notifier using a bot token (xoxb-...). minSeverity
// is the channel noise gate (low | medium | high; "" means low). recurrenceMode
// is "change-gated" | "off" ("" normalizes to change-gated).
func New(botToken, channel, minSeverity, recurrenceMode string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	return newNotifier(slacklib.New(botToken), channel, minSeverity, recurrenceMode, store, auditor)
}

// NewWithClient constructs a Notifier with a custom SlackClient, enabling
// injection of a mock in tests.
func NewWithClient(client SlackClient, channel, minSeverity, recurrenceMode string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	return newNotifier(client, channel, minSeverity, recurrenceMode, store, auditor)
}

func newNotifier(client SlackClient, channel, minSeverity, recurrenceMode string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	mode := recurrenceChangeGated
	if recurrenceMode == string(recurrenceOff) {
		mode = recurrenceOff
	}
	return &Notifier{
		client:         client,
		channel:        channel,
		minSeverity:    minSeverity,
		recurrenceMode: mode,
		store:          store,
		auditor:        auditor,
		now:            time.Now,
		after:          func(d time.Duration, fn func()) stopper { return time.AfterFunc(d, fn) },
		occ:            make(map[string]*occThrottle),
		cardWrites:     make(map[string]*cardWriteState),
	}
}

// Name returns the stable sink label used in the notify outcome line. The
// channel rides the wrapped error on failure (and the startup "slack connected"
// line), never the label, so the label stays constant across findings.
func (n *Notifier) Name() string { return "slack" }

// Notify dispatches to notifyFiring or notifyResolved based on f.Status.
func (n *Notifier) Notify(ctx context.Context, f notify.Finding) error {
	unlock := n.lockCardWrite(f.IncidentID)
	defer unlock()
	if f.Status == "resolved" {
		n.cancelPendingOcc(f.IncidentID)
		return n.notifyResolved(ctx, f)
	}
	return n.notifyFiring(ctx, f)
}

// lockCardWrite takes a reference-counted per-incident lock and returns its
// unlock function. Entries disappear when the final holder/waiter leaves, so
// long-lived agents do not retain one mutex for every incident ever observed.
func (n *Notifier) lockCardWrite(incidentID string) func() {
	n.cardWritesMu.Lock()
	state := n.cardWrites[incidentID]
	if state == nil {
		state = &cardWriteState{}
		n.cardWrites[incidentID] = state
	}
	state.refs++
	n.cardWritesMu.Unlock()

	state.mu.Lock()
	return func() {
		state.mu.Unlock()
		n.cardWritesMu.Lock()
		state.refs--
		if state.refs == 0 {
			delete(n.cardWrites, incidentID)
		}
		n.cardWritesMu.Unlock()
	}
}

func (n *Notifier) notifyFiring(ctx context.Context, f notify.Finding) error {
	// A recorded thread means the incident already has a card: this Notify is a
	// re-judgment update, not a first firing. Edit the existing card in place
	// (new finding + recurrence line) and thread the fresh analysis — never post
	// a new card, never overwrite slack_ts (ADR-0019). An update to an
	// already-visible incident is not re-gated by min_severity (mirrors resolve).
	// A non-ErrNotFound lookup error is NOT treated as "no card yet": doing so
	// would post a duplicate card and clobber slack_ts for an incident that
	// already has one, so the error is surfaced instead (mirrors
	// OnOccurrenceAttached's errors.Is(err, store.ErrNotFound) check).
	if n.store != nil {
		ts, ch, err := n.store.GetIncidentSlackThread(ctx, f.IncidentID)
		switch {
		case err == nil:
			return n.updateFiringInPlace(ctx, f, ts, ch)
		case !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("channel %s: firing thread lookup: %w", n.channel, err)
		}
	}
	// No thread recorded: first firing (or a previously gate-suppressed incident
	// now worth showing). Apply the severity gate, then post a new card.
	if n.belowMinSeverity(f) {
		n.auditSkipped(ctx, f)
		return nil
	}
	ch, ts, err := n.client.PostMessageContext(ctx, n.channel,
		slacklib.MsgOptionText(firingFallback(f), false),
		slacklib.MsgOptionBlocks(firingCardBlocks(f)...),
	)
	if err != nil {
		return fmt.Errorf("channel %s: post message: %w", n.channel, err)
	}
	if n.store != nil && ts != "" {
		_ = n.store.SetIncidentSlackThread(ctx, f.IncidentID, ts, ch)
	}
	if ts != "" {
		_, _, _ = n.client.PostMessageContext(ctx, ch,
			slacklib.MsgOptionText(firingFallback(f), false),
			slacklib.MsgOptionTS(ts),
			slacklib.MsgOptionBlocks(firingDetailBlocks(f)...),
		)
	}
	n.audit(ctx, f.IncidentID, "firing")
	return nil
}

// updateFiringInPlace edits the incident's existing card with the re-judgment's
// fresh finding + recurrence line and threads the new analysis as a plain reply
// (the "why" thread reply, if any, already fired from OnOccurrenceAttached). It
// preserves slack_ts — the card is the incident's durable anchor.
func (n *Notifier) updateFiringInPlace(ctx context.Context, f notify.Finding, originalTS, ch string) error {
	channel := ch
	if channel == "" {
		channel = n.channel
	}
	if _, _, _, err := n.client.UpdateMessageContext(ctx, channel, originalTS,
		slacklib.MsgOptionText(firingFallback(f), false),
		slacklib.MsgOptionBlocks(firingCardBlocks(f)...),
	); err != nil {
		return fmt.Errorf("channel %s: update firing card: %w", channel, err)
	}
	if _, _, err := n.client.PostMessageContext(ctx, channel,
		slacklib.MsgOptionText(firingFallback(f), false),
		slacklib.MsgOptionTS(originalTS),
		slacklib.MsgOptionBlocks(firingDetailBlocks(f)...),
	); err != nil {
		return fmt.Errorf("channel %s: post thread reply: %w", channel, err)
	}
	n.audit(ctx, f.IncidentID, "rejudge")
	return nil
}

func (n *Notifier) notifyResolved(ctx context.Context, f notify.Finding) error {
	if n.store != nil {
		if ts, ch, err := n.store.GetIncidentSlackThread(ctx, f.IncidentID); err == nil {
			return n.updateAndThread(ctx, f, ts, ch)
		}
	}
	// No prior thread recorded. When the firing post was suppressed by the
	// severity gate, suppress the resolution too — otherwise a fresh resolved
	// card would leak the gated incident into the channel after all.
	if n.belowMinSeverity(f) {
		n.auditSkipped(ctx, f)
		return nil
	}
	// Fallback: post a fresh resolved message.
	_, _, err := n.client.PostMessageContext(ctx, n.channel,
		slacklib.MsgOptionText(resolvedFallback(f), false),
		slacklib.MsgOptionBlocks(resolvedMainBlocks(f)...),
	)
	if err != nil {
		return fmt.Errorf("channel %s: post resolved message: %w", n.channel, err)
	}
	n.audit(ctx, f.IncidentID, "resolved")
	return nil
}

func (n *Notifier) updateAndThread(ctx context.Context, f notify.Finding, originalTS, ch string) error {
	channel := ch
	if channel == "" {
		channel = n.channel
	}

	// Update the original firing message in-place: header changes 🔴 → ✅,
	// root cause is preserved, duration appears.
	if _, _, _, err := n.client.UpdateMessageContext(ctx, channel, originalTS,
		slacklib.MsgOptionText(resolvedFallback(f), false),
		slacklib.MsgOptionBlocks(resolvedMainBlocks(f)...),
	); err != nil {
		return fmt.Errorf("channel %s: update message: %w", channel, err)
	}

	// Post full resolution details as a thread reply.
	if _, _, err := n.client.PostMessageContext(ctx, channel,
		slacklib.MsgOptionText(resolvedFallback(f), false),
		slacklib.MsgOptionTS(originalTS),
		slacklib.MsgOptionBlocks(resolvedThreadBlocks(f)...),
	); err != nil {
		return fmt.Errorf("channel %s: post thread reply: %w", channel, err)
	}

	n.audit(ctx, f.IncidentID, "resolved")
	return nil
}

// belowMinSeverity reports whether the finding's severity ranks below the
// configured gate. A finding whose severity isn't on the ladder (empty or
// unexpected model output) always posts: the gate exists to drop known-low
// noise, never to hide the unclassifiable.
func (n *Notifier) belowMinSeverity(f notify.Finding) bool {
	sev := severityRank(f.Severity)
	if sev == 0 {
		return false
	}
	return sev < severityRank(n.minSeverity)
}

// severityRank orders the severity ladder for the min_severity gate:
// low=1, medium=2, high=3; anything else (including empty) is 0. Callers
// interpret 0 per side: an off-ladder finding severity always posts, and an
// empty gate value means low (config validation rejects other gate values).
// Delegates to internal/severity.GateRank — the gate-only ladder — NOT to the
// full Rank (which the recurrence trigger uses): recognizing warning/info there
// would narrow the "unclassifiable always posts" rule and silently gate
// off-ladder findings.
func severityRank(s string) int {
	return severity.GateRank(s)
}

// auditSkipped records a severity-gate suppression in the audit trail.
func (n *Notifier) auditSkipped(ctx context.Context, f notify.Finding) {
	if n.auditor == nil {
		return
	}
	_ = n.auditor.Append(ctx, "notify.slack", "notify.skipped", map[string]any{
		"incident_id":  f.IncidentID,
		"severity":     f.Severity,
		"min_severity": n.minSeverity,
		"recipient":    "slack",
	})
}

func (n *Notifier) audit(ctx context.Context, incidentID, event string) {
	if n.auditor == nil {
		return
	}
	_ = n.auditor.Append(ctx, "notify.slack", "notify.sent", map[string]any{
		"incident_id": incidentID,
		"event":       event,
		"recipient":   "slack",
	})
}

// ----------------------------------------------------------------------
// Block Kit payload builders
// ----------------------------------------------------------------------

// drillMarker / drillPlainMarker return the DRILL banner fragment prepended to
// every rendered surface of a Drill finding or recurrence event (main card,
// thread detail, fallback, recurrence reply): a synthetic card must be
// unmistakably synthetic in a shared channel (ADR-0013). Empty when not a drill.
func drillMarker(drill bool) string {
	if drill {
		return ":test_tube: *DRILL* — "
	}
	return ""
}

func drillPlainMarker(drill bool) string {
	if drill {
		return "🧪 DRILL — "
	}
	return ""
}

func drillMd(f notify.Finding) string    { return drillMarker(f.Drill) }
func drillPlain(f notify.Finding) string { return drillPlainMarker(f.Drill) }

// drillFrameBlock is the one-line explainer under a Drill card's headline: a
// first-time viewer in a shared channel must not need the CLI output (or any
// product vocabulary) to know the incident is synthetic and harmless. The
// banner marks the card; this line decodes the banner. nil for real findings.
func drillFrameBlock(f notify.Finding) slacklib.Block {
	if !f.Drill {
		return nil
	}
	return slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			"🧪 [this is a drill — a synthetic incident fired by `alertint drill` to demo the pipeline; no real systems are affected]",
			false, false),
	)
}

// firingMainBlocks builds the brief main-channel message posted when an incident
// fires: headline + root cause only. Keeps the channel timeline scannable.
func firingMainBlocks(f notify.Finding) []slacklib.Block {
	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("%s:red_circle: *INCIDENT DETECTED* — %s", drillMd(f), f.AnalysisName), false, false),
			nil, nil,
		),
	}
	if b := drillFrameBlock(f); b != nil {
		blocks = append(blocks, b)
	}
	if f.OverallIssue != "" {
		blocks = append(blocks, slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("*Root cause:* %s", f.OverallIssue), false, false),
			nil, nil,
		))
	}
	// Severity and confidence ride the channel-visible meta line — they are
	// the two numbers an operator triages by, and the thread (where the full
	// fields grid lives) is invisible until clicked.
	meta := fmt.Sprintf("Incident `%s` · %d alerts", shortID(f.IncidentID), f.AlertCount)
	if f.Severity != "" {
		meta += fmt.Sprintf(" · %s · %.0f%%", strings.ToLower(f.Severity), f.Confidence*100)
	}
	meta += fmt.Sprintf(" · group `%s` · started %s UTC", f.GroupKey, f.FirstAlertAt.UTC().Format("15:04"))
	blocks = append(blocks, slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType, meta, false, false),
	))
	// The MCP handoff is the differentiator, so it rides the headline card as
	// a full-size section (a context block renders as small grey caption text
	// and gets lost). Full incident ID — the downstream alertint_get_incident
	// call must resolve unambiguously. The same block appears on the thread
	// detail so the CTA reads identically on every firing surface.
	// Resolved cards drop this block: the handoff is for active incidents.
	if f.IncidentID != "" {
		blocks = append(blocks, agentHandoffBlock(f.IncidentID))
	}
	return blocks
}

// firingCardBlocks is the single source of truth for the incident's main card
// body across first firing, occurrence count-edit, and re-judgment edit: the
// finding (firingMainBlocks) plus a recurrence context line when the finding
// carries live occurrence stats. Unifying the three renders keeps them from
// drifting.
func firingCardBlocks(f notify.Finding) []slacklib.Block {
	blocks := firingMainBlocks(f)
	if f.Recurrence != nil {
		blocks = append(blocks, recurrenceContextBlock(f.Recurrence.Episodes, f.Recurrence.LastSeen))
	}
	// The history line (🆕/👀/📌 + the operator's note text) renders on the
	// thread detail, next to the operator-notes block it introduces — context
	// for whoever opens the incident, not triage signal. The steering ruling
	// stays on the card: it is the outcome ("correction checked: does not
	// apply now") and must be visible in the channel feed.
	if b := steeringContextBlock(f.Steering); b != nil {
		blocks = append(blocks, b)
	}
	return blocks
}

// historyContextBlock renders the tri-state operator history (R9). Counts are
// windowed and the wording says so; 🆕 renders only on the true "first" state
// (clean-empty recall + unbounded incident-existence check, D8).
func historyContextBlock(h *notify.History) slacklib.Block {
	if h == nil {
		return nil
	}
	var text string
	switch h.State {
	case "first":
		text = "🆕 first occurrence — no prior incidents, verdicts, or notes for this failure group"
	case "seen":
		if h.Episodes > 1 && !h.FirstSeen.IsZero() {
			text = fmt.Sprintf("👀 seen ×%d in the last %dd (since %s) — no operator verdict yet",
				h.Episodes, h.WindowDays, h.FirstSeen.UTC().Format("2006-01-02"))
		} else {
			text = "👀 seen before — no operator verdict yet"
		}
	case "history":
		if h.Verdict == nil {
			if len(h.Notes) == 0 {
				return nil
			}
			text = fmt.Sprintf("📝 %d operator note(s) on this failure group — see analysis details", len(h.Notes)+h.NotesMore)
		} else {
			text = fmt.Sprintf("📌 operator %s (%s): %s", h.Verdict.Kind, h.Verdict.Age, slackCap(h.Verdict.Note, 200))
		}
	case "unavailable":
		text = "⚠️ operator history unavailable"
	default:
		return nil
	}
	return slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType, text, false, false))
}

// steeringContextBlock renders the ruling line on steered findings (R9). A
// dead check renders as exactly that — never as a fabricated "unverifiable".
func steeringContextBlock(s *notify.Steering) slacklib.Block {
	if s == nil {
		return nil
	}
	var text string
	switch s.Ruling {
	case "supported":
		text = "✅ operator correction checked: supported"
		if s.Basis != "" {
			text += " — " + s.Basis
		}
	case "contradicted":
		text = "❌ operator correction checked: does not apply now"
		if s.Basis != "" {
			text += " — " + s.Basis
		}
	case "unverifiable":
		text = fmt.Sprintf("⚠️ adopted per operator correction of %s, not verifiable from current evidence (confidence capped)", s.VerdictDate)
		if s.Basis != "" {
			text += " — " + s.Basis
		}
	case "untested":
		// an unbacked supported/contradicted, remapped by the producer: the
		// correction's named evidence never fetched, so no ruling took effect
		text = fmt.Sprintf("⚠️ operator correction of %s could not be tested — its named evidence returned no usable data this round (confidence capped)", s.VerdictDate)
	case "unruled":
		text = "⚠️ operator correction present — check did not complete"
	default:
		return nil
	}
	return slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType, text, false, false))
}

// recurrenceContextBlock is the "recurred ×N · last HH:MM" line appended to a
// recurring incident's card.
func recurrenceContextBlock(occurrences int, lastSeen time.Time) slacklib.Block {
	return slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			fmt.Sprintf(":repeat: *recurred ×%d* · last %s UTC", occurrences, lastSeen.UTC().Format("15:04")),
			false, false),
	)
}

// agentHandoffBlock is the MCP call to action, rendered the same wherever it
// appears: main firing card and thread detail. One line — a full-size section
// block (a context block renders as small grey caption text and gets lost)
// but without a separate header row, keeping the channel card compact.
func agentHandoffBlock(incidentID string) slacklib.Block {
	return slacklib.NewSectionBlock(
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			fmt.Sprintf(":robot_face: *Investigate in your AI agent:* `investigate incident %s using alertint`", incidentID),
			false, false),
		nil, nil,
	)
}

// evidenceLine renders the always-on evidence summary text (R6/R7/R8/R12). A
// short-circuit or zero-connector finding renders one card-level state; otherwise
// each source renders "<Source> <count> <unit>" (unit omitted for changes),
// "<Source> unreachable" when the connector could not be reached, or "<Source>
// slow" when it was reachable but too slow to answer within the deadline.
func evidenceLine(s notify.EvidenceSummary) string {
	switch {
	case s.Skipped:
		return "skipped (known issue)"
	case s.NoSources:
		return "no sources configured"
	}
	parts := make([]string, 0, len(s.Sources))
	for _, src := range s.Sources {
		if src.State == notify.EvidenceUnreachable {
			parts = append(parts, src.Source+" unreachable")
			continue
		}
		if src.State == notify.EvidenceDegraded {
			parts = append(parts, src.Source+" slow")
			continue
		}
		if src.Unit == "" {
			parts = append(parts, fmt.Sprintf("%s %d", src.Source, src.Count))
		} else {
			parts = append(parts, fmt.Sprintf("%s %d %s", src.Source, src.Count, src.Unit))
		}
	}
	return strings.Join(parts, " · ")
}

// firingDetailBlocks builds the immediate thread reply with the full analysis:
// severity, confidence, correlation findings, and MCP hint.
func firingDetailBlocks(f notify.Finding) []slacklib.Block {
	confidence := fmt.Sprintf("%.0f%%", f.Confidence*100)
	severity := strings.ToUpper(f.Severity)

	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType, drillMd(f)+"*Analysis details*", false, false),
			nil, nil,
		),
		slacklib.NewSectionBlock(nil, []*slacklib.TextBlockObject{
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Severity*\n%s", severity), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Confidence*\n%s", confidence), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Alerts*\n%d", f.AlertCount), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Group*\n`%s`", f.GroupKey), false, false),
		}, nil),
	}

	blocks = append(blocks, slacklib.NewSectionBlock(
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			"*Evidence:* "+evidenceLine(f.Evidence), false, false),
		nil, nil,
	))

	// Invalid-query caveat (Task 6): a locally-invalid or backend-rejected
	// verification query was never fetched and never used as evidence — a
	// distinct, classified caveat from Unverified/"checks unavailable" below,
	// which reflects connector/round-level degradation instead. Renders the
	// count only, never the query expression. Must precede the Unverified
	// block so the two independent caveats stay visually ordered.
	if n := f.VerificationInvalidQueries; n > 0 {
		noun := "query"
		if n != 1 {
			noun = "queries"
		}
		text := fmt.Sprintf("⚠ verification incomplete — %d metrics %s invalid; not used as evidence and confidence could not increase", n, noun)
		blocks = append(blocks, slacklib.NewContextBlock("",
			slacklib.NewTextBlockObject(slacklib.MarkdownType, text, false, false)))
	}

	if f.Unverified {
		// Drill wording: on a drill the missing checks are the expected state
		// (drill labels are fictional, no evidence source can verify them), and
		// the bare caveat reads as "the product is broken" to a first-timer.
		unverifiedText := notify.UnverifiedCaveat(f.DegradationReason, f.Drill)
		blocks = append(blocks, slacklib.NewContextBlock("",
			slacklib.NewTextBlockObject(slacklib.MarkdownType, unverifiedText, false, false),
		))
	}

	if len(f.CorrelationFindings) > 0 {
		var sb strings.Builder
		sb.WriteString("*Correlation findings*\n")
		for _, cf := range f.CorrelationFindings {
			sb.WriteString("• ")
			sb.WriteString(cf)
			sb.WriteString("\n")
		}
		blocks = append(blocks, slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType, strings.TrimRight(sb.String(), "\n"), false, false),
			nil, nil,
		))
	}

	// The tri-state history line (moved off the main card to keep the channel
	// feed scannable) heads the operator context: 🆕/👀 state or the 📌
	// governing-verdict note, then the bounded notes list.
	if b := historyContextBlock(f.History); b != nil {
		blocks = append(blocks, b)
	}

	if f.History != nil && len(f.History.Notes) > 0 {
		var nb strings.Builder
		nb.WriteString("*Operator notes*")
		shown := len(f.History.Notes)
		if shown > 3 {
			shown = 3
		}
		for _, n := range f.History.Notes[:shown] {
			fmt.Fprintf(&nb, "\n📝 %s (%s): %s", n.Kind, n.Age, slackCap(n.Note, 300))
		}
		if more := len(f.History.Notes) - shown + f.History.NotesMore; more > 0 {
			fmt.Fprintf(&nb, "\n+%d more", more)
		}
		blocks = append(blocks, slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType, nb.String(), false, false), nil, nil))
	}

	blocks = append(blocks,
		slacklib.NewDividerBlock(),
		agentHandoffBlock(f.IncidentID),
	)
	return blocks
}

// resolvedMainBlocks builds the updated main-channel message when an incident
// resolves: header changes 🔴 → ✅, root cause is preserved, duration appears.
func resolvedMainBlocks(f notify.Finding) []slacklib.Block {
	duration := formatDuration(f.AnalyzedAt.Sub(f.FirstAlertAt))
	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("%s:white_check_mark: *INCIDENT RESOLVED* — %s", drillMd(f), f.AnalysisName), false, false),
			nil, nil,
		),
	}
	if b := drillFrameBlock(f); b != nil {
		blocks = append(blocks, b)
	}
	if f.OverallIssue != "" {
		blocks = append(blocks, slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("*Root cause:* %s", f.OverallIssue), false, false),
			nil, nil,
		))
	}
	ctxText := fmt.Sprintf("Incident `%s` · resolved after %s · %s UTC",
		shortID(f.IncidentID), duration, f.AnalyzedAt.UTC().Format("15:04"))
	if f.Recurrence != nil && f.Recurrence.Episodes > 1 {
		ctxText = fmt.Sprintf("Incident `%s` · resolved after recurring ×%d over %s · %s UTC",
			shortID(f.IncidentID), f.Recurrence.Episodes, duration, f.AnalyzedAt.UTC().Format("15:04"))
	}
	blocks = append(blocks, slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType, ctxText, false, false),
	))
	return blocks
}

// resolvedThreadBlocks builds the thread reply posted when an incident resolves:
// full resolution details — duration, alert count, resolved time.
func resolvedThreadBlocks(f notify.Finding) []slacklib.Block {
	duration := formatDuration(f.AnalyzedAt.Sub(f.FirstAlertAt))
	return []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				drillMd(f)+":white_check_mark: *All clear — all alerts have recovered.*", false, false),
			nil, nil,
		),
		slacklib.NewSectionBlock(nil, []*slacklib.TextBlockObject{
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Duration*\n%s", duration), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Alerts*\n%d recovered", f.AlertCount), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("*Resolved*\n%s UTC", f.AnalyzedAt.UTC().Format("15:04")), false, false),
		}, nil),
		slacklib.NewDividerBlock(),
		slacklib.NewContextBlock("",
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("Incident `%s` · duration %s",
					shortID(f.IncidentID), duration),
				false, false),
		),
	}
}

func firingFallback(f notify.Finding) string {
	return fmt.Sprintf("%s🔴 INCIDENT DETECTED: %s (severity: %s)",
		drillPlain(f), f.AnalysisName, strings.ToUpper(f.Severity))
}

func resolvedFallback(f notify.Finding) string {
	return fmt.Sprintf("%s✅ INCIDENT RESOLVED: %s (duration: %s)",
		drillPlain(f), f.AnalysisName, formatDuration(f.AnalyzedAt.Sub(f.FirstAlertAt)))
}

// slackCap returns the first limit runes of s (so multi-byte characters are
// never split), bounding operator-authored free text before it rides a Slack
// block — an unbounded verdict/note string must not blow out a card. limit <= 0
// leaves s unchanged.
func slackCap(s string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m == 0 {
		return "< 1m"
	}
	return fmt.Sprintf("%dm", m)
}
