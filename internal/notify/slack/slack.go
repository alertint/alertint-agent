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
	"fmt"
	"strings"
	"sync"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/severity"
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
	client      SlackClient
	channel     string
	store       ThreadStore
	auditor     *audit.Auditor
	minSeverity string // findings below this severity are not posted ("" = low = post everything)

	// Occurrence card-edit throttle (recurrence collapse, R10): at most one edit
	// per incident per occEditThrottle, coalesced, with a trailing flush. now and
	// after are seams so the throttle is deterministic in tests; occ holds
	// in-memory per-incident state (lost on restart — the next attach
	// self-corrects, an accepted gap).
	now   func() time.Time
	after func(d time.Duration, fn func()) stopper
	occMu sync.Mutex
	occ   map[string]*occThrottle
}

// Probe verifies the bot token against the Slack auth.test API. Used by
// the integration health check; a failure means the token is invalid,
// revoked, or Slack is unreachable.
func Probe(ctx context.Context, botToken string) error {
	_, err := slacklib.New(botToken).AuthTestContext(ctx)
	return err
}

// New constructs a Slack Notifier using a bot token (xoxb-...). minSeverity
// is the channel noise gate (low | medium | high; "" means low).
func New(botToken, channel, minSeverity string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	return newNotifier(slacklib.New(botToken), channel, minSeverity, store, auditor)
}

// NewWithClient constructs a Notifier with a custom SlackClient, enabling
// injection of a mock in tests.
func NewWithClient(client SlackClient, channel, minSeverity string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	return newNotifier(client, channel, minSeverity, store, auditor)
}

func newNotifier(client SlackClient, channel, minSeverity string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	return &Notifier{
		client:      client,
		channel:     channel,
		minSeverity: minSeverity,
		store:       store,
		auditor:     auditor,
		now:         time.Now,
		after:       func(d time.Duration, fn func()) stopper { return time.AfterFunc(d, fn) },
		occ:         make(map[string]*occThrottle),
	}
}

// Name returns the stable sink label used in the notify outcome line. The
// channel rides the wrapped error on failure (and the startup "slack connected"
// line), never the label, so the label stays constant across findings.
func (n *Notifier) Name() string { return "slack" }

// Notify dispatches to notifyFiring or notifyResolved based on f.Status.
func (n *Notifier) Notify(ctx context.Context, f notify.Finding) error {
	if f.Status == "resolved" {
		return n.notifyResolved(ctx, f)
	}
	return n.notifyFiring(ctx, f)
}

func (n *Notifier) notifyFiring(ctx context.Context, f notify.Finding) error {
	// Severity gate: below-threshold findings never reach the channel (stdout
	// still emits them). Skipping records an audit row so the suppression is
	// visible in the hash-chained trail, not silent.
	if n.belowMinSeverity(f) {
		n.auditSkipped(ctx, f)
		return nil
	}
	// Post brief main-channel message: headline + root cause only.
	ch, ts, err := n.client.PostMessageContext(ctx, n.channel,
		slacklib.MsgOptionText(firingFallback(f), false),
		slacklib.MsgOptionBlocks(firingMainBlocks(f)...),
	)
	if err != nil {
		return fmt.Errorf("channel %s: post message: %w", n.channel, err)
	}
	if n.store != nil && ts != "" {
		_ = n.store.SetIncidentSlackThread(ctx, f.IncidentID, ts, ch)
	}
	// Post full analysis detail immediately as a thread reply.
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

// drillMd / drillPlain return the DRILL banner fragment prepended to every
// rendered surface of a Drill finding (main card, thread detail, fallback):
// a synthetic card must be unmistakably synthetic in a shared channel
// (ADR-0013). Empty for real incidents.
func drillMd(f notify.Finding) string {
	if f.Drill {
		return ":test_tube: *DRILL* — "
	}
	return ""
}

func drillPlain(f notify.Finding) string {
	if f.Drill {
		return "🧪 DRILL — "
	}
	return ""
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
	if f.OverallIssue != "" {
		blocks = append(blocks, slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("*Root cause:* %s", f.OverallIssue), false, false),
			nil, nil,
		))
	}
	blocks = append(blocks, slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			fmt.Sprintf("Incident `%s` · %d alerts · group `%s` · started %s UTC",
				shortID(f.IncidentID), f.AlertCount, f.GroupKey,
				f.FirstAlertAt.UTC().Format("15:04")),
			false, false),
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

// agentHandoffBlock is the MCP call to action, rendered the same wherever it
// appears: main firing card and thread detail.
func agentHandoffBlock(incidentID string) slacklib.Block {
	return slacklib.NewSectionBlock(
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			fmt.Sprintf(":robot_face: *Investigate in your AI agent*\n`investigate incident %s using alertint`", incidentID),
			false, false),
		nil, nil,
	)
}

// evidenceLine renders the always-on evidence summary text (R6/R7/R8/R12). A
// short-circuit or zero-connector finding renders one card-level state; otherwise
// each source renders "<Source> <count> <unit>" (unit omitted for changes), or
// "<Source> unreachable" when the connector could not be reached.
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
	if f.OverallIssue != "" {
		blocks = append(blocks, slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf("*Root cause:* %s", f.OverallIssue), false, false),
			nil, nil,
		))
	}
	blocks = append(blocks, slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType,
			fmt.Sprintf("Incident `%s` · resolved after %s · %s UTC",
				shortID(f.IncidentID), duration, f.AnalyzedAt.UTC().Format("15:04")),
			false, false),
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
