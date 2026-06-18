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
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
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
	client  SlackClient
	channel string
	store   ThreadStore
	auditor *audit.Auditor
}

// Probe verifies the bot token against the Slack auth.test API. Used by
// the integration health check; a failure means the token is invalid,
// revoked, or Slack is unreachable.
func Probe(ctx context.Context, botToken string) error {
	_, err := slacklib.New(botToken).AuthTestContext(ctx)
	return err
}

// New constructs a Slack Notifier using a bot token (xoxb-...).
func New(botToken, channel string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	return &Notifier{
		client:  slacklib.New(botToken),
		channel: channel,
		store:   store,
		auditor: auditor,
	}
}

// NewWithClient constructs a Notifier with a custom SlackClient, enabling
// injection of a mock in tests.
func NewWithClient(client SlackClient, channel string, store ThreadStore, auditor *audit.Auditor) *Notifier {
	return &Notifier{client: client, channel: channel, store: store, auditor: auditor}
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
	// Fallback: no prior thread recorded — post a fresh resolved message.
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

// firingMainBlocks builds the brief main-channel message posted when an incident
// fires: headline + root cause only. Keeps the channel timeline scannable.
func firingMainBlocks(f notify.Finding) []slacklib.Block {
	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf(":red_circle: *INCIDENT DETECTED* — %s", f.AnalysisName), false, false),
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
	return blocks
}

// firingDetailBlocks builds the immediate thread reply with the full analysis:
// severity, confidence, correlation findings, and MCP hint.
func firingDetailBlocks(f notify.Finding) []slacklib.Block {
	confidence := fmt.Sprintf("%.0f%%", f.Confidence*100)
	severity := strings.ToUpper(f.Severity)

	blocks := []slacklib.Block{
		slacklib.NewSectionBlock(
			slacklib.NewTextBlockObject(slacklib.MarkdownType, "*Analysis details*", false, false),
			nil, nil,
		),
		slacklib.NewSectionBlock(nil, []*slacklib.TextBlockObject{
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Severity*\n%s", severity), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Confidence*\n%s", confidence), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Alerts*\n%d", f.AlertCount), false, false),
			slacklib.NewTextBlockObject(slacklib.MarkdownType, fmt.Sprintf("*Group*\n`%s`", f.GroupKey), false, false),
		}, nil),
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

	blocks = append(blocks,
		slacklib.NewDividerBlock(),
		slacklib.NewContextBlock("",
			slacklib.NewTextBlockObject(slacklib.MarkdownType,
				fmt.Sprintf(":mag: `alertint_get_incident(\"%s\")` · `alertint_list_incidents`", f.IncidentID),
				false, false),
		),
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
				fmt.Sprintf(":white_check_mark: *INCIDENT RESOLVED* — %s", f.AnalysisName), false, false),
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
				":white_check_mark: *All clear — all alerts have recovered.*", false, false),
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
	return fmt.Sprintf("🔴 INCIDENT DETECTED: %s (severity: %s)",
		f.AnalysisName, strings.ToUpper(f.Severity))
}

func resolvedFallback(f notify.Finding) string {
	return fmt.Sprintf("✅ INCIDENT RESOLVED: %s (duration: %s)",
		f.AnalysisName, formatDuration(f.AnalyzedAt.Sub(f.FirstAlertAt)))
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
