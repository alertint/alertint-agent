// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// annotationKindLabel renders an annotation kind as a thread-reply headline.
var annotationKindLabel = map[string]string{
	"correction":   "Operator correction",
	"confirmation": "Operator confirmation",
	"observation":  "Operator note",
}

// OnAnnotation posts one thread reply on the incident's existing Slack card
// with the operator's annotation. An incident with no recorded card (never
// posted, or gate-suppressed) is a silent no-op — there is nothing to thread
// on, and the annotation is still visible via the stdout sink and the audit
// chain.
func (n *Notifier) OnAnnotation(ctx context.Context, ev notify.AnnotationEvent) error {
	if n.store == nil {
		return nil
	}
	ts, ch, err := n.store.GetIncidentSlackThread(ctx, ev.IncidentID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			slog.Default().Warn("slack: annotation thread lookup failed; skipping reply", "incident_id", ev.IncidentID, "err", err)
		}
		return nil
	}
	if ts == "" {
		return nil
	}
	channel := ch
	if channel == "" {
		channel = n.channel
	}
	label := annotationKindLabel[ev.Kind]
	if label == "" {
		label = "Operator note"
	}
	text := fmt.Sprintf("📝 %s: %s", label, ev.Note)
	if _, _, err := n.client.PostMessageContext(ctx, channel,
		slacklib.MsgOptionText(text, false),
		slacklib.MsgOptionTS(ts),
	); err != nil {
		return fmt.Errorf("channel %s: annotation thread reply: %w", channel, err)
	}
	return nil
}
