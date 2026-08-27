// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"fmt"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/llmhealth"
)

var _ llmhealth.Publisher = (*Notifier)(nil)

// PostSystemMessage posts one plain-text installation message as a channel
// root. It bypasses min_severity (not a Finding) and never threads.
func (n *Notifier) PostSystemMessage(ctx context.Context, text string) (string, string, error) {
	ch, ts, err := n.client.PostMessageContext(ctx, n.channel, slacklib.MsgOptionText(text, false))
	if err != nil {
		return "", "", fmt.Errorf("channel %s: post system message: %w", n.channel, err)
	}
	return ch, ts, nil
}

// UpdateSystemMessage edits a previously posted system root in place.
func (n *Notifier) UpdateSystemMessage(ctx context.Context, channel, ts, text string) error {
	if channel == "" {
		channel = n.channel
	}
	if _, _, _, err := n.client.UpdateMessageContext(ctx, channel, ts, slacklib.MsgOptionText(text, false)); err != nil {
		return fmt.Errorf("channel %s: update system message: %w", channel, err)
	}
	return nil
}
