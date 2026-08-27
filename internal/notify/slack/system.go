// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"errors"
	"fmt"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/llmhealth"
)

var _ llmhealth.Publisher = (*Notifier)(nil)

// PostSystemMessage posts one plain-text installation message as a channel
// root. It bypasses min_severity (not a Finding) and never threads. A failure
// Slack itself answered (an API error, a rate limit, an HTTP status) means
// the message was not posted and is returned as-is so the caller retries;
// any other failure (the request may have been sent and accepted) is marked
// llmhealth.ErrDeliveryIndeterminate so the caller never posts a duplicate.
func (n *Notifier) PostSystemMessage(ctx context.Context, text string) (string, string, error) {
	ch, ts, err := n.client.PostMessageContext(ctx, n.channel, slacklib.MsgOptionText(text, false))
	if err != nil {
		if !isDefiniteSlackRejection(err) {
			err = fmt.Errorf("%w: %w", llmhealth.ErrDeliveryIndeterminate, err)
		}
		return "", "", fmt.Errorf("channel %s: post system message: %w", n.channel, err)
	}
	return ch, ts, nil
}

// isDefiniteSlackRejection reports whether err is a reply from Slack (so the
// message was definitely not posted), as opposed to a transport failure.
func isDefiniteSlackRejection(err error) bool {
	var apiErr slacklib.SlackErrorResponse
	var statusErr slacklib.StatusCodeError
	var rateErr *slacklib.RateLimitedError
	return errors.As(err, &apiErr) || errors.As(err, &statusErr) || errors.As(err, &rateErr)
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
