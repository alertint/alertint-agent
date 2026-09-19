// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"errors"
	"fmt"
	"strings"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/situation"
)

// RenderExpectedBehaviorReview renders a standalone schedule review card.
func RenderExpectedBehaviorReview(intent situation.ExpectedBehaviorReviewIntent) (RenderedMessage, error) {
	if intent.ID == "" || intent.EnvelopeID == "" || intent.Head.Policy == nil {
		return RenderedMessage{}, errors.New("slack: incomplete expected behavior review")
	}
	p := intent.Head.Policy
	escape := func(value string) string {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value)
	}
	text := fmt.Sprintf("*Expected schedule review*\n*Workload:* %s\n*Scope:* %s · %s · %s · trigger %s\n*Review due:* %s\n*Matched:* %d Situation(s) since this version was confirmed\n*Envelope:* `%s` (version %d)\n*Read in MCP:* `alertint_get_expected_behavior {\"envelope_id\":\"%s\"}`\nThis schedule stays active until an operator changes it.",
		escape(p.Conditions.Workload), escape(p.Scope.Source), escape(p.Scope.SourceInstanceID), escape(p.Scope.Host),
		escape(p.Scope.PrimaryTriggerID), SlackDateToken(p.ReviewDueAt, "{date_short_pretty} {time}"), intent.MatchCount,
		escape(intent.EnvelopeID), intent.EnvelopeVersion, escape(intent.EnvelopeID))
	return RenderedMessage{Text: text, Blocks: []slacklib.Block{sectionBlock(text)}}, nil
}
