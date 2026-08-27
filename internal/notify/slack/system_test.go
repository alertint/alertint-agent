// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"errors"
	"testing"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/llmhealth"
)

// TestPostSystemMessageClassifiesIndeterminateFailures pins the contract the
// llmhealth tracker relies on to keep one root per Outage episode: a
// definite Slack rejection (Slack answered, the message was not posted) is
// returned as-is so the tracker retries, while a transport failure — where
// Slack may already have accepted the message — is marked
// llmhealth.ErrDeliveryIndeterminate so the tracker never posts again.
func TestPostSystemMessageClassifiesIndeterminateFailures(t *testing.T) {
	fake := newFakeSlack(t)
	fake.postErr = errors.New("channel_not_found")
	n := NewWithClient(fake, "#alerts", "high", "", &fakeThreadStore{}, nil)
	_, _, err := n.PostSystemMessage(context.Background(), "x")
	if err == nil || llmhealth.IsDeliveryIndeterminate(err) {
		t.Fatalf("a definite Slack rejection must be retryable, got %v", err)
	}

	dead := NewWithClient(slacklib.New("xoxb-test", slacklib.OptionAPIURL("http://127.0.0.1:1/")), "#alerts", "high", "", &fakeThreadStore{}, nil)
	_, _, err = dead.PostSystemMessage(context.Background(), "x")
	if err == nil || !llmhealth.IsDeliveryIndeterminate(err) {
		t.Fatalf("a transport failure must be indeterminate, got %v", err)
	}
}

func TestPostAndUpdateSystemMessageArePlainRootMessages(t *testing.T) {
	fake := newFakeSlack(t)
	n := NewWithClient(fake, "#alerts", "high", "", &fakeThreadStore{}, nil)

	ch, ts, err := n.PostSystemMessage(context.Background(), "⚠️ AlertINT system · test")
	if err != nil || ch == "" || ts == "" {
		t.Fatalf("post: ch=%q ts=%q err=%v", ch, ts, err)
	}
	post := fake.lastPost()
	if post.channel != "#alerts" || post.text != "⚠️ AlertINT system · test" || post.threadTS != "" || len(post.blocks) != 0 {
		t.Fatalf("post = %+v (must be a plain root message, no thread, no blocks)", post)
	}

	if err := n.UpdateSystemMessage(context.Background(), ch, ts, "✅ AlertINT system · recovered"); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastUpdate(); got != "✅ AlertINT system · recovered" {
		t.Fatalf("update text = %q", got)
	}
}
