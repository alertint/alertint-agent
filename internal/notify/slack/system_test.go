// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"testing"
)

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
