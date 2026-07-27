// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/notify"
)

func TestOnAnnotation_ThreadsReplyOnExistingCard(t *testing.T) {
	client := newFakeSlack(t)
	n := NewWithClient(client, "chan", "", "change-gated", &fakeThreadStore{}, nil)

	err := n.OnAnnotation(context.Background(), notify.AnnotationEvent{
		IncidentID: "inc1", GroupKey: "k", Kind: "correction", Note: "not AZ outage",
	})
	if err != nil {
		t.Fatalf("OnAnnotation: %v", err)
	}
	if client.postCount() != 1 {
		t.Fatalf("posts = %d, want 1", client.postCount())
	}
	last := client.lastPost()
	if last.threadTS != "ts-1" {
		t.Errorf("threadTS = %q, want ts-1", last.threadTS)
	}
	if !strings.Contains(last.text, "Operator correction") || !strings.Contains(last.text, "not AZ outage") {
		t.Errorf("text = %q, want it to mention the correction and the note", last.text)
	}
}

func TestOnAnnotation_NoCardIsSilent(t *testing.T) {
	client := newFakeSlack(t)
	n := NewWithClient(client, "chan", "", "change-gated", &fakeThreadStore{missing: true}, nil)

	err := n.OnAnnotation(context.Background(), notify.AnnotationEvent{
		IncidentID: "inc1", GroupKey: "k", Kind: "observation", Note: "fyi",
	})
	if err != nil {
		t.Fatalf("OnAnnotation: %v", err)
	}
	if client.postCount() != 0 {
		t.Errorf("posts = %d, want 0 (no card to thread on)", client.postCount())
	}
}
