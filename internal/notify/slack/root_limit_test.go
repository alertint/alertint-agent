// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"fmt"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// A growing set of distinct alerts must not make the replacement root too
// large for chat.update, and the operator must know where the rest went.
func TestCanonicalRootBoundsManyAlertIdentities(t *testing.T) {
	b := canonicalFixture(t)
	b.Alerts = nil
	for i := 0; i < 47; i++ {
		b.Alerts = append(b.Alerts, model.BriefingAlert{
			ID:    fmt.Sprintf("alert-%02d", i),
			Name:  fmt.Sprintf("Alert-%02d-%s", i, strings.Repeat("x", 150)),
			State: "firing",
		})
	}
	b.Firing, b.Total = 47, 47
	in := bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), b)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Text) > 4000 || len(msg.Blocks) > 50 {
		t.Fatalf("oversized root: text=%d bytes blocks=%d", len(msg.Text), len(msg.Blocks))
	}
	bcBothSurfaces(t, msg, "47 firing", "Alert-00", "42 more", "Slack message limit reached", "get situation")
	if strings.Contains(msg.Text, "Alert-46") {
		t.Fatal("root must leave the omitted identities to MCP")
	}
}

// Even an unusually long legacy title must not bypass the final payload
// guard. The compact card still tells the operator what to do and where to
// retrieve the full Situation.
func TestRootCompactFallbackBoundsWholeMessage(t *testing.T) {
	in := bcRoot(t, model.LifecycleActive, model.AttentionUrgent, bcObserveMonitorContract(bcNow(t)), canonicalFixture(t))
	in.Summary.Briefing = nil
	in.SourceTransition.Projection.Briefing = nil
	in.Summary.Title = strings.Repeat("Exception in checkout 🚨 ", 300)
	msg, err := RenderSituationRoot(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Text) > 4000 || len(msg.Blocks) > 50 {
		t.Fatalf("oversized fallback: text=%d bytes blocks=%d", len(msg.Text), len(msg.Blocks))
	}
	bcBothSurfaces(t, msg, "Slack message limit reached", "Monitoring alert changes", "get situation")
}
