// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/packs"
)

// TestBoundedItemizationPromptConsistency pins the bounded-itemization and
// brevity rules across every prompt surface to the Go constants: the literal
// cap lives in three static templates AND in maxItemizedAlerts, and the two
// must never drift — the code defaulting un-itemized roles (skill.go) relies
// on the prompts promising exactly that behavior.
func TestBoundedItemizationPromptConsistency(t *testing.T) {
	capPhrase := fmt.Sprintf("more than %d alerts", maxItemizedAlerts)
	brevityPhrase := "at most 6 correlation_findings"

	if !strings.Contains(SystemPrompt, capPhrase) {
		t.Errorf("SystemPrompt: missing bounded-itemization rule %q", capPhrase)
	}
	if !strings.Contains(SystemPrompt, brevityPhrase) {
		t.Errorf("SystemPrompt: missing brevity rule %q", brevityPhrase)
	}

	for _, name := range []string{"correlated.md", "storm.md", "recovery.md"} {
		b, err := fs.ReadFile(packs.BaselineFS(), "templates/"+name)
		if err != nil {
			t.Fatalf("read template %s: %v", name, err)
		}
		tmpl := string(b)
		if !strings.Contains(tmpl, capPhrase) {
			t.Errorf("%s: missing bounded-itemization rule %q", name, capPhrase)
		}
		if !strings.Contains(tmpl, brevityPhrase) {
			t.Errorf("%s: missing brevity rule %q", name, brevityPhrase)
		}
	}
}
