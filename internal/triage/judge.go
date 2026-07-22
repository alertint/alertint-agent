// SPDX-License-Identifier: FSL-1.1-ALv2

package triage

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

const judgePromptV1 = "v1"

//go:embed judge_prompt.md
var judgePromptBody string

// Verdict is the structured judge response.
type Verdict struct {
	Decision string   `json:"verdict"`
	Reasons  []string `json:"reasons"`
	Missing  []string `json:"missing"`
}

// Judge calls the LLM with the versioned judge prompt and parses the
// structured verdict. Returns the verdict, the raw completion (for cost/
// latency logging), and any error.
func Judge(ctx context.Context, client acutetriage.LLMClient, g *Golden) (Verdict, llm.Completion, error) {
	if client == nil {
		return Verdict{}, llm.Completion{}, fmt.Errorf("triage: judge: nil client")
	}
	user := renderJudgeUserPrompt(g)
	comp, err := client.Complete(ctx, strings.TrimSpace(judgePromptBody), llm.Prompt{Prefix: user}, []string{"verdict", "reasons", "missing"})
	if err != nil {
		return Verdict{}, comp, fmt.Errorf("triage: judge: complete: %w", err)
	}
	var v Verdict
	if err := json.Unmarshal(comp.Raw, &v); err != nil {
		return Verdict{}, comp, fmt.Errorf("triage: judge: parse: %w", err)
	}
	if v.Decision != "pass" && v.Decision != "fail" {
		return Verdict{}, comp, fmt.Errorf("triage: judge: unknown verdict %q", v.Decision)
	}
	return v, comp, nil
}

func renderJudgeUserPrompt(g *Golden) string {
	var b strings.Builder
	b.WriteString("## Incident alerts\n\n")
	for _, a := range g.Incident.Alerts {
		b.WriteString("- id=")
		b.WriteString(a.ID)
		b.WriteString(" labels=")
		b.WriteString(mustJSON(a.Labels))
		if len(a.Annotations) > 0 {
			b.WriteString(" annotations=")
			b.WriteString(mustJSON(a.Annotations))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Rendered finding\n\n```json\n")
	b.WriteString(string(g.RenderedFinding))
	b.WriteString("\n```\n")
	return b.String()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "triage: mustJSON:", err)
		return "{}"
	}
	return string(b)
}
