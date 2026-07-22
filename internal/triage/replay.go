// SPDX-License-Identifier: FSL-1.1-ALv2

package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/packs"
	"github.com/alertint/alertint-agent/skills/acutetriage"
	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
)

// DeterminismReplay re-invokes the skill with the captured scenario and
// scripted LLM responses, then asserts the new rendered finding equals the
// golden's byte-for-byte (after scrubbing timestamps and generated IDs).
// Returns nil when the replay matches.
func DeterminismReplay(g *Golden, scenarioPath, responsesPath string) []FieldError {
	sc, err := LoadScenario(scenarioPath)
	if err != nil {
		return []FieldError{{Field: "scenario", Got: err.Error(), Want: "loadable scenario"}}
	}
	resps, err := LoadResponses(responsesPath)
	if err != nil {
		return []FieldError{{Field: "responses", Got: err.Error(), Want: "loadable responses"}}
	}

	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		return []FieldError{{Field: "store", Got: err.Error(), Want: "openable store"}}
	}
	defer func() { _ = st.Close() }()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := rules.NewEngine(ctx, logger, rules.NewEmbeddedSource(packs.BaselineFS(), "embedded:baseline", 0))
	if err != nil {
		return []FieldError{{Field: "engine", Got: err.Error(), Want: "buildable engine"}}
	}

	alerts, groupKey, err := materializeForReplay(sc, g.Incident.Alerts)
	if err != nil {
		return []FieldError{{Field: "materialize", Got: err.Error(), Want: "materializable scenario"}}
	}

	incidentID := "replay-" + sc.ID
	firstAt := alerts[0].StartsAt
	lastAt := alerts[len(alerts)-1].StartsAt
	inc := store.Incident{
		ID:           incidentID,
		GroupKey:     groupKey,
		Status:       "collecting",
		FirstAlertAt: firstAt,
		LastAlertAt:  lastAt,
		ReadyAt:      lastAt,
		AlertCount:   len(alerts),
	}
	if err := st.InsertIncident(ctx, inc); err != nil {
		return []FieldError{{Field: "store.insert", Got: err.Error(), Want: "insertable incident"}}
	}
	for _, a := range alerts {
		stored, err := st.UpsertAlertByFingerprint(ctx, a)
		if err != nil {
			return []FieldError{{Field: "store.upsert", Got: err.Error(), Want: "upsertable alert"}}
		}
		if err := st.AddAlertToIncident(ctx, incidentID, stored.ID, a.StartsAt); err != nil {
			return []FieldError{{Field: "store.add", Got: err.Error(), Want: "addable alert"}}
		}
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		return []FieldError{{Field: "store.ready", Got: err.Error(), Want: "markable ready"}}
	}

	scripted := &replayScriptedLLM{responses: resps}
	auditor := audit.New(st.DB())
	notifier := notify.NewMulti(logger)
	skill := acutetriage.New(
		acutetriage.Config{
			WindowSeconds: 300,
			MinAlerts:     1,
			Rules:         engine,
			Verification:  acutetriage.VerificationParams{Enabled: false},
		},
		st, scripted, auditor, notifier, logger,
	)

	if err := skill.Run(ctx, inc); err != nil {
		return []FieldError{{Field: "skill.run", Got: err.Error(), Want: "runnable skill"}}
	}

	persisted, err := st.GetIncidentByID(ctx, incidentID)
	if err != nil {
		return []FieldError{{Field: "store.read", Got: err.Error(), Want: "readable incident"}}
	}

	// Substitute PLACEHOLDER alert_ids in the replayed output with the real
	// alert IDs from the materialized scenario, so the byte-identical
	// comparison matches the golden (which was captured with the same
	// substitution applied).
	replayed := substituteAlertIDsForReplay(persisted.OutputJSON, alerts)
	got := scrubFinding(replayed)
	want := scrubFinding(string(g.RenderedFinding))
	if got != want {
		return []FieldError{{
			Field: "rendered_finding",
			Got:   truncate(got, 200),
			Want:  truncate(want, 200),
		}}
	}
	return nil
}

// materializeForReplay rebuilds alerts from the scenario, reusing the
// golden's alert IDs so the rendered finding's alert_id references match.
func materializeForReplay(sc *Scenario, goldenAlerts []AlertSnapshot) ([]store.Alert, string, error) {
	goldenByFP := make(map[string]string, len(goldenAlerts))
	for _, ga := range goldenAlerts {
		fp := fingerprintFromLabels(ga.Labels)
		goldenByFP[fp] = ga.ID
	}

	var alerts []store.Alert
	idx := 0
	now := time.Now().UTC()
	for _, tpl := range sc.Alerts {
		n := tpl.Repeat
		if n <= 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			labels := make(map[string]string, len(tpl.Labels))
			for k, v := range tpl.Labels {
				labels[k] = v
			}
			for _, k := range tpl.Spread {
				labels[k] = fmt.Sprintf("%s-%d", tpl.Labels[k], i)
			}
			fp := fingerprintFromLabels(labels)
			id, ok := goldenByFP[fp]
			if !ok {
				id = fmt.Sprintf("replay-%s-%d-%d", sc.ID, idx, i)
			}
			startsAt := now.Add(time.Duration(tpl.OffsetSeconds) * time.Second)
			alerts = append(alerts, store.Alert{
				ID:          id,
				Fingerprint: fp,
				Status:      "firing",
				Labels:      labels,
				Annotations: tpl.Annotations,
				StartsAt:    startsAt,
				ReceivedAt:  now,
			})
			idx++
		}
	}
	if len(alerts) == 0 {
		return nil, "", fmt.Errorf("scenario %q produced no alerts", sc.ID)
	}
	shared := make(map[string]string, len(alerts[0].Labels))
	for k, v := range alerts[0].Labels {
		shared[k] = v
	}
	for _, a := range alerts[1:] {
		for k := range shared {
			if a.Labels[k] != shared[k] {
				delete(shared, k)
			}
		}
	}
	parts := make([]string, 0, len(shared))
	for k, v := range shared {
		parts = append(parts, k+"="+v)
	}
	return alerts, strings.Join(parts, ","), nil
}

// fingerprintFromLabels produces a deterministic fingerprint from a label set.
func fingerprintFromLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(labels[k])
		b.WriteString(";")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// scrubFinding normalizes a rendered finding JSON for byte-identical
// comparison: strips timestamps and generated IDs that vary between runs.
func scrubFinding(raw string) string {
	if raw == "" {
		return ""
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	if ver, ok := v["verification"].(map[string]any); ok {
		if rounds, ok := ver["rounds"].([]any); ok {
			for _, r := range rounds {
				if rm, ok := r.(map[string]any); ok {
					delete(rm, "at")
				}
			}
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// replayScriptedLLM is the replay-side scripted LLM.
type replayScriptedLLM struct {
	responses []ScriptedResponse
	idx       int
}

func (s *replayScriptedLLM) Complete(_ context.Context, _ string, prompt llm.Prompt, _ []string) (llm.Completion, error) {
	hash := PromptHash(prompt.Prefix + prompt.Suffix)
	for _, r := range s.responses {
		if r.MatchPromptHash != "" && r.MatchPromptHash == hash {
			return llm.Completion{Raw: r.Response, Model: "scripted"}, nil
		}
	}
	if s.idx >= len(s.responses) {
		return llm.Completion{}, fmt.Errorf("replayScriptedLLM: out of responses")
	}
	r := s.responses[s.idx]
	s.idx++
	return llm.Completion{Raw: r.Response, Model: "scripted"}, nil
}

// substituteAlertIDsForReplay replaces PLACEHOLDER alert_id values in a
// replayed rendered finding with real alert IDs from the materialized
// scenario. Mirrors the substitution applied at capture time in
// cmd/alertint/drill_golden.go so the byte-identical replay comparison
// matches the golden.
func substituteAlertIDsForReplay(raw string, alerts []store.Alert) string {
	if raw == "" || len(alerts) == 0 {
		return raw
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	alertsArr, ok := v["alerts"].([]any)
	if !ok || len(alertsArr) == 0 {
		return raw
	}
	next := 0
	for _, a := range alertsArr {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := m["alert_id"].(string); ok && id == "PLACEHOLDER" {
			m["alert_id"] = alerts[next%len(alerts)].ID
			next++
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return string(b)
}
