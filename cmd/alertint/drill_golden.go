// SPDX-License-Identifier: FSL-1.1-ALv2

// Command drill-golden captures a triage golden trace from a scripted
// scenario + responses sidecar. See docs.superpowers/specs/2026-07-19-
// triage-eval-harness-design.md for the golden JSON shape.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/rules"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/packs"
	"github.com/alertint/alertint-agent/skills/acutetriage"
	"github.com/alertint/alertint-agent/internal/triage"
	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
)

// drillGoldenOpts are the parsed `alertint drill-golden` flags.
type drillGoldenOpts struct {
	cfgPath   string
	scenario  string
	responses string
	out       string
}

// scriptedLLM is a fake LLMClient that returns scripted responses in order.
// When MatchPromptHash is set on a response, it is returned only when the
// current prompt's hash matches; otherwise responses are returned in order.
type scriptedLLM struct {
	responses []triage.ScriptedResponse
	idx       int
	calls     int
}

func (s *scriptedLLM) Complete(_ context.Context, _ string, prompt llm.Prompt, _ []string) (llm.Completion, error) {
	hash := promptHash(prompt.Prefix + prompt.Suffix)
	// Prefer hash-matched response if available.
	for _, r := range s.responses {
		if r.MatchPromptHash != "" && r.MatchPromptHash == hash {
			s.calls++
			return llm.Completion{
				Raw:          r.Response,
				Model:        "scripted",
				InputTokens:  len(prompt.Prefix) / 4,
				OutputTokens: len(r.Response) / 4,
				Latency:      time.Millisecond,
			}, nil
		}
	}
	// Fall back to in-order.
	if s.idx >= len(s.responses) {
		return llm.Completion{}, fmt.Errorf("scriptedLLM: out of responses (call %d)", s.calls+1)
	}
	r := s.responses[s.idx]
	s.idx++
	s.calls++
	return llm.Completion{
		Raw:          r.Response,
		Model:        "scripted",
		InputTokens:  len(prompt.Prefix) / 4,
		OutputTokens: len(r.Response) / 4,
		Latency:      time.Millisecond,
	}, nil
}

func promptHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func runDrillGolden(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint drill-golden", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts drillGoldenOpts
	fs.StringVar(&opts.cfgPath, "config", "", "path to alertint YAML config")
	fs.StringVar(&opts.scenario, "scenario", "", "path to scenario YAML")
	fs.StringVar(&opts.responses, "responses", "", "path to responses JSON sidecar")
	fs.StringVar(&opts.out, "out", "", "path to write the captured golden JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.cfgPath == "" || opts.scenario == "" || opts.responses == "" || opts.out == "" {
		return fmt.Errorf("drill-golden: --config, --scenario, --responses, and --out are all required")
	}

	cfg, err := config.LoadOffline(opts.cfgPath)
	if err != nil {
		return fmt.Errorf("drill-golden: load config: %w", err)
	}

	sc, err := triage.LoadScenario(opts.scenario)
	if err != nil {
		return fmt.Errorf("drill-golden: load scenario: %w", err)
	}
	resps, err := triage.LoadResponses(opts.responses)
	if err != nil {
		return fmt.Errorf("drill-golden: load responses: %w", err)
	}

	// Open an in-memory store so the skill can persist the finding.
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		return fmt.Errorf("drill-golden: open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	// Build the rule engine from the embedded baseline pack.
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	engine, err := rules.NewEngine(ctx, logger, rules.NewEmbeddedSource(packs.BaselineFS(), "embedded:baseline", 0))
	if err != nil {
		return fmt.Errorf("drill-golden: build engine: %w", err)
	}

	// Materialize the scenario into alerts + an incident.
	alerts, groupKey, err := materializeScenarioAlerts(sc, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("drill-golden: materialize: %w", err)
	}
	incidentID := "drill-" + sc.ID
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
		return fmt.Errorf("drill-golden: insert incident: %w", err)
	}
	for _, a := range alerts {
		stored, err := st.UpsertAlertByFingerprint(ctx, a)
		if err != nil {
			return fmt.Errorf("drill-golden: upsert alert: %w", err)
		}
		if err := st.AddAlertToIncident(ctx, incidentID, stored.ID, a.StartsAt); err != nil {
			return fmt.Errorf("drill-golden: add alert to incident: %w", err)
		}
	}
	if err := st.MarkIncidentReady(ctx, incidentID); err != nil {
		return fmt.Errorf("drill-golden: mark ready: %w", err)
	}

	// Build the skill with the scripted LLM.
	scripted := &scriptedLLM{responses: resps}
	auditor := audit.New(st.DB())
	notifier := notify.NewMulti(logger) // no sinks; drill-golden doesn't notify
	skill := acutetriage.New(
		acutetriage.Config{
			WindowSeconds: cfg.Correlator.WindowSeconds,
			MinAlerts:     cfg.Correlator.MinAlerts,
			Rules:         engine,
			Verification: acutetriage.VerificationParams{
				Enabled:             cfg.VerificationEnabled(),
				MaxQueries:          cfg.Triage.Verification.MaxQueries,
				QueryTimeoutSeconds: cfg.Triage.Verification.QueryTimeoutSeconds,
				MaxSeries:           cfg.Prometheus.MaxSeries,
			},
		},
		st, scripted, auditor, notifier, logger,
	)

	// Run the skill.
	if err := skill.Run(ctx, inc); err != nil {
		return fmt.Errorf("drill-golden: skill run: %w", err)
	}

	// Read back the persisted finding.
	persisted, err := st.GetIncidentByID(ctx, incidentID)
	if err != nil {
		return fmt.Errorf("drill-golden: read incident: %w", err)
	}

	// Build the golden.
	golden := buildGolden(sc, inc, alerts, persisted, scripted, cfg, engine, opts)
	if err := triage.SaveGolden(opts.out, golden); err != nil {
		return fmt.Errorf("drill-golden: save golden: %w", err)
	}
	fmt.Fprintf(stdout, "drill-golden: wrote %s\n", opts.out)
	return nil
}

// materializeScenarioAlerts expands a scenario into concrete store.Alert
// values, applying Repeat and Spread. Returns the alerts and the group key
// (sorted k=v join of shared labels).
func materializeScenarioAlerts(sc *triage.Scenario, now time.Time) ([]store.Alert, string, error) {
	var alerts []store.Alert
	idx := 0
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
			// Apply spread: each spread key gets a unique value per repeat.
			for _, k := range tpl.Spread {
				labels[k] = fmt.Sprintf("%s-%d", tpl.Labels[k], i)
			}
			startsAt := now.Add(time.Duration(tpl.OffsetSeconds) * time.Second)
			if tpl.OffsetSeconds > 0 && i > 0 {
				startsAt = now.Add(time.Duration(tpl.OffsetSeconds) * time.Second)
			}
			fp := fmt.Sprintf("drill-%s-%d-%d", sc.ID, idx, i)
			alerts = append(alerts, store.Alert{
				ID:          fmt.Sprintf("alert-%s-%d-%d", sc.ID, idx, i),
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
	// Group key: sorted k=v join of labels shared by all alerts.
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

// buildGolden assembles the Golden struct from the captured run.
// substituteAlertIDs replaces PLACEHOLDER alert_id values in a rendered
// finding JSON with real alert IDs from the materialized alerts. The scripted
// LLM responses use PLACEHOLDER because they don't know the generated IDs at
// authoring time; the schema gate requires every alert_id to reference a real
// incident alert, so we substitute at capture time.
func substituteAlertIDs(raw string, alerts []store.Alert) string {
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

func buildGolden(sc *triage.Scenario, inc store.Incident, alerts []store.Alert, persisted *store.Incident, scripted *scriptedLLM, cfg *config.Config, engine *rules.Engine, opts drillGoldenOpts) *triage.Golden {
	// Build incident snapshot.
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
	alertSnaps := make([]triage.AlertSnapshot, len(alerts))
	for i, a := range alerts {
		alertSnaps[i] = triage.AlertSnapshot{
			ID:          a.ID,
			Labels:      a.Labels,
			Annotations: a.Annotations,
			StartsAt:    a.StartsAt,
		}
	}

	// Build config snapshot.
	packs := engine.Packs()
	packIDs := make([]triage.RulePackIdentity, len(packs))
	for i, p := range packs {
		packIDs[i] = triage.RulePackIdentity{Name: p.Name, Version: p.Version}
	}

	// Parse the rendered finding to extract verification outcome if present.
	ver := triage.VerificationSnapshot{}
	if persisted != nil && persisted.OutputJSON != "" {
		var raw struct {
			Verification struct {
				Outcome string `json:"outcome"`
				Rounds  []struct {
					Queries []map[string]any `json:"queries"`
				} `json:"rounds"`
			} `json:"verification"`
		}
		if err := json.Unmarshal([]byte(persisted.OutputJSON), &raw); err == nil {
			ver.Outcome = raw.Verification.Outcome
			for _, r := range raw.Verification.Rounds {
				ver.QueriesExecuted += len(r.Queries)
				for _, q := range r.Queries {
					if outcome, ok := q["outcome"].(string); ok && (outcome == "failed" || outcome == "degraded") {
						ver.QueriesFailed++
					}
				}
			}
		}
	}

	rendered := json.RawMessage(substituteAlertIDs(persisted.OutputJSON, alerts))
	if len(rendered) == 0 {
		rendered = json.RawMessage("{}")
	}

	return &triage.Golden{
		SchemaVersion: triage.SchemaVersion,
		ID:            sc.ID,
		CapturedAt:    time.Now().UTC(),
		ScenarioPath:  filepath.ToSlash(opts.scenario),
		Incident: triage.IncidentSnapshot{
			ID:           inc.ID,
			GroupKey:     inc.GroupKey,
			AlertCount:   len(alerts),
			SharedLabels: shared,
			Alerts:       alertSnaps,
		},
		RenderedFinding: rendered,
		Verification:    ver,
		ModelUsage: triage.ModelUsage{
			Model:       "scripted",
			InputTokens: 0,
			OutputTokens: 0,
			LatencyMS:   int64(scripted.calls) * 1,
			CostUSD:     0,
			PromptHash:  "",
		},
		ConfigSnapshot: triage.ConfigSnapshot{
			Model:               cfg.LLM.Model,
			MaxTokens:           cfg.LLM.MaxTokens,
			SystemPromptHash:    "",
			TriageMinAlerts:     cfg.Correlator.MinAlerts,
			VerificationEnabled: cfg.VerificationEnabled(),
			ClassifierMode:      string(cfg.Memory.Classifier.Mode),
			SlackMinSeverity:    cfg.Notify.Slack.MinSeverity,
			RulePacks:           packIDs,
		},
		Judge: triage.JudgeMeta{
			Model:            "claude-haiku-4-5",
			PromptVersion:    "v1",
			SystemPromptPath: "internal/triage/judge_prompt.md",
		},
	}
}
