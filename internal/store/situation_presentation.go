// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func loadSituationPresentationFactsTx(ctx context.Context, tx *sql.Tx, situationID string) (situation.PresentationFacts, error) {
	out, err := loadInvestigationPresentationFactsTx(ctx, tx, situationID)
	if err != nil {
		return out, err
	}
	usage, checks, err := loadEnrichmentPresentationFactsTx(ctx, tx, situationID)
	if err != nil {
		return out, err
	}
	out.AnalysisUsage, out.SourceChecks = usage, checks
	return out, nil
}

func loadInvestigationPresentationFactsTx(ctx context.Context, tx *sql.Tx, situationID string) (out situation.PresentationFacts, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT started_at, completed_at, COALESCE(result_code,'') FROM incident_triage_attempts WHERE situation_id=? ORDER BY started_at,id`, situationID)
	if err != nil {
		return out, fmt.Errorf("store: load presentation investigation timing: %w", err)
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var startedRaw, result string
		var completedRaw sql.NullString
		if err := rows.Scan(&startedRaw, &completedRaw, &result); err != nil {
			return out, err
		}
		startedAt, err := time.Parse(time.RFC3339Nano, startedRaw)
		if err != nil {
			return out, err
		}
		if out.InvestigationStartedAt == nil {
			at := startedAt.UTC()
			out.InvestigationStartedAt = &at
		}
		if !completedRaw.Valid {
			continue
		}
		completedAt, err := time.Parse(time.RFC3339Nano, completedRaw.String)
		if err != nil {
			return out, err
		}
		runtime := completedAt.Sub(startedAt)
		if runtime < 0 {
			runtime = 0
		}
		seconds := int64(runtime / time.Second)
		if out.InvestigationRuntimeSeconds == nil {
			out.InvestigationRuntimeSeconds = new(int64)
		}
		*out.InvestigationRuntimeSeconds += seconds
		if result == "success" {
			at := completedAt.UTC()
			out.InvestigationCompletedAt = &at
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func loadEnrichmentPresentationFactsTx(ctx context.Context, tx *sql.Tx, situationID string) (usage model.AnalysisUsage, sourceChecks []model.SourceCheck, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT i.status, COALESCE(i.enrichment_json,'') FROM situation_incidents si JOIN incidents i ON i.id=si.incident_id WHERE si.situation_id=? ORDER BY i.id`, situationID)
	if err != nil {
		return usage, nil, fmt.Errorf("store: load presentation sources: %w", err)
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	checks := map[string]model.SourceCheck{}
	usageSeen := false
	usageUnknown := false
	for rows.Next() {
		var status, raw string
		if err := rows.Scan(&status, &raw); err != nil {
			return usage, nil, err
		}
		if status == "analyzed" || status == "resolved" {
			current, known := presentationAnalysisUsage(raw)
			if !known {
				usage = model.AnalysisUsage{}
				usageSeen = false
				usageUnknown = true
			} else if !usageUnknown {
				if !usageSeen {
					usage = model.AnalysisUsage{CallsKnown: true, InputTokensKnown: true, OutputTokensKnown: true}
					usageSeen = true
				}
				usage.Calls += current.Calls
				usage.InputTokens += current.InputTokens
				usage.OutputTokens += current.OutputTokens
				usage.InputTokensKnown = usage.InputTokensKnown && current.InputTokensKnown
				usage.OutputTokensKnown = usage.OutputTokensKnown && current.OutputTokensKnown
			}
		}
		for _, check := range presentationSourceChecks(raw) {
			key := check.Source + "\x00" + check.Check + "\x00" + string(check.Outcome) + "\x00" + check.Unit + "\x00" + check.Detail
			prior, ok := checks[key]
			if !ok {
				checks[key] = check
				continue
			}
			if prior.CallsKnown && check.CallsKnown {
				prior.Calls += check.Calls
			} else {
				prior.CallsKnown = false
			}
			if prior.RecordsKnown && check.RecordsKnown {
				prior.Records += check.Records
			} else {
				prior.RecordsKnown = false
			}
			checks[key] = prior
		}
	}
	if err := rows.Err(); err != nil {
		return usage, nil, err
	}
	for _, check := range checks {
		sourceChecks = append(sourceChecks, check)
	}
	sort.Slice(sourceChecks, func(i, j int) bool {
		if sourceChecks[i].Source != sourceChecks[j].Source {
			return sourceChecks[i].Source < sourceChecks[j].Source
		}
		if sourceChecks[i].Check != sourceChecks[j].Check {
			return sourceChecks[i].Check < sourceChecks[j].Check
		}
		return sourceChecks[i].Outcome < sourceChecks[j].Outcome
	})
	return usage, sourceChecks, nil
}

func presentationAnalysisUsage(raw string) (model.AnalysisUsage, bool) {
	var env struct {
		AnalysisUsage *model.AnalysisUsage `json:"analysis_usage"`
	}
	if json.Unmarshal([]byte(raw), &env) != nil || env.AnalysisUsage == nil || !env.AnalysisUsage.CallsKnown {
		return model.AnalysisUsage{}, false
	}
	return *env.AnalysisUsage, true
}

func presentationSourceChecks(raw string) []model.SourceCheck {
	var env struct {
		Metrics *struct {
			Outcome              string            `json:"outcome"`
			Snapshots            []json.RawMessage `json:"snapshots"`
			Note                 string            `json:"note"`
			RequestAttempts      int               `json:"request_attempts"`
			RequestAttemptsKnown bool              `json:"request_attempts_known"`
		} `json:"metrics"`
		Logs *struct {
			Source               string            `json:"source"`
			Outcome              string            `json:"outcome"`
			Lines                []json.RawMessage `json:"lines"`
			Note                 string            `json:"note"`
			RequestAttempts      int               `json:"request_attempts"`
			RequestAttemptsKnown bool              `json:"request_attempts_known"`
		} `json:"logs"`
		Changes *struct {
			Outcome string            `json:"outcome"`
			Changes []json.RawMessage `json:"changes"`
			Events  []json.RawMessage `json:"events"`
			Note    string            `json:"note"`
		} `json:"changes"`
		Sentry *struct {
			Outcome              string            `json:"outcome"`
			Issues               []json.RawMessage `json:"issues"`
			Note                 string            `json:"note"`
			RequestAttempts      int               `json:"request_attempts"`
			RequestAttemptsKnown bool              `json:"request_attempts_known"`
		} `json:"sentry"`
		Zabbix *struct {
			Outcome              string          `json:"outcome"`
			Note                 string          `json:"note"`
			Operator             json.RawMessage `json:"operator"`
			Topology             json.RawMessage `json:"topology"`
			Problem              json.RawMessage `json:"problem"`
			RequestAttempts      int             `json:"request_attempts"`
			RequestAttemptsKnown bool            `json:"request_attempts_known"`
		} `json:"zabbix"`
		Verification *struct {
			Rounds []struct {
				Queries []struct {
					Kind                 string `json:"kind"`
					Why                  string `json:"why"`
					Outcome              string `json:"outcome"`
					Result               string `json:"result"`
					RequestAttempts      int    `json:"request_attempts"`
					RequestAttemptsKnown bool   `json:"request_attempts_known"`
				} `json:"queries"`
			} `json:"rounds"`
		} `json:"verification"`
	}
	if json.Unmarshal([]byte(raw), &env) != nil {
		return nil
	}
	var out []model.SourceCheck
	if env.Metrics != nil {
		check := countedSourceCheck("Prometheus", "snapshots", env.Metrics.Outcome, len(env.Metrics.Snapshots))
		check.Calls, check.CallsKnown = env.Metrics.RequestAttempts, env.Metrics.RequestAttemptsKnown
		check.Detail = boundedSourceDetail(env.Metrics.Note)
		out = append(out, check)
	}
	if env.Logs != nil {
		source := strings.TrimSpace(env.Logs.Source)
		if source == "" {
			source = "Loki"
		} else {
			source = displaySource(source)
		}
		check := countedSourceCheck(source, "lines", env.Logs.Outcome, len(env.Logs.Lines))
		check.Calls, check.CallsKnown = env.Logs.RequestAttempts, env.Logs.RequestAttemptsKnown
		check.Detail = boundedSourceDetail(env.Logs.Note)
		out = append(out, check)
	}
	if env.Changes != nil {
		check := countedSourceCheck("Changes", "records", env.Changes.Outcome, len(env.Changes.Changes)+len(env.Changes.Events))
		check.Calls, check.CallsKnown = 1, true // one durable local ChangesInWindow query, never HTTP
		check.Detail = boundedSourceDetail(env.Changes.Note)
		out = append(out, check)
	}
	if env.Sentry != nil {
		outcome := env.Sentry.Outcome
		if outcome == "ok" {
			if len(env.Sentry.Issues) == 0 {
				outcome = "empty"
			} else {
				outcome = "fetched"
			}
		}
		check := countedSourceCheck("Sentry", "issues", outcome, len(env.Sentry.Issues))
		check.Calls, check.CallsKnown = env.Sentry.RequestAttempts, env.Sentry.RequestAttemptsKnown
		check.Detail = boundedSourceDetail(env.Sentry.Note)
		out = append(out, check)
	}
	if env.Zabbix != nil {
		records := 0
		for _, raw := range []json.RawMessage{env.Zabbix.Operator, env.Zabbix.Topology, env.Zabbix.Problem} {
			if len(raw) > 0 && string(raw) != "null" {
				records++
			}
		}
		check := countedSourceCheck("Zabbix", "records", env.Zabbix.Outcome, records)
		check.Calls, check.CallsKnown = env.Zabbix.RequestAttempts, env.Zabbix.RequestAttemptsKnown
		check.Detail = boundedSourceDetail(env.Zabbix.Note)
		out = append(out, check)
	}
	if env.Verification != nil {
		for _, round := range env.Verification.Rounds {
			for _, q := range round.Queries {
				check := strings.Join(strings.Fields(q.Why), " ")
				if check == "" {
					check = q.Kind
				}
				if check == "" {
					check = "verification"
				}
				source := "Verification"
				if q.Kind == "promql" || q.Kind == "up_ratio" {
					source = "Prometheus"
				}
				if strings.Contains(q.Kind, "zabbix") {
					source = "Zabbix"
				}
				calls, callsKnown := q.RequestAttempts, q.RequestAttemptsKnown
				detail := boundedSourceDetail(q.Result)
				out = append(out, model.SourceCheck{Source: source, Check: check, Outcome: sourceOutcome(q.Outcome), Calls: calls, CallsKnown: callsKnown, Detail: detail})
			}
		}
	}
	return out
}

func boundedSourceDetail(detail string) string {
	detail = strings.Join(strings.Fields(detail), " ")
	if len(detail) > 500 {
		return "Recorded source detail is available via MCP."
	}
	return detail
}

func countedSourceCheck(source, unit, outcome string, records int) model.SourceCheck {
	result := model.SourceCheck{Source: source, Check: "collection", Unit: unit, Outcome: sourceOutcome(outcome)}
	switch outcome {
	case "fetched", "empty":
		result.Records, result.RecordsKnown = records, true
	case "no_selector", "skipped", "disabled":
		result.CallsKnown, result.RecordsKnown = true, true
	}
	return result
}

func sourceOutcome(outcome string) model.SourceCheckOutcome {
	switch outcome {
	case "fetched":
		return model.SourceCheckReturned
	case "empty":
		return model.SourceCheckEmpty
	case "no_selector", "skipped", "disabled":
		return model.SourceCheckSkipped
	case "failed", "invalid", "degraded":
		return model.SourceCheckFailed
	default:
		return model.SourceCheckConfigured
	}
}

func displaySource(source string) string {
	if strings.EqualFold(source, "loki") {
		return "Loki"
	}
	return strings.Join(strings.Fields(source), " ")
}
