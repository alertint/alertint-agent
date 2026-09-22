// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

const serverInstructions = `Investigate from the Situation reference. Start with alertint_get_situation, then read recorded history with alertint_list_situation_transitions and the relevant judgment or expected-schedule history. Inspect member Incidents and persisted evidence before making a causal claim. Treat captured evidence as historical; use configured query tools with explicit scope and time only when current data is needed. Never infer a past rule version, transition reason, recovery, or source result from current configuration.

Keep expectedness separate from lifecycle and source-owned recovery. Summarize with Finding / Evidence / Now / Next, citing record IDs and times. If the records do not support a Finding, say "Finding: Insufficient evidence —" and name the specific missing or failed evidence. Next is AlertINT's recorded automatic action or deadline, not a proposed investigation.

Tool annotations are client hints, not authorization. Read tools may query configured external sources. Any note, verdict, judgment, schedule, or semantic-profile write requires explicit operator authorization; preserve each tool's confirmation and version checks.`

type toolBehavior struct {
	readOnly    bool
	destructive bool
	idempotent  bool
	openWorld   bool
}

var localReadTools = map[string]struct{}{
	"alertint_list_incidents":                   {},
	"alertint_get_incident":                     {},
	"alertint_search_alerts":                    {},
	"alertint_get_evidence_pack":                {},
	"alertint_verify_audit":                     {},
	"alertint_usage_stats":                      {},
	"alertint_list_situations":                  {},
	"alertint_get_situation":                    {},
	"alertint_list_situation_transitions":       {},
	"alertint_get_delivery_state":               {},
	"alertint_list_situation_judgments":         {},
	"alertint_get_expected_behavior_validation": {},
	"alertint_get_expected_behavior":            {},
	"alertint_list_expected_behaviors":          {},
	"alertint_list_expected_behavior_history":   {},
	"alertint_list_observation_runs":            {},
	"alertint_get_semantic_profile":             {},
	"alertint_recent_changes":                   {},
}

var externalReadTools = map[string]struct{}{
	"prometheus_query":       {},
	"prometheus_query_range": {},
	"sentry_issues_list":     {},
	"sentry_issues_trace":    {},
	"zabbix_metric_history":  {},
	"zabbix_host_problems":   {},
}

var writeToolBehavior = map[string]toolBehavior{
	"alertint_incident_annotate":          {idempotent: false},
	"alertint_incident_capture_verdict":   {destructive: true, idempotent: false, openWorld: true},
	"alertint_record_situation_expected":  {idempotent: true},
	"alertint_replace_situation_expected": {destructive: true, idempotent: true},
	"alertint_revoke_situation_expected":  {destructive: true, idempotent: true},
	"alertint_restore_situation_expected": {idempotent: true},
	"alertint_expected_behavior_prepare":  {idempotent: false, openWorld: true},
	"alertint_expected_behavior_confirm":  {idempotent: true},
	"alertint_expected_behavior_replace":  {destructive: true, idempotent: true},
	"alertint_expected_behavior_revoke":   {destructive: true, idempotent: true},
	"alertint_expected_behavior_restore":  {idempotent: true},
	"alertint_correct_semantic_profile":   {destructive: true, idempotent: true},
}

func newTool(name string, opts ...mcplib.ToolOption) mcplib.Tool {
	tool := mcplib.NewTool(name, opts...)
	behavior, ok := toolBehaviorFor(name)
	if !ok {
		panic("mcp: missing protocol metadata for tool " + name)
	}
	title := strings.ReplaceAll(name, "_", " ")
	if strings.HasPrefix(title, "alertint ") {
		title = "AlertINT " + strings.TrimPrefix(title, "alertint ")
	} else if title != "" {
		title = strings.ToUpper(title[:1]) + title[1:]
	}
	tool.Annotations = mcplib.ToolAnnotation{
		Title:           title,
		ReadOnlyHint:    mcplib.ToBoolPtr(behavior.readOnly),
		DestructiveHint: mcplib.ToBoolPtr(behavior.destructive),
		IdempotentHint:  mcplib.ToBoolPtr(behavior.idempotent),
		OpenWorldHint:   mcplib.ToBoolPtr(behavior.openWorld),
	}
	return tool
}

func toolBehaviorFor(name string) (toolBehavior, bool) {
	if _, ok := localReadTools[name]; ok {
		return toolBehavior{readOnly: true, idempotent: true}, true
	}
	if _, ok := externalReadTools[name]; ok {
		return toolBehavior{readOnly: true, idempotent: true, openWorld: true}, true
	}
	if strings.HasSuffix(name, "_query_range") {
		return toolBehavior{readOnly: true, idempotent: true, openWorld: true}, true
	}
	behavior, ok := writeToolBehavior[name]
	return behavior, ok
}
