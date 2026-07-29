// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ZabbixEvent is the webhook contract AlertINT owns (ADR-0031): a small fixed
// JSON object the Zabbix media-type JS template builds from macros and POSTs
// to /webhook/zabbix. All mapping intelligence lives here, in tested Go; the
// template is a thin macro-forwarder (docs/integrations/zabbix.md).
type ZabbixEvent struct {
	EventID       string      `json:"event_id"`     // {EVENT.ID} — stable across PROBLEM→RESOLVED
	Status        string      `json:"status"`       // "PROBLEM" | "RESOLVED"
	Severity      string      `json:"severity"`     // {EVENT.SEVERITY} display name (per-install renameable)
	NSeverity     string      `json:"nseverity"`    // {EVENT.NSEVERITY} numeric 0..5 (stable)
	Host          string      `json:"host"`         // {HOST.HOST} technical name — the API lookup key
	HostVisible   string      `json:"host_visible"` // {HOST.NAME} display only
	TriggerID     string      `json:"trigger_id"`
	TriggerName   string      `json:"trigger_name"`
	ItemKey       string      `json:"item_key"`
	ItemValue     string      `json:"item_value"`
	Tags          []ZabbixTag `json:"tags"`           // {EVENT.TAGSJSON}, emitted unquoted by the template
	Clock         string      `json:"clock"`          // display only — never parsed (ADR-0031)
	RecoveryClock string      `json:"recovery_clock"` // display only — never parsed
	GeneratorURL  string      `json:"generator_url"`
}

// ZabbixTag is one {tag,value} entry from {EVENT.TAGSJSON}.
type ZabbixTag struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// ParseZabbix decodes and validates a Zabbix webhook body. Pure: no clock, no
// persistence (the ParseAlertmanager split). A returned error maps to HTTP 400.
func ParseZabbix(body []byte) (ZabbixEvent, error) {
	var ev ZabbixEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return ZabbixEvent{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if strings.TrimSpace(ev.EventID) == "" {
		return ZabbixEvent{}, fmt.Errorf("zabbix: event_id is required")
	}
	switch ev.Status {
	case "PROBLEM", "RESOLVED":
	default:
		return ZabbixEvent{}, fmt.Errorf("zabbix: status %q must be PROBLEM or RESOLVED", ev.Status)
	}
	if strings.TrimSpace(ev.Host) == "" {
		return ZabbixEvent{}, fmt.Errorf("zabbix: host is required")
	}
	if strings.TrimSpace(ev.TriggerName) == "" {
		return ZabbixEvent{}, fmt.Errorf("zabbix: trigger_name is required")
	}
	return ev, nil
}
