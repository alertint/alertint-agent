// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound marks a lookup whose identity resolved to nothing (no such
// host/item/trigger). Callers distinguish "identity wrong" from transport
// failure with errors.Is.
var ErrNotFound = errors.New("not found")

// HostGroupInfo is one host group with its size — the ranking input for the
// verification floor's smallest-groups-first scope discipline (ADR-0034).
type HostGroupInfo struct {
	GroupID string
	Name    string
	Hosts   int
}

// Series is a normalized metric time series. Source is "history" or "trends" —
// which store answered (ADR-0032: the retention fallback is visible, never
// silent).
type Series struct {
	ItemID string        `json:"itemid"`
	Name   string        `json:"name"`
	Units  string        `json:"units"`
	Source string        `json:"source"` // "history" | "trends"
	Points []SeriesPoint `json:"points"`
}

type SeriesPoint struct {
	Clock time.Time `json:"clock"`
	Value string    `json:"value"`         // history value, or trend avg
	Min   string    `json:"min,omitempty"` // trends only
	Max   string    `json:"max,omitempty"` // trends only
}

// ProblemSelector filters OpenProblems. SeverityMin "" means no floor.
type ProblemSelector struct {
	SeverityMin string // numeric "0".."5"
}

// Problem is one open problem (problem.get).
type Problem struct {
	EventID    string    `json:"eventid"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"` // numeric 0..5
	Clock      time.Time `json:"clock"`
	Acked      bool      `json:"acked"`
	Suppressed bool      `json:"suppressed"`
	Tags       []KV      `json:"tags,omitempty"`
}

type KV struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// ProblemHistoryRow is one normalized trigger-problem lifecycle returned by
// event.get. Source macro text remains text; only Unix clock/r_clock fields are
// admitted as canonical UTC instants.
type ProblemHistoryRow struct {
	EventID         string     `json:"event_id"`
	TriggerID       string     `json:"trigger_id"`
	Name            string     `json:"name"`
	StartedAt       time.Time  `json:"started_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	DurationSeconds int64      `json:"duration_seconds"`
	Ongoing         bool       `json:"ongoing"`
	Severity        string     `json:"severity"`
	Acknowledged    bool       `json:"acknowledged"`
	Suppressed      bool       `json:"suppressed"`
	Tags            []KV       `json:"tags,omitempty"`
	CauseEventID    string     `json:"cause_event_id,omitempty"`
	Truncated       bool       `json:"truncated,omitempty"`
}

// zItem is the item.get shape we read.
type zItem struct {
	ItemID    string `json:"itemid"`
	ValueType string `json:"value_type"` // 0 float,1 char,2 log,3 uint,4 text,5 binary
	Name      string `json:"name"`
	Units     string `json:"units"`
}

// Operator is the trigger-config knowledge (trigger.get + flap count).
type Operator struct {
	TriggerName  string       `json:"trigger_name"`
	Runbook      string       `json:"runbook,omitempty"` // trigger.comments; caller caps chars
	URL          string       `json:"url,omitempty"`
	Expression   string       `json:"expression,omitempty"`
	Severity     string       `json:"severity"`
	Dependencies []DepTrigger `json:"dependencies,omitempty"` // upstream/root-cause triggers
	Tags         []KV         `json:"tags,omitempty"`
}

type DepTrigger struct {
	TriggerID string `json:"triggerid"`
	Name      string `json:"name"`
}

// ProblemDetail is the problem.get detail (severity, duration, ack, suppression).
type ProblemDetail struct {
	Severity     string      `json:"severity"`
	StartedAt    time.Time   `json:"started_at"`
	Ongoing      bool        `json:"ongoing"`
	DurationSecs int64       `json:"duration_secs,omitempty"`
	Tags         []KV        `json:"tags,omitempty"`
	Acknowledges []AckEntry  `json:"acknowledges,omitempty"`
	Suppression  Suppression `json:"suppression"`
	OpData       string      `json:"opdata,omitempty"`
	CauseEventID string      `json:"cause_eventid,omitempty"` // "0"/"" = is itself a cause
}

type AckEntry struct {
	At           time.Time `json:"at"`
	User         string    `json:"user,omitempty"`
	Message      string    `json:"message,omitempty"`
	Acknowledged bool      `json:"acknowledged"` // action bit 2
}

// Suppression.Kind is "none" | "maintenance" | "manual".
type Suppression struct {
	Kind  string    `json:"kind"`
	Until time.Time `json:"until,omitempty"`
}

// Topology is the CMDB/host layer (host.get).
type Topology struct {
	VisibleName       string            `json:"visible_name,omitempty"`
	Description       string            `json:"description,omitempty"`
	Inventory         map[string]string `json:"inventory,omitempty"` // curated subset (inventoryFields)
	Templates         []string          `json:"templates,omitempty"`
	Groups            []string          `json:"groups,omitempty"` // host groups (selectHostGroups — never the deprecated selectGroups)
	MaintenanceActive bool              `json:"maintenance_active"`
	Interfaces        []IfaceState      `json:"interfaces,omitempty"`
}

type IfaceState struct {
	Addr      string `json:"addr"`
	Available string `json:"available"` // 0 unknown, 1 available, 2 unavailable
	Error     string `json:"error,omitempty"`
}

// inventoryFields is the curated high-signal inventory subset (ADR-0032 —
// never the full ~70 fields).
var inventoryFields = []string{
	"poc_1_name", "poc_1_email", "contact", "location", "os", "os_full",
	"hardware", "site_rack", "notes",
}

// flexInventory decodes host.get's inventory field, which is an object when
// inventory is populated but an empty JSON array ([]) when host inventory is
// disabled for that host — a documented Zabbix API quirk. Either shape decodes
// to a possibly-empty map, so HostContext never fails on inventory-disabled hosts.
type flexInventory map[string]string

func (m *flexInventory) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		*m = flexInventory{}
		return nil
	}
	var v map[string]string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*m = v
	return nil
}

// Acknowledge action bitmask (corrected — the 7.0 doc misprints ack as 6; its
// own "34 = ack + suppress" example proves 34 = 32 + 2). Bits: 1 close · 2 ack ·
// 4 message · 8 severity · 16 unack · 32 suppress · 64 unsuppress · 128 cause ·
// 256 symptom.
const ackActionAcknowledge = 1 << 1
