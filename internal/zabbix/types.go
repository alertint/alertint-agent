// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix

import "time"

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

// zItem is the item.get shape we read.
type zItem struct {
	ItemID    string `json:"itemid"`
	ValueType string `json:"value_type"` // 0 float,1 char,2 log,3 uint,4 text,5 binary
	Name      string `json:"name"`
	Units     string `json:"units"`
}
