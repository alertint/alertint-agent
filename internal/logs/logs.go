// SPDX-License-Identifier: FSL-1.1-ALv2

// Package logs defines the provider-agnostic log-source abstraction the
// acute-triage skill uses to enrich a triage prompt with recent log lines,
// and that the MCP server uses to expose a native-query passthrough.
//
// The enrichment path and the MCP handlers depend ONLY on this package: they
// know nothing about Loki or any other backend. Concrete backends live in
// subpackages (internal/logs/loki) and implement Source. This package imports
// no backend and renders no query string — translating the generic Selector
// into a native query (LogQL, ES-DSL, …) is each provider's job.
package logs

import (
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"
)

// Source is a read-only log backend. It exposes only what a backend uniquely
// does: fetch-for-enrichment and native-query passthrough. Generic tunables
// (look-back window, line limit) are passed in by the caller from config —
// they are deliberately NOT methods here, so each new provider implements
// three methods, not five.
type Source interface {
	// Name returns the provider name, e.g. "loki". Used in prompt labels, the
	// MCP tool name/description, and health/status entries.
	Name() string

	// FetchRecent powers prompt enrichment. The provider translates the
	// generic Selector into its own native query, fetches up to limit lines
	// (newest within [start, end]), and returns them alongside the native
	// query string it executed. The caller passes start/end/limit from generic
	// config, applies Normalize to the lines, and persists Query verbatim in
	// the snapshot — the generic layer never parses Query, it only stores and
	// logs it. On the filtered-then-fallback path Query is whichever pass
	// produced the lines. A nil/empty result with a nil error means "queried
	// but nothing matched" (or no selector survived translation).
	FetchRecent(ctx context.Context, sel Selector, start, end time.Time, limit int) (Fetched, error)

	// QueryRange powers MCP passthrough using the provider's native query
	// language (LogQL for Loki). It returns the raw provider "data" payload.
	// There is no QueryInstant: for logs, range subsumes instant — a range log
	// query returns the lines an instant query would, plus surrounding context.
	QueryRange(ctx context.Context, query string, start, end time.Time, limit int, dir string) (json.RawMessage, error)
}

// Line is a single normalized log line with its timestamp.
type Line struct {
	Timestamp time.Time `json:"timestamp"`
	Line      string    `json:"line"`
}

// Fetched is the result of FetchRecent: the lines plus the provider's native
// query string. Query is opaque to the generic layer — persisted and logged,
// never parsed. Keeping it here is what lets the snapshot replay exactly what
// ran and the empty-result breadcrumb name the real query.
type Fetched struct {
	Lines []Line
	Query string // e.g. `{namespace="prod",app="api"} |~ "(?i)(error|…)"`
}

// Selector is provider-agnostic: it carries the incident's ALERT labels
// (Alertmanager vocabulary), already filtered to AllowedSelectorKeys. Each key
// maps to the set of DISTINCT values that key takes across the incident's member
// alerts — one value for a homogeneous incident, several for a correlated
// multi-service one (e.g. {"service":{"api","db-proxy"}}). Only keys present on
// EVERY member are carried, so a provider AND-combining them never over-constrains
// a member's stream out. Each Source translates it into its own native query,
// rendering a multi-value key as a regex alternation.
type Selector struct {
	Labels map[string][]string // e.g. {"namespace":{"prod"},"service":{"api","db-proxy"}}
}

// AllowedSelectorKeys is the generic allowlist of alert-label keys that
// plausibly identify a log stream across ANY backend. The skill intersects an
// incident's shared labels with this set to drop alert-metadata noise
// (alertname, severity, prometheus, …) that no log backend labels streams by.
// Per-backend renaming/dropping to a real stream-label schema is the
// provider's job (e.g. loki.label_map), NOT this layer's.
var AllowedSelectorKeys = []string{"namespace", "service", "job", "pod", "container", "instance"}

// Default normalization caps. Internal constants (not config in v1): each line
// is truncated to MaxLineChars characters, and the running byte total is capped
// at MaxBytes. With these values only ~16 of up to 50 lines survive, so
// truncation is the norm — which is why Normalize drops the oldest, not the
// newest (see Normalize).
const (
	MaxLineChars = 500
	MaxBytes     = 8192
)

// Normalize truncates each line to lineMaxChars characters and drops lines once
// the running byte total exceeds maxBytes. It preserves input order and drops
// from the TAIL: given the newest-first order FetchRecent guarantees, the
// dropped lines are the OLDEST, so the lines nearest the incident always
// survive. The single newest line is always kept, even if it alone exceeds the
// byte cap, so an enrichment is never emptied by one oversized line. Applied by
// the caller after FetchRecent.
func Normalize(in []Line, maxBytes, lineMaxChars int) []Line {
	if len(in) == 0 {
		return nil
	}
	out := make([]Line, 0, len(in))
	total := 0
	for i, ln := range in {
		text := truncateRunes(ln.Line, lineMaxChars)
		// Always keep the first (newest) line; otherwise stop as soon as adding
		// this line would push the running total past the byte cap.
		if i > 0 && total+len(text) > maxBytes {
			break
		}
		total += len(text)
		out = append(out, Line{Timestamp: ln.Timestamp, Line: text})
	}
	return out
}

// truncateRunes returns the first limit runes of s (so multi-byte characters are
// never split). limit <= 0 leaves s unchanged.
func truncateRunes(s string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}
