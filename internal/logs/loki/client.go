// SPDX-License-Identifier: FSL-1.1-ALv2

// Package loki provides a read-only client for the Grafana Loki HTTP API v1,
// implementing logs.Source. It covers both self-hosted Loki and Grafana Cloud
// Logs (same backend, different auth). Modeled on internal/prometheus: GET-only,
// envelope unwrap {status,data}, configurable timeout. The client never writes,
// tails, or streams.
//
// This package owns all translation from the provider-agnostic logs.Selector
// into LogQL: it renames/drops alert-label keys to stream-label keys via
// label_map, AND-combines the survivors into a {k="v",…} matcher, and appends
// the configured line_filter. internal/logs imports no Loki concept.
package loki

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
)

// Client is a read-only Loki HTTP API v1 client implementing logs.Source.
type Client struct {
	baseURL    string
	httpClient *http.Client
	authHeader string
	orgID      string
	lineFilter string
	labelMap   map[string]string
}

// Config holds the values needed to construct a Client. The secret (bearer
// token or basic password) is resolved by the caller via config.LokiAuthSecret
// and passed in — the client never reads env vars.
type Config struct {
	BaseURL        string
	AuthMode       string // none | bearer | basic
	Username       string // basic mode: user/instance ID (not a secret)
	Secret         string // bearer token or basic password
	OrgID          string
	LineFilter     string
	LabelMap       map[string]string
	TimeoutSeconds int
}

// NewClient builds a Client from cfg. A zero TimeoutSeconds defaults to 10s.
// The HTTP client timeout bounds each individual request; the enrichment caller
// additionally wraps the context as the TOTAL budget across both fetch passes.
func NewClient(cfg Config) *Client {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	c := &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		httpClient: &http.Client{Timeout: timeout},
		orgID:      cfg.OrgID,
		lineFilter: cfg.LineFilter,
		labelMap:   cfg.LabelMap,
	}
	switch cfg.AuthMode {
	case "bearer":
		if cfg.Secret != "" {
			c.authHeader = "Bearer " + cfg.Secret
		}
	case "basic":
		raw := cfg.Username + ":" + cfg.Secret
		c.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
	}
	return c
}

// Name returns the provider name.
func (c *Client) Name() string { return "loki" }

// FetchRecent translates the selector into a LogQL matcher, runs the
// error-biased filtered query first, and falls back to one unfiltered query
// only when the filtered pass returns zero lines. The returned Fetched.Query is
// whichever query actually produced the lines. If no label survives translation
// it returns an empty Fetched with no error (the caller renders a note).
func (c *Client) FetchRecent(ctx context.Context, sel logs.Selector, start, end time.Time, limit int) (logs.Fetched, error) {
	matcher := c.buildMatcher(sel)
	if matcher == "" {
		return logs.Fetched{}, nil
	}

	// Filtered pass (error-biased) when a line_filter is configured.
	query := matcher
	if c.lineFilter != "" {
		query = matcher + " " + c.lineFilter
	}
	lines, err := c.queryRangeLines(ctx, query, start, end, limit)
	if err != nil {
		return logs.Fetched{Query: query}, err
	}
	if len(lines) > 0 || c.lineFilter == "" {
		return logs.Fetched{Lines: lines, Query: query}, nil
	}

	// Filtered pass was empty — one unfiltered fallback (matcher only) so apps
	// whose log format doesn't match the regex still get newest-N lines. Shares
	// the caller's single deadline; if it's already exhausted this errors out.
	fbLines, err := c.queryRangeLines(ctx, matcher, start, end, limit)
	if err != nil {
		return logs.Fetched{Query: matcher}, err
	}
	return logs.Fetched{Lines: fbLines, Query: matcher}, nil
}

// QueryRange powers the MCP passthrough: it returns the raw provider "data"
// payload for the given native LogQL query. dir defaults to "backward".
func (c *Client) QueryRange(ctx context.Context, query string, start, end time.Time, limit int, dir string) (json.RawMessage, error) {
	if dir == "" {
		dir = "backward"
	}
	params := url.Values{
		"query":     {query},
		"start":     {start.UTC().Format(time.RFC3339Nano)},
		"end":       {end.UTC().Format(time.RFC3339Nano)},
		"direction": {dir},
	}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	return c.apiGet(ctx, "/loki/api/v1/query_range", params)
}

// queryRangeLines runs a backward range query and decodes the streams result
// into a single newest-first slice of lines.
func (c *Client) queryRangeLines(ctx context.Context, query string, start, end time.Time, limit int) ([]logs.Line, error) {
	params := url.Values{
		"query":     {query},
		"start":     {start.UTC().Format(time.RFC3339Nano)},
		"end":       {end.UTC().Format(time.RFC3339Nano)},
		"direction": {"backward"},
	}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	data, err := c.apiGet(ctx, "/loki/api/v1/query_range", params)
	if err != nil {
		return nil, err
	}
	return parseStreams(data)
}

// buildMatcher translates the generic selector into a LogQL stream matcher.
// It applies label_map (rename, or drop on ""), AND-combines the survivors, and
// renders {k="v",…} with keys sorted for a deterministic query string. Returns
// "" when no label survives translation.
func (c *Client) buildMatcher(sel logs.Selector) string {
	translated := make(map[string]string, len(sel.Labels))
	for k, v := range sel.Labels {
		nk := k
		if c.labelMap != nil {
			if mapped, ok := c.labelMap[k]; ok {
				if mapped == "" {
					continue // explicit drop
				}
				nk = mapped
			}
		}
		if _, exists := translated[nk]; !exists {
			translated[nk] = v
		}
	}
	if len(translated) == 0 {
		return ""
	}
	keys := make([]string, 0, len(translated))
	for k := range translated {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, translated[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// apiGet issues a GET to path?params, sets auth and tenancy headers, unwraps the
// Loki envelope, and returns the raw data JSON on success.
func (c *Client) apiGet(ctx context.Context, path string, params url.Values) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}
	if c.orgID != "" {
		// Assigned directly (not via Set) to keep the exact Loki spelling on the
		// wire; HTTP header names are case-insensitive, but this matches docs.
		req.Header["X-Scope-OrgID"] = []string{c.orgID}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("loki: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki: query failed: http %d: %s", resp.StatusCode, snippet(body))
	}

	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("loki: decode response: %w", err)
	}
	if envelope.Status != "success" {
		return nil, fmt.Errorf("loki: query status %q", envelope.Status)
	}
	return envelope.Data, nil
}

// parseStreams decodes a Loki "streams" result and flattens every stream's
// values into one slice sorted newest-first. Loki bounds the set to the newest
// `limit` entries globally but lays them out grouped by stream, each stream
// independently ordered — so the cross-stream merge + sort here is mandatory.
func parseStreams(raw json.RawMessage) ([]logs.Line, error) {
	var d struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("loki: decode streams: %w", err)
	}
	var out []logs.Line
	for _, s := range d.Result {
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			ts, err := parseNanoEpoch(v[0])
			if err != nil {
				continue // skip malformed timestamps rather than fail the whole fetch
			}
			out = append(out, logs.Line{Timestamp: ts, Line: v[1]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp.After(out[j].Timestamp)
	})
	return out, nil
}

// parseNanoEpoch parses a nanosecond Unix epoch string into a UTC time.
func parseNanoEpoch(s string) (time.Time, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, n).UTC(), nil
}

// snippet returns a short, single-line excerpt of an error body for messages.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	const maxLen = 200
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
