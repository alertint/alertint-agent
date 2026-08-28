// SPDX-License-Identifier: FSL-1.1-ALv2

// Package prometheus provides a read-only HTTP client for the Prometheus
// HTTP API v1. It is used by the MCP server to run PromQL queries on behalf
// of AI coding agents investigating incidents.
//
// Only GET requests are issued; the client never mutates Prometheus state.
package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is a read-only Prometheus HTTP API v1 client.
type Client struct {
	baseURL             string
	httpClient          *http.Client
	authHeader          string
	orgID               string
	defaultRangeMinutes int
}

// Config holds the values needed to construct a Client.
type Config struct {
	BaseURL             string
	BearerToken         string // empty = no auth
	OrgID               string // empty = no tenant header (multi-tenant Mimir/Cortex only)
	TimeoutSeconds      int
	DefaultRangeMinutes int
}

// APIError represents a structured Prometheus API error response.
type APIError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("prometheus %s: %s", e.Type, e.Message)
}

// IsInvalidQuery reports whether err is a bad_data APIError specifically
// indicating a malformed query parameter, as opposed to other parameter
// errors (limit, time) or non-bad_data failures.
func IsInvalidQuery(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Type != "bad_data" {
		return false
	}
	msg := strings.ToLower(apiErr.Message)
	queryParam := strings.Contains(msg, `parameter "query"`) ||
		strings.Contains(msg, "parameter 'query'") || strings.Contains(msg, "parameter query")
	if strings.Contains(msg, "parameter") {
		return queryParam // an explicitly named non-query parameter wins over generic parse wording
	}
	for _, marker := range []string{"parse error", "parse query", "parsing query", "invalid promql", "invalid query"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// NewClient builds a Client from cfg. A zero TimeoutSeconds defaults to 10s.
func NewClient(cfg Config) *Client {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	c := &Client{
		baseURL:             strings.TrimRight(cfg.BaseURL, "/"),
		httpClient:          &http.Client{Timeout: timeout},
		orgID:               cfg.OrgID,
		defaultRangeMinutes: cfg.DefaultRangeMinutes,
	}
	if cfg.BearerToken != "" {
		c.authHeader = "Bearer " + cfg.BearerToken
	}
	return c
}

// DefaultRangeMinutes returns the configured default look-back window.
func (c *Client) DefaultRangeMinutes() int { return c.defaultRangeMinutes }

// QueryInstant executes an instant PromQL query. A zero t is treated as "now".
// A positive limit bounds the number of series the server returns (the
// Prometheus API's optional "limit" param; 0 = unbounded). The returned JSON is
// the raw "data" field from the Prometheus API response, i.e.
// {"resultType":"vector","result":[...]}.
func (c *Client) QueryInstant(ctx context.Context, expr string, t time.Time, limit int) (json.RawMessage, error) {
	params := url.Values{"query": {expr}}
	if !t.IsZero() {
		params.Set("time", formatTS(t))
	}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	return c.apiGet(ctx, "/api/v1/query", params)
}

// QueryRange executes a range PromQL query. A zero step is auto-computed from
// the time range (30s–15m depending on width).
// The returned JSON is the raw "data" field: {"resultType":"matrix","result":[...]}.
func (c *Client) QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) (json.RawMessage, error) {
	params := url.Values{
		"query": {expr},
		"start": {formatTS(start)},
		"end":   {formatTS(end)},
		"step":  {autoStep(step, end.Sub(start))},
	}
	return c.apiGet(ctx, "/api/v1/query_range", params)
}

// apiGet issues a GET to path?params, unwraps the Prometheus envelope, and
// returns the raw data JSON on success or an error on API/network failure.
func (c *Client) apiGet(ctx context.Context, path string, params url.Values) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}
	if c.orgID != "" {
		// Assigned directly (not via Set) to keep the exact spelling on the
		// wire; HTTP header names are case-insensitive, but this matches the
		// Mimir/Cortex docs.
		req.Header["X-Scope-OrgID"] = []string{c.orgID}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("prometheus: read response: %w", err)
	}

	var envelope struct {
		Status    string          `json:"status"`
		Data      json.RawMessage `json:"data"`
		ErrorType string          `json:"errorType"`
		Error     string          `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("prometheus: decode response: %w", err)
	}
	if envelope.Status != "success" {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Type:       envelope.ErrorType,
			Message:    envelope.Error,
		}
	}
	return envelope.Data, nil
}

// formatTS formats t as a Unix timestamp with millisecond precision.
func formatTS(t time.Time) string {
	return fmt.Sprintf("%.3f", float64(t.UnixMilli())/1000)
}

// autoStep returns a step string suitable for range queries.
// If step > 0 the caller's value is used; otherwise it is derived from rangeWidth.
func autoStep(step time.Duration, rangeWidth time.Duration) string {
	if step > 0 {
		return fmt.Sprintf("%ds", int(step.Seconds()))
	}
	switch {
	case rangeWidth <= time.Hour:
		return "30s"
	case rangeWidth <= 6*time.Hour:
		return "2m"
	case rangeWidth <= 24*time.Hour:
		return "5m"
	default:
		return "15m"
	}
}
