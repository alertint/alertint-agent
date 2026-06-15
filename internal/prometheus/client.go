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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a read-only Prometheus HTTP API v1 client.
type Client struct {
	baseURL             string
	httpClient          *http.Client
	authHeader          string
	defaultRangeMinutes int
}

// Config holds the values needed to construct a Client.
type Config struct {
	BaseURL             string
	BearerToken         string // empty = no auth
	TimeoutSeconds      int
	DefaultRangeMinutes int
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
// The returned JSON is the raw "data" field from the Prometheus API response,
// i.e. {"resultType":"vector","result":[...]}.
func (c *Client) QueryInstant(ctx context.Context, expr string, t time.Time) (json.RawMessage, error) {
	params := url.Values{"query": {expr}}
	if !t.IsZero() {
		params.Set("time", formatTS(t))
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
		return nil, fmt.Errorf("prometheus %s: %s", envelope.ErrorType, envelope.Error)
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
