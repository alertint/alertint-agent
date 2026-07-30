// SPDX-License-Identifier: FSL-1.1-ALv2

// Package zabbix is a read-only JSON-RPC client for the Zabbix 7.0 frontend
// API (api_jsonrpc.php). It issues only *.get methods (plus apiinfo.version):
// it never mutates Zabbix state (ADR-0032). Auth is the Authorization: Bearer
// header (not the legacy auth param, removed in 7.2).
package zabbix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BaseURL              string // Zabbix frontend; "/api_jsonrpc.php" is appended
	APIToken             string
	TimeoutSeconds       int
	HistoryRetentionDays int
	FlapWindowHours      int
}

type Client struct {
	endpoint         string
	httpClient       *http.Client
	authHeader       string
	historyRetention time.Duration
	flapWindow       time.Duration
}

func NewClient(cfg Config) *Client {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	hr := cfg.HistoryRetentionDays
	if hr <= 0 {
		hr = 7
	}
	fw := cfg.FlapWindowHours
	if fw <= 0 {
		fw = 24
	}
	return &Client{
		endpoint:         strings.TrimRight(cfg.BaseURL, "/") + "/api_jsonrpc.php",
		httpClient:       &http.Client{Timeout: timeout},
		authHeader:       "Bearer " + cfg.APIToken,
		historyRetention: time.Duration(hr) * 24 * time.Hour,
		flapWindow:       time.Duration(fw) * time.Hour,
	}
}

// FlapWindow exposes the configured flap look-back for callers computing "since".
func (c *Client) FlapWindow() time.Duration { return c.flapWindow }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
	ID      int    `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

// call issues one JSON-RPC method and unmarshals result into out. withAuth=false
// for apiinfo.version (which needs no token). A non-nil error object → Go error.
func (c *Client) call(ctx context.Context, method string, params any, withAuth bool, out any) error {
	if params == nil {
		params = map[string]any{}
	}
	reqBody, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json-rpc")
	if withAuth {
		req.Header.Set("Authorization", c.authHeader)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("zabbix request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("zabbix: read response: %w", err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("zabbix: decode response: %w", err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("zabbix %s: %s (%s)", method, envelope.Error.Message, envelope.Error.Data)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, out)
}

// APIVersion returns the frontend version via apiinfo.version (no auth
// required). Used as the health probe.
func (c *Client) APIVersion(ctx context.Context) (string, error) {
	var v string
	if err := c.call(ctx, "apiinfo.version", []any{}, false, &v); err != nil {
		return "", err
	}
	return v, nil
}

// resolveItem looks up an item's id + value_type by host (technical name) + key.
func (c *Client) resolveItem(ctx context.Context, host, key string) (zItem, error) {
	var items []zItem
	err := c.call(ctx, "item.get", map[string]any{
		"output": []string{"itemid", "value_type", "name", "units"},
		"host":   host,
		"search": map[string]string{"key_": key},
		"limit":  1,
	}, true, &items)
	if err != nil {
		return zItem{}, err
	}
	if len(items) == 0 {
		return zItem{}, fmt.Errorf("zabbix: no item matching host=%q key=%q", host, key)
	}
	return items[0], nil
}

// MetricHistory returns a normalized series for host+itemKey over [from,to].
// It resolves the item's value_type first (history.get silently returns empty
// for floats under the default history=3) and falls back to trends for windows
// older than the configured history retention.
func (c *Client) MetricHistory(ctx context.Context, host, itemKey string, from, to time.Time, limit int) (Series, error) {
	item, err := c.resolveItem(ctx, host, itemKey)
	if err != nil {
		return Series{}, err
	}
	if time.Since(from) > c.historyRetention {
		var rows []struct {
			Clock    string `json:"clock"`
			ValueAvg string `json:"value_avg"`
			ValueMin string `json:"value_min"`
			ValueMax string `json:"value_max"`
		}
		if err := c.call(ctx, "trend.get", map[string]any{
			"output":    "extend",
			"itemids":   item.ItemID,
			"time_from": from.Unix(),
			"time_till": to.Unix(),
			"limit":     limit,
		}, true, &rows); err != nil {
			return Series{}, err
		}
		pts := make([]SeriesPoint, 0, len(rows))
		for _, r := range rows {
			pts = append(pts, SeriesPoint{Clock: unixStr(r.Clock), Value: r.ValueAvg, Min: r.ValueMin, Max: r.ValueMax})
		}
		return Series{ItemID: item.ItemID, Name: item.Name, Units: item.Units, Source: "trends", Points: pts}, nil
	}

	var rows []struct {
		Clock string `json:"clock"`
		Value string `json:"value"`
	}
	if err := c.call(ctx, "history.get", map[string]any{
		"output":    "extend",
		"history":   item.ValueType, // the fix: resolved type, not default 3
		"itemids":   item.ItemID,
		"time_from": from.Unix(),
		"time_till": to.Unix(),
		"sortfield": "clock",
		"sortorder": "DESC",
		"limit":     limit,
	}, true, &rows); err != nil {
		return Series{}, err
	}
	pts := make([]SeriesPoint, 0, len(rows))
	for _, r := range rows {
		pts = append(pts, SeriesPoint{Clock: unixStr(r.Clock), Value: r.Value})
	}
	return Series{ItemID: item.ItemID, Name: item.Name, Units: item.Units, Source: "history", Points: pts}, nil
}

// OpenProblems lists currently-open problems on a host.
func (c *Client) OpenProblems(ctx context.Context, host string, sel ProblemSelector) ([]Problem, error) {
	hostids, err := c.hostIDs(ctx, host)
	if err != nil {
		return nil, err
	}
	params := map[string]any{
		"output":     "extend",
		"selectTags": "extend",
		"hostids":    hostids,
		"recent":     false,
		"sortfield":  []string{"eventid"},
		"sortorder":  "DESC",
	}
	if sel.SeverityMin != "" {
		params["severities"] = severitiesFrom(sel.SeverityMin)
	}
	var rows []struct {
		EventID      string `json:"eventid"`
		Name         string `json:"name"`
		Severity     string `json:"severity"`
		Clock        string `json:"clock"`
		Acknowledged string `json:"acknowledged"`
		Suppressed   string `json:"suppressed"`
		Tags         []KV   `json:"tags"`
	}
	if err := c.call(ctx, "problem.get", params, true, &rows); err != nil {
		return nil, err
	}
	out := make([]Problem, 0, len(rows))
	for _, r := range rows {
		out = append(out, Problem{
			EventID: r.EventID, Name: r.Name, Severity: r.Severity, Clock: unixStr(r.Clock),
			Acked: r.Acknowledged == "1", Suppressed: r.Suppressed == "1", Tags: r.Tags,
		})
	}
	return out, nil
}

// hostIDs resolves a technical host name to its hostid(s).
func (c *Client) hostIDs(ctx context.Context, host string) ([]string, error) {
	var hosts []struct {
		HostID string `json:"hostid"`
	}
	if err := c.call(ctx, "host.get", map[string]any{
		"output": []string{"hostid"},
		"filter": map[string][]string{"host": {host}},
	}, true, &hosts); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ids = append(ids, h.HostID)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("zabbix: no host matching %q", host)
	}
	return ids, nil
}

func unixStr(s string) time.Time {
	n, _ := strconv.ParseInt(s, 10, 64)
	return time.Unix(n, 0).UTC()
}

// severitiesFrom returns the list of numeric severities >= min (0..5).
func severitiesFrom(min string) []int {
	lo, _ := strconv.Atoi(min)
	var out []int
	for s := lo; s <= 5; s++ {
		out = append(out, s)
	}
	return out
}
