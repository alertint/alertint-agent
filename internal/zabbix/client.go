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
func severitiesFrom(minSev string) []int {
	lo, _ := strconv.Atoi(minSev)
	var out []int
	for s := lo; s <= 5; s++ {
		out = append(out, s)
	}
	return out
}

// TriggerContext reads the operator knowledge baked into a trigger.
func (c *Client) TriggerContext(ctx context.Context, triggerID string) (Operator, error) {
	var rows []struct {
		Description  string `json:"description"` // trigger NAME
		Comments     string `json:"comments"`    // runbook text
		URL          string `json:"url"`
		Expression   string `json:"expression"`
		Priority     string `json:"priority"` // severity 0..5
		Dependencies []struct {
			TriggerID   string `json:"triggerid"`
			Description string `json:"description"`
		} `json:"dependencies"`
		Tags []KV `json:"tags"`
	}
	err := c.call(ctx, "trigger.get", map[string]any{
		"output":             []string{"description", "comments", "url", "expression", "priority"},
		"triggerids":         triggerID,
		"selectDependencies": []string{"triggerid", "description"},
		"selectTags":         "extend",
	}, true, &rows)
	if err != nil {
		return Operator{}, err
	}
	if len(rows) == 0 {
		return Operator{}, fmt.Errorf("zabbix: no trigger %q", triggerID)
	}
	r := rows[0]
	op := Operator{
		TriggerName: r.Description, Runbook: r.Comments, URL: r.URL,
		Expression: r.Expression, Severity: r.Priority, Tags: r.Tags,
	}
	for _, d := range r.Dependencies {
		op.Dependencies = append(op.Dependencies, DepTrigger{TriggerID: d.TriggerID, Name: d.Description})
	}
	return op, nil
}

// suppressionRow is the selectSuppressionData shape.
type suppressionRow struct {
	MaintenanceID string `json:"maintenanceid"`
	UserID        string `json:"userid"`
	SuppressUntil string `json:"suppress_until"`
}

// ProblemContext reads a problem's detail, decoding ack history and suppression cause.
func (c *Client) ProblemContext(ctx context.Context, eventID string) (ProblemDetail, error) {
	var rows []struct {
		Severity     string `json:"severity"`
		Clock        string `json:"clock"`
		RClock       string `json:"r_clock"`
		OpData       string `json:"opdata"`
		CauseEventID string `json:"cause_eventid"`
		Tags         []KV   `json:"tags"`
		Acknowledges []struct {
			Clock    string `json:"clock"`
			Message  string `json:"message"`
			Action   string `json:"action"`
			Username string `json:"username"`
		} `json:"acknowledges"`
		Suppression []suppressionRow `json:"suppression_data"`
	}
	err := c.call(ctx, "problem.get", map[string]any{
		"output":                "extend",
		"eventids":              eventID,
		"selectTags":            "extend",
		"selectAcknowledges":    "extend",
		"selectSuppressionData": "extend",
	}, true, &rows)
	if err != nil {
		return ProblemDetail{}, err
	}
	if len(rows) == 0 {
		return ProblemDetail{}, fmt.Errorf("zabbix: no problem event %q", eventID)
	}
	r := rows[0]
	pd := ProblemDetail{Severity: r.Severity, StartedAt: unixStr(r.Clock), Tags: r.Tags, OpData: r.OpData}
	if r.CauseEventID != "" && r.CauseEventID != "0" {
		pd.CauseEventID = r.CauseEventID
	}
	if r.RClock == "0" || r.RClock == "" {
		pd.Ongoing = true
	} else {
		pd.DurationSecs = unixStr(r.RClock).Unix() - unixStr(r.Clock).Unix()
	}
	for _, a := range r.Acknowledges {
		action, _ := strconv.Atoi(a.Action)
		pd.Acknowledges = append(pd.Acknowledges, AckEntry{
			At: unixStr(a.Clock), User: a.Username, Message: a.Message,
			Acknowledged: action&ackActionAcknowledge != 0,
		})
	}
	pd.Suppression = decodeSuppression(r.Suppression)
	return pd, nil
}

func decodeSuppression(data []suppressionRow) Suppression {
	for _, s := range data {
		if s.MaintenanceID != "" && s.MaintenanceID != "0" {
			return Suppression{Kind: "maintenance", Until: unixStr(s.SuppressUntil)}
		}
		if s.UserID != "" && s.UserID != "0" {
			return Suppression{Kind: "manual", Until: unixStr(s.SuppressUntil)}
		}
	}
	return Suppression{Kind: "none"}
}

// HostContext reads the CMDB/topology layer (selectHostGroups, not the
// deprecated selectGroups; live maintenance from maintenance_status —
// host-level `available` is gone in 7.0, reachability is per-interface).
func (c *Client) HostContext(ctx context.Context, host string) (Topology, error) {
	var rows []struct {
		Name              string        `json:"name"`
		Description       string        `json:"description"`
		MaintenanceStatus string        `json:"maintenance_status"`
		Inventory         flexInventory `json:"inventory"`
		HostGroups        []struct {
			Name string `json:"name"`
		} `json:"hostgroups"`
		ParentTemplates []struct {
			Name string `json:"name"`
		} `json:"parentTemplates"`
		Interfaces []struct {
			IP        string `json:"ip"`
			DNS       string `json:"dns"`
			Available string `json:"available"`
			Error     string `json:"error"`
		} `json:"interfaces"`
	}
	err := c.call(ctx, "host.get", map[string]any{
		"output":                []string{"name", "description", "maintenance_status"},
		"filter":                map[string][]string{"host": {host}},
		"selectInventory":       inventoryFields,
		"selectHostGroups":      []string{"name"},
		"selectParentTemplates": []string{"name"},
		"selectInterfaces":      []string{"ip", "dns", "available", "error"},
	}, true, &rows)
	if err != nil {
		return Topology{}, err
	}
	if len(rows) == 0 {
		return Topology{}, fmt.Errorf("zabbix: no host %q", host)
	}
	r := rows[0]
	top := Topology{
		VisibleName: r.Name, Description: r.Description,
		MaintenanceActive: r.MaintenanceStatus == "1",
		Inventory:         r.Inventory, // already the curated subset (selectInventory list)
	}
	for _, g := range r.HostGroups {
		top.Groups = append(top.Groups, g.Name)
	}
	for _, t := range r.ParentTemplates {
		top.Templates = append(top.Templates, t.Name)
	}
	for _, i := range r.Interfaces {
		addr := i.IP
		if addr == "" {
			addr = i.DNS
		}
		top.Interfaces = append(top.Interfaces, IfaceState{Addr: addr, Available: i.Available, Error: i.Error})
	}
	return top, nil
}

// FlapCount counts trigger firings since `since` (event.get countOutput;
// objectids is the plural array param).
func (c *Client) FlapCount(ctx context.Context, triggerID string, since time.Time) (int, error) {
	var count string
	err := c.call(ctx, "event.get", map[string]any{
		"countOutput": true,
		"object":      0, // trigger
		"source":      0, // trigger events
		"objectids":   []string{triggerID},
		"time_from":   since.Unix(),
	}, true, &count)
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(count)
	return n, nil
}
