// SPDX-License-Identifier: FSL-1.1-ALv2

// Package zabbix is a read-only JSON-RPC client for the Zabbix 7.0 frontend
// API (api_jsonrpc.php). It issues only *.get methods (plus apiinfo.version):
// it never mutates Zabbix state (ADR-0032). Auth is the Authorization: Bearer
// header (not the legacy auth param, removed in 7.2).
package zabbix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/httpcount"
	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// ErrResponseTooLarge is returned by the bounded (proactive preparation)
// request path — every callInstrumented dispatch — when the DECODED
// response body exceeds model.MaxDecodedResponseBytes. The excess is never
// read into memory. Callers classify it with errors.Is.
var ErrResponseTooLarge = errors.New("zabbix: response exceeds the bounded decoded-body limit")

// ErrRedirectRefused is returned by the bounded (proactive preparation)
// request path — every callInstrumented dispatch — when the frontend
// answers 3xx. Following a redirect would be a second physical request
// (a re-POST of the JSON-RPC body) outside the one durable reservation
// that wrapped this call, so the bounded path never follows one. Callers
// classify it with errors.Is.
var ErrRedirectRefused = errors.New("zabbix: redirect refused on the bounded request path")

type Config struct {
	BaseURL              string // Zabbix frontend; "/api_jsonrpc.php" is appended
	APIToken             string
	InstanceID           string
	TimeoutSeconds       int
	HistoryRetentionDays int
	FlapWindowHours      int
}

type Client struct {
	endpoint   string
	endpointID string
	instanceID string
	httpClient *http.Client
	// boundedHTTP is httpClient with redirects disabled — the transport the
	// bounded (proactive) callInstrumented path uses so one reservation is
	// exactly one physical request.
	boundedHTTP      *http.Client
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
	httpClient := &http.Client{Timeout: timeout}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/api_jsonrpc.php"
	sum := sha256.Sum256([]byte(endpoint))
	return &Client{
		endpoint:         endpoint,
		endpointID:       "sha256:" + hex.EncodeToString(sum[:]),
		instanceID:       strings.TrimSpace(cfg.InstanceID),
		httpClient:       httpClient,
		boundedHTTP:      noRedirectClient(httpClient),
		authHeader:       "Bearer " + cfg.APIToken,
		historyRetention: time.Duration(hr) * 24 * time.Hour,
		flapWindow:       time.Duration(fw) * time.Hour,
	}
}

// noRedirectClient returns a shallow copy of base whose redirect policy
// hands every 3xx back as the final response (http.ErrUseLastResponse)
// instead of issuing a further, unreserved physical request.
func noRedirectClient(base *http.Client) *http.Client {
	cp := *base
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
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
// This is the legacy (Acute Triage / MCP) path: its body read is unbounded.
func (c *Client) call(ctx context.Context, method string, params any, withAuth bool, out any) error {
	return c.rpc(ctx, method, params, withAuth, out, nil, nil, false)
}

// callInstrumented is call with a per-physical-request hook, for the
// proactive preparation path: before is called immediately before the one
// physical HTTP request this method issues (a non-nil error aborts before
// it is made); after reports its outcome immediately once it completes.
// Both may be nil. Every Zabbix *.get call the proactive path makes —
// including a secondary item/recovery lookup — goes through this one
// method, so every physical dispatch is individually reservable by a
// caller in internal/observation/connectors. Unlike call, its decoded
// response body is capped at model.MaxDecodedResponseBytes
// (ErrResponseTooLarge past it). Every proactive call is an authenticated
// *.get, so there is no withAuth switch here.
func (c *Client) callInstrumented(ctx context.Context, method string, params any, out any,
	before func() error, after func(started bool, err error)) error {
	return c.rpc(ctx, method, params, true, out, before, after, true)
}

// rpcFunc is the one-method shape MetricHistory (legacy, call) and
// MetricHistoryBounded (proactive, callInstrumented with hooks) each bind
// so the shared item/history/trend request code is written once.
type rpcFunc func(ctx context.Context, method string, params any, out any) error

// rpc is the shared JSON-RPC body behind call and callInstrumented.
func (c *Client) rpc(ctx context.Context, method string, params any, withAuth bool, out any,
	before func() error, after func(started bool, err error), bounded bool) error {
	if params == nil {
		params = map[string]any{}
	}
	if before != nil {
		if err := before(); err != nil {
			return err
		}
	}
	reqBody, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		if after != nil {
			after(false, err)
		}
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		if after != nil {
			after(false, err)
		}
		return err
	}
	req.Header.Set("Content-Type", "application/json-rpc")
	if withAuth {
		req.Header.Set("Authorization", c.authHeader)
	}
	httpClient := c.httpClient
	if bounded {
		httpClient = c.boundedHTTP
	}
	httpcount.Observe(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		if after != nil {
			after(true, err)
		}
		return fmt.Errorf("zabbix request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if bounded && resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		if after != nil {
			after(true, ErrRedirectRefused)
		}
		return ErrRedirectRefused
	}
	var body []byte
	if bounded {
		body, err = readBounded(resp.Body, model.MaxDecodedResponseBytes)
	} else {
		body, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		if after != nil {
			after(true, err)
		}
		if errors.Is(err, ErrResponseTooLarge) {
			return err
		}
		return fmt.Errorf("zabbix: read response: %w", err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		if after != nil {
			after(true, err)
		}
		return fmt.Errorf("zabbix: decode response: %w", err)
	}
	if envelope.Error != nil {
		rpcErr := fmt.Errorf("zabbix %s: %s (%s)", method, envelope.Error.Message, envelope.Error.Data)
		if after != nil {
			after(true, rpcErr)
		}
		return rpcErr
	}
	if after != nil {
		after(true, nil)
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

// resolveItem looks up an item's id + value_type by host (technical name) +
// key over rpc. It tries an EXACT key match first, falling back to a fuzzy
// substring search only when no exact item exists — so an unambiguous key
// (e.g. system.cpu.util) is never shadowed by an unrelated longer key that
// happens to substring-match it (e.g. system.cpu.util[,iowait]) under a
// bare `search`. Legacy (MetricHistory) path only.
func (c *Client) resolveItem(ctx context.Context, host, key string, rpc rpcFunc) (zItem, error) {
	item, ok, err := c.lookupItem(ctx, host, key, false, rpc)
	if err != nil {
		return zItem{}, err
	}
	if !ok {
		item, ok, err = c.lookupItem(ctx, host, key, true, rpc)
		if err != nil {
			return zItem{}, err
		}
	}
	if !ok {
		return zItem{}, fmt.Errorf("zabbix: no item matching host=%q key=%q", host, key)
	}
	return item, nil
}

// lookupItem runs one item.get, exact (filter) or fuzzy (search) on key_.
func (c *Client) lookupItem(ctx context.Context, host, key string, fuzzy bool, rpc rpcFunc) (zItem, bool, error) {
	params := map[string]any{
		"output": []string{"itemid", "value_type", "name", "units"},
		"host":   host,
		"limit":  1,
	}
	if fuzzy {
		params["search"] = map[string]string{"key_": key}
	} else {
		params["filter"] = map[string]string{"key_": key}
	}
	var items []zItem
	if err := rpc(ctx, "item.get", params, &items); err != nil {
		return zItem{}, false, err
	}
	if len(items) == 0 {
		return zItem{}, false, nil
	}
	return items[0], true, nil
}

// MetricHistory returns a normalized series for host+itemKey over [from,to].
// It resolves the item's value_type first (history.get silently returns empty
// for floats under the default history=3) and falls back to trends for windows
// older than the configured history retention.
func (c *Client) MetricHistory(ctx context.Context, host, itemKey string, from, to time.Time, limit int) (Series, error) {
	rpc := func(ctx context.Context, method string, params any, out any) error {
		return c.call(ctx, method, params, true, out)
	}
	item, err := c.resolveItem(ctx, host, itemKey, rpc)
	if err != nil {
		return Series{}, err
	}
	return c.fetchSeries(ctx, item, from, to, limit, rpc)
}

// MetricHistoryBounded is the proactive preparation path's MetricHistory:
// exactly two physical requests — one EXACT item.get (never the legacy
// fuzzy substring fallback, which could substitute an unrelated item) and
// one history.get/trend.get — each individually reservable through
// before/after by a caller in internal/observation/connectors, over the
// bounded transport path (decoded body capped at
// model.MaxDecodedResponseBytes). The item must be proven to belong to
// host (selectHosts linkage); a missing or foreign item is ErrNotFound.
func (c *Client) MetricHistoryBounded(ctx context.Context, host, itemKey string, from, to time.Time, limit int,
	before func() error, after func(started bool, err error)) (Series, error) {
	rpc := func(ctx context.Context, method string, params any, out any) error {
		return c.callInstrumented(ctx, method, params, out, before, after)
	}
	item, err := c.lookupItemLinked(ctx, host, itemKey, rpc)
	if err != nil {
		return Series{}, err
	}
	return c.fetchSeries(ctx, item, from, to, limit, rpc)
}

// lookupItemLinked runs one exact-filter item.get scoped to host and
// returns the item only when the source proves the linkage: the request
// carries the host filter, and the response's selectHosts data must
// name the requested host (and agree with the item's own
// hostid). No match, or a mismatch, is ErrNotFound — never a fuzzy
// substitute.
func (c *Client) lookupItemLinked(ctx context.Context, host, key string, rpc rpcFunc) (zItem, error) {
	params := map[string]any{
		"output":      []string{"itemid", "hostid", "value_type", "name", "units"},
		"host":        host,
		"filter":      map[string]string{"key_": key},
		"selectHosts": []string{"hostid", "host"},
		"limit":       1,
	}
	var items []zItem
	if err := rpc(ctx, "item.get", params, &items); err != nil {
		return zItem{}, err
	}
	if len(items) == 0 {
		return zItem{}, fmt.Errorf("zabbix: no item with exact key %q on host %q: %w", key, host, ErrNotFound)
	}
	item := items[0]
	hostID, ok := hostRefFor(item.Hosts, host)
	if !ok || hostID == "" || item.ItemID == "" || (item.HostID != "" && hostID != item.HostID) {
		return zItem{}, fmt.Errorf("zabbix: item %q (key %q) is not linked to host %q: %w", item.ItemID, key, host, ErrNotFound)
	}
	return item, nil
}

// fetchSeries issues the one history.get (or trend.get, for windows older
// than the configured history retention) that reads item's values over
// [from,to] via rpc, and normalizes the rows into a Series.
func (c *Client) fetchSeries(ctx context.Context, item zItem, from, to time.Time, limit int, rpc rpcFunc) (Series, error) {
	if time.Since(from) > c.historyRetention {
		var rows []struct {
			Clock    string `json:"clock"`
			ValueAvg string `json:"value_avg"`
			ValueMin string `json:"value_min"`
			ValueMax string `json:"value_max"`
		}
		if err := rpc(ctx, "trend.get", map[string]any{
			"output":    "extend",
			"itemids":   item.ItemID,
			"time_from": from.Unix(),
			"time_till": to.Unix(),
			"limit":     limit,
		}, &rows); err != nil {
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
	if err := rpc(ctx, "history.get", map[string]any{
		"output":    "extend",
		"history":   item.ValueType, // the fix: resolved type, not default 3
		"itemids":   item.ItemID,
		"time_from": from.Unix(),
		"time_till": to.Unix(),
		"sortfield": "clock",
		"sortorder": "DESC",
		"limit":     limit,
	}, &rows); err != nil {
		return Series{}, err
	}
	pts := make([]SeriesPoint, 0, len(rows))
	for _, r := range rows {
		pts = append(pts, SeriesPoint{Clock: unixStr(r.Clock), Value: r.Value})
	}
	return Series{ItemID: item.ItemID, Name: item.Name, Units: item.Units, Source: "history", Points: pts}, nil
}

// openProblemsCall issues one problem.get with the shared output/sort shape
// and decodes rows into []Problem. scopeKey/scopeIDs is "hostids" or
// "groupids" — the only difference between the host- and group-scoped reads.
func (c *Client) openProblemsCall(ctx context.Context, scopeKey string, scopeIDs []string, sel ProblemSelector) ([]Problem, error) {
	params := map[string]any{
		"output":     "extend",
		"selectTags": "extend",
		scopeKey:     scopeIDs,
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

// GroupOpenProblems lists currently-open problems across host groups —
// OpenProblems' group-scoped sibling, serving the verification floor's
// neighbor check (ADR-0034).
func (c *Client) GroupOpenProblems(ctx context.Context, groupIDs []string, sel ProblemSelector) ([]Problem, error) {
	return c.openProblemsCall(ctx, "groupids", groupIDs, sel)
}

// OpenProblems lists currently-open problems on a host.
func (c *Client) OpenProblems(ctx context.Context, host string, sel ProblemSelector) ([]Problem, error) {
	hostids, err := c.hostIDs(ctx, host)
	if err != nil {
		return nil, err
	}
	return c.openProblemsCall(ctx, "hostids", hostids, sel)
}

// ProblemStateBounded reads whether one exact trigger is currently open on
// one exact technical host. An empty, complete problem.get is proof of
// absence; transport, identity, and decoding failures remain errors.
func (c *Client) ProblemStateBounded(ctx context.Context, host, triggerID string,
	before func() error, after func(started bool, err error),
) (ProblemState, error) {
	if host == "" || triggerID == "" {
		return ProblemState{}, ErrNotFound
	}
	var hosts []struct {
		HostID string `json:"hostid"`
	}
	if err := c.callInstrumented(ctx, "host.get", map[string]any{
		"output": []string{"hostid"}, "filter": map[string][]string{"host": {host}},
	}, &hosts, before, after); err != nil {
		return ProblemState{}, err
	}
	if len(hosts) != 1 || hosts[0].HostID == "" {
		return ProblemState{}, ErrNotFound
	}
	var rows []struct {
		EventID string `json:"eventid"`
	}
	if err := c.callInstrumented(ctx, "problem.get", map[string]any{
		"output": []string{"eventid"}, "hostids": []string{hosts[0].HostID}, "objectids": []string{triggerID},
		"recent": false, "sortfield": []string{"eventid"}, "sortorder": "DESC", "limit": 2,
	}, &rows, before, after); err != nil {
		return ProblemState{}, err
	}
	if len(rows) == 0 {
		return ProblemState{Presence: ProblemAbsent}, nil
	}
	eventIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.EventID != "" {
			eventIDs = append(eventIDs, row.EventID)
		}
	}
	return ProblemState{Presence: ProblemPresent, EventIDs: eventIDs}, nil
}

// HostGroups resolves group names to ids and host counts (hostgroup.get with
// selectHosts "count") — one call serving both the floor's scope ranking and
// its peer count.
func (c *Client) HostGroups(ctx context.Context, names []string) ([]HostGroupInfo, error) {
	var rows []struct {
		GroupID string `json:"groupid"`
		Name    string `json:"name"`
		Hosts   string `json:"hosts"`
	}
	if err := c.call(ctx, "hostgroup.get", map[string]any{
		"output":      []string{"groupid", "name"},
		"filter":      map[string][]string{"name": names},
		"selectHosts": "count",
	}, true, &rows); err != nil {
		return nil, err
	}
	out := make([]HostGroupInfo, 0, len(rows))
	for _, r := range rows {
		n, err := strconv.Atoi(r.Hosts)
		if err != nil {
			return nil, fmt.Errorf("zabbix: hostgroup.get: parse host count for group %q: %w", r.Name, err)
		}
		out = append(out, HostGroupInfo{GroupID: r.GroupID, Name: r.Name, Hosts: n})
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
		return nil, fmt.Errorf("zabbix: no host matching %q: %w", host, ErrNotFound)
	}
	return ids, nil
}

// readBounded reads at most limit bytes of the (already transport-decoded)
// body, reading limit+1 through an io.LimitReader so an over-limit body is
// detected without buffering the remainder (ErrResponseTooLarge). Go's
// http.Transport transparently gunzips a body it negotiated itself (the
// client never sets Accept-Encoding), so the cap applies to the DECODED
// stream, never the compressed wire size.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrResponseTooLarge
	}
	return body, nil
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
		return Topology{}, fmt.Errorf("zabbix: no host %q: %w", host, ErrNotFound)
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
