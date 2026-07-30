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
