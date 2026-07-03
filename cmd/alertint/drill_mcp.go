// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// mcpOneShotClient is the drill's minimal MCP client: initialize once, then
// tools/call over streamable HTTP. The server's session validation is
// format-only (stateless session manager), so carrying the id returned by
// initialize is sufficient — no notifications, no streams, no SSE.
type mcpOneShotClient struct {
	endpoint  string // e.g. http://127.0.0.1:9912/mcp
	token     string
	http      *http.Client
	sessionID string
	nextID    int
}

type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newMCPOneShotClient(endpoint, token string, httpClient *http.Client) *mcpOneShotClient {
	return &mcpOneShotClient{endpoint: endpoint, token: token, http: httpClient, nextID: 1}
}

// post sends one JSON-RPC request and decodes the single JSON response,
// returning the result plus the response headers (the body is fully consumed
// and closed here).
func (c *mcpOneShotClient) post(ctx context.Context, method string, params any) (json.RawMessage, http.Header, error) {
	body, err := json.Marshal(jsonrpcRequest{JSONRPC: "2.0", ID: c.nextID, Method: method, Params: params})
	if err != nil {
		return nil, nil, fmt.Errorf("drill: marshal %s request: %w", method, err)
	}
	c.nextID++

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("drill: build %s request: %w", method, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("drill: mcp %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("drill: read mcp %s response: %w", method, err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, nil, fmt.Errorf("drill: mcp %s: http %d: %s", method, resp.StatusCode, snippet(raw))
	}

	var rpc jsonrpcResponse
	if err := json.Unmarshal(raw, &rpc); err != nil {
		return nil, nil, fmt.Errorf("drill: mcp %s: decode response: %w (%s)", method, err, snippet(raw))
	}
	if rpc.Error != nil {
		return nil, nil, fmt.Errorf("drill: mcp %s: rpc error %d: %s", method, rpc.Error.Code, rpc.Error.Message)
	}
	return rpc.Result, resp.Header, nil
}

// initialize performs the MCP handshake and captures the session id header.
func (c *mcpOneShotClient) initialize(ctx context.Context) error {
	params := map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "alertint-drill", "version": resolveVersion()},
	}
	_, header, err := c.post(ctx, "initialize", params)
	if err != nil {
		return err
	}
	if sid := header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID = sid
	}
	return nil
}

// callTool invokes one MCP tool and returns the JSON payload from
// result.content[0].text (the shape NewToolResultJSON produces).
func (c *mcpOneShotClient) callTool(ctx context.Context, name string, args map[string]any) (json.RawMessage, error) {
	result, _, err := c.post(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var tool struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(result, &tool); err != nil {
		return nil, fmt.Errorf("drill: mcp %s: decode tool result: %w", name, err)
	}
	if len(tool.Content) == 0 {
		return nil, fmt.Errorf("drill: mcp %s: empty tool result", name)
	}
	if tool.IsError {
		return nil, fmt.Errorf("drill: mcp %s: %s", name, tool.Content[0].Text)
	}
	return json.RawMessage(tool.Content[0].Text), nil
}

// snippet truncates a response body for error messages.
func snippet(b []byte) string {
	const maxLen = 200
	s := string(b)
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}
