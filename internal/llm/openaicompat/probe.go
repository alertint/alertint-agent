// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/alertint/alertint-agent/internal/llm"
)

var _ llm.Prober = (*Client)(nil)

// Probe checks reachability without generating tokens. Hosted OpenAI uses a
// model-metadata GET (the only safe route it exposes); a generic
// OpenAI-compatible runtime tries a health endpoint first and falls back to a
// models listing only when the health route is unsupported (404/405/501).
func (c *Client) Probe(ctx context.Context) llm.ProbeResult {
	if c.hosted {
		return c.probeGET(ctx, "/v1/models/"+url.PathEscape(c.cfg.Model))
	}
	res := c.probeGET(ctx, "/health")
	if res.Outcome == llm.ProbeUnsupported {
		return c.probeGET(ctx, "/v1/models")
	}
	return res
}

func (c *Client) probeGET(ctx context.Context, p string) llm.ProbeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+p, nil)
	if err != nil {
		return llm.ProbeResult{Outcome: llm.ProbeFailed, Method: http.MethodGet, Path: p, Err: fmt.Errorf("llm: build probe: %w", err)}
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	return llm.DoProbe(c.http, req, p)
}
