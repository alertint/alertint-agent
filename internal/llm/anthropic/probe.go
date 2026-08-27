// SPDX-License-Identifier: FSL-1.1-ALv2

package anthropic

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/alertint/alertint-agent/internal/llm"
)

var _ llm.Prober = (*Client)(nil)

// Probe checks reachability with a model-metadata GET. It never touches the
// generation endpoint and sends no prompt, so it costs zero tokens.
func (c *Client) Probe(ctx context.Context) llm.ProbeResult {
	p := "/v1/models/" + url.PathEscape(c.cfg.Model)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+p, nil)
	if err != nil {
		return llm.ProbeResult{Outcome: llm.ProbeFailed, Method: http.MethodGet, Path: p, Err: fmt.Errorf("llm: build probe: %w", err)}
	}
	req.Header.Set("X-Api-Key", c.cfg.APIKey)
	req.Header.Set("Anthropic-Version", anthropicVersion)
	return llm.DoProbe(c.http, req, p)
}
