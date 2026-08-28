// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat

import (
	"log/slog"
	"net/http"
	"time"
)

// NewForTest builds a Client pointed at cfg.BaseURL (an httptest.Server, in
// practice) with the hosted-vs-generic Probe routing forced explicitly,
// since isHostedOpenAI(cfg.BaseURL) can never match a test server's host.
func NewForTest(cfg Config, hosted bool) *Client {
	cfg.defaults()
	return &Client{
		cfg:      cfg,
		http:     &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
		logger:   slog.Default(),
		now:      func() time.Time { return time.Now().UTC() },
		endpoint: cfg.BaseURL + "/v1/chat/completions",

		pinChatTemplateKwargs: !hosted,
		hosted:                hosted,
	}
}
