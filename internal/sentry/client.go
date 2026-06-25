// SPDX-License-Identifier: FSL-1.1-ALv2

// Package sentry is the read-only Sentry change source: a shared egress-only
// REST client plus a background poller (poller.go) that turns new Sentry
// deploys/releases into store.Change rows. It parallels internal/prometheus and
// internal/logs/loki — GET-only, configurable timeout, host-root base URL — but
// unlike a log source it produces Changes (not log lines), runs a background
// poller, and never touches the correlator. In CONTEXT.md terms it is the first
// Change source. Reads only: no write/mutating calls, no Seer/sentry-mcp.
package sentry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultTimeout matches the Prometheus/Loki clients.
const defaultTimeout = 10 * time.Second

// defaultMaxRetries bounds how many times doGET retries a 429/5xx before
// returning a typed error.
const defaultMaxRetries = 3

// maxBackoff caps any single backoff so a far-future (or bogus) rate-limit
// Reset header can't park the poller for a long time — the cycle is better off
// erroring out and retrying on the next tick.
const maxBackoff = 60 * time.Second

// maxErrBody bounds how much of a non-200 body we read into an error message.
const maxErrBody = 4 << 10

// Release is one entry from the org releases-list endpoint. Only the fields the
// poller reads are decoded. There is no permalink/url worth trusting (KTD6), so
// the change Link is built from the host-root base URL instead.
type Release struct {
	Version      string     `json:"version"`
	DateCreated  time.Time  `json:"dateCreated"`          // non-null; the paginate-stop sort key
	DateReleased *time.Time `json:"dateReleased"`         // nullable; preferred OccurredAt for a release change
	DeployCount  int        `json:"deployCount"`          // 0 ⇒ release-without-deploy
	LastDeploy   *Deploy    `json:"lastDeploy,omitempty"` // inline gate: skip the deploys call unless this is newer than the watermark
}

// Deploy is one entry from the per-release deploys-list endpoint (also the
// inline lastDeploy on a Release). The endpoint returns the latest deploy per
// (project, environment). dateFinished is the change timestamp; id is the
// cross-cycle dedup key (KTD2). Environment is a pointer so a missing value is
// distinguishable from the empty string (the label is then omitted).
type Deploy struct {
	ID           string    `json:"id"`
	Environment  *string   `json:"environment"`
	DateFinished time.Time `json:"dateFinished"`
}

// Client is a read-only Sentry REST client. It is the single shared egress path
// for every Sentry feature (Specs 2/3 reuse it). Construct with NewClient.
type Client struct {
	baseURL    string
	org        string
	httpClient *http.Client
	authHeader string

	// clk and maxRetries are overridable by same-package tests for
	// deterministic rate-limit/backoff coverage without real sleeps.
	clk        clock
	maxRetries int
}

// Config holds the values needed to construct a Client. The token is resolved by
// the caller via config.SentryToken and passed in — the client never reads env
// vars.
type Config struct {
	BaseURL        string // host root, e.g. https://sentry.io, https://de.sentry.io, or a self-hosted host
	Org            string // organization slug
	Token          string // Internal-Integration token (project:read scope)
	TimeoutSeconds int
}

// NewClient builds a Client from cfg. A zero TimeoutSeconds defaults to 10s,
// mirroring the Prometheus/Loki clients. BaseURL is treated as the host root and
// the API path is appended (KTD6).
func NewClient(cfg Config) *Client {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		org:        cfg.Org,
		httpClient: &http.Client{Timeout: timeout},
		authHeader: "Bearer " + cfg.Token,
		clk:        realClock{},
		maxRetries: defaultMaxRetries,
	}
}

// BaseURL returns the host-root base URL the client was built with (used by the
// poller to build change permalinks, KTD6).
func (c *Client) BaseURL() string { return c.baseURL }

// Org returns the organization slug.
func (c *Client) Org() string { return c.org }

// ListReleases lists releases for the org, newest-first (Sentry's default sort),
// optionally filtered to the given project slugs, one page per call. Pass the
// returned next cursor to fetch the following page; next is "" on the last page.
func (c *Client) ListReleases(ctx context.Context, projects []string, cursor string) (releases []Release, next string, err error) {
	q := url.Values{}
	for _, p := range projects {
		if p != "" {
			q.Add("project", p)
		}
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	path := "/api/0/organizations/" + url.PathEscape(c.org) + "/releases/"
	resp, err := c.doGET(ctx, path, q)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("sentry: read releases: %w", err)
	}
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, "", fmt.Errorf("sentry: decode releases: %w", err)
	}
	next, _ = parseLinkNext(resp.Header.Get("Link"))
	return releases, next, nil
}

// ListDeploys lists the deploys of one release scoped to one project slug. The
// endpoint returns the latest deploy per (project, environment) — the multi-env
// fan-out the mapping wants (R8). version is URL-encoded into the path so
// versions containing @ or / are safe.
func (c *Client) ListDeploys(ctx context.Context, project, version string) ([]Deploy, error) {
	q := url.Values{}
	if project != "" {
		q.Set("project", project)
	}
	path := "/api/0/organizations/" + url.PathEscape(c.org) + "/releases/" + url.PathEscape(version) + "/deploys/"
	resp, err := c.doGET(ctx, path, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sentry: read deploys: %w", err)
	}
	var deploys []Deploy
	if err := json.Unmarshal(body, &deploys); err != nil {
		return nil, fmt.Errorf("sentry: decode deploys: %w", err)
	}
	return deploys, nil
}

// doGET issues an authenticated GET to baseURL+path?query and returns the
// response on 200. On 429/5xx it backs off (rate-limit-aware) and retries up to
// maxRetries; on a non-retryable status, or once retries are exhausted, it
// returns a typed *APIError carrying the status. The caller owns Body.Close on
// success.
func (c *Client) doGET(ctx context.Context, path string, query url.Values) (*http.Response, error) {
	target := c.baseURL + path
	if enc := query.Encode(); enc != "" {
		target += "?" + enc
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", c.authHeader)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("sentry request: %w", err)
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		apiErr := &APIError{StatusCode: resp.StatusCode, Body: snippet(body)}

		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if !retryable || attempt == c.maxRetries {
			_ = resp.Body.Close()
			return nil, apiErr
		}

		delay := c.backoffDelay(resp, attempt)
		_ = resp.Body.Close()
		if err := c.clk.Sleep(ctx, delay); err != nil {
			return nil, err // context cancelled mid-backoff (e.g. shutdown)
		}
		lastErr = apiErr
	}
	return nil, lastErr
}

// backoffDelay picks the wait before the next retry. For a 429 it honors the
// rate-limit headers (KTD4); for a 5xx — or a 429 with no usable header — it
// falls back to exponential backoff. Every delay is capped at maxBackoff.
func (c *Client) backoffDelay(resp *http.Response, attempt int) time.Duration {
	if resp.StatusCode == http.StatusTooManyRequests {
		if d, ok := rateLimitWait(resp, c.clk.Now()); ok {
			return capBackoff(d)
		}
	}
	// 5xx, or 429 without a usable header: exponential backoff 0.5s, 1s, 2s, …
	return capBackoff((500 * time.Millisecond) << attempt)
}

// rateLimitWait derives the wait from a 429's headers: X-Sentry-Rate-Limit-Reset
// (UTC epoch seconds) first, then Retry-After — the Sentry REST API documents the
// former but does not reliably send the latter (KTD4). ok is false when neither
// yields a usable delay, leaving the caller on exponential backoff. A reset
// already in the past returns (0, true) to retry immediately.
func rateLimitWait(resp *http.Response, now time.Time) (time.Duration, bool) {
	if reset := resp.Header.Get("X-Sentry-Rate-Limit-Reset"); reset != "" {
		if epoch, err := strconv.ParseInt(reset, 10, 64); err == nil {
			d := time.Unix(epoch, 0).Sub(now)
			if d < 0 {
				d = 0
			}
			return d, true
		}
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	return 0, false
}

func capBackoff(d time.Duration) time.Duration {
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// APIError is a non-200 Sentry response. StatusCode lets callers distinguish a
// 429 (rate-limited, retries exhausted) from a 4xx/5xx; the poller treats any of
// them as a skip-this-cycle signal.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sentry: api request failed: http %d: %s", e.StatusCode, e.Body)
}

// parseLinkNext extracts the next-page cursor from a Sentry Link header. Sentry
// returns RFC-5988 links with extra attributes:
//
//	<url>; rel="previous"; results="false"; cursor="0:0:1",
//	<url>; rel="next"; results="true"; cursor="0:100:0"
//
// It returns the rel="next" cursor only when results="true"; Sentry sets
// results="false" on the terminal page, which yields ("", false).
func parseLinkNext(header string) (cursor string, more bool) {
	if header == "" {
		return "", false
	}
	for _, part := range strings.Split(header, ",") {
		seg := strings.TrimSpace(part)
		if !strings.Contains(seg, `rel="next"`) {
			continue
		}
		if !strings.Contains(seg, `results="true"`) {
			return "", false
		}
		if cur := linkAttr(seg, "cursor"); cur != "" {
			return cur, true
		}
	}
	return "", false
}

// linkAttr pulls the value of a name="value" attribute out of one Link segment.
func linkAttr(seg, name string) string {
	needle := name + `="`
	i := strings.Index(seg, needle)
	if i < 0 {
		return ""
	}
	rest := seg[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// snippet returns a short single-line excerpt of a response body for errors.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	const maxLen = 200
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// clock abstracts time so the rate-limit backoff is deterministic in tests.
type clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// realClock is the production clock: wall time and a context-aware sleep so a
// backoff aborts promptly on shutdown.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
