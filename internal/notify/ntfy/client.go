// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var ErrClaimLost = errors.New("ntfy: delivery claim lost")

// Claim is a fenced lease over a frozen message.
type Claim struct {
	ID, Destination, Owner string
	Token                  int64
	Attempts               int
	Message                Message
}

type DeliveryError struct {
	Status     int
	Blocked    bool
	RetryAfter time.Duration
}

func (e *DeliveryError) Error() string { return fmt.Sprintf("ntfy: HTTP %d", e.Status) }

type Client struct {
	http  *http.Client
	token string
}

func NewClient(token string) *Client {
	return &Client{token: token, http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) Send(ctx context.Context, destination string, m Message) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, destination, strings.NewReader(m.Body))
	if err != nil {
		return errors.New("ntfy: invalid destination")
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Markdown", "yes")
	req.Header.Set("Title", m.Title)
	req.Header.Set("Priority", strconv.Itoa(m.Priority))
	// Identity is useful for diagnostics; external deduplication is not assumed.
	req.Header.Set("X-Alertint-Notification-Id", m.ID)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return errors.New("ntfy: request failed or timed out")
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	failure := &DeliveryError{Status: res.StatusCode, Blocked: res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusNotFound || res.StatusCode >= 300 && res.StatusCode < 400}
	if seconds, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && seconds > 0 {
		failure.RetryAfter = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(res.Header.Get("Retry-After")); err == nil {
		failure.RetryAfter = time.Until(at)
	}
	return failure
}
