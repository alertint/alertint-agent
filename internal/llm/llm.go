// SPDX-License-Identifier: FSL-1.1-ALv2

// Package llm holds the provider-neutral LLM surface: the prompt/completion
// types every client implements against, the sentinel errors callers match
// on, and the JSON-extraction helpers whose semantics must be identical
// across providers (never copy-pasted per client) — see ADR-0026.
package llm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Prompt is the user-turn payload of a Complete call. Prefix is always set;
// Suffix is the verification round's call-2 continuation (empty on a
// single-call prompt). CachePrefix marks the end of Prefix as a prompt-cache
// breakpoint on providers that support client-side caching; providers
// without it ignore the flag.
type Prompt struct {
	Prefix      string
	Suffix      string
	CachePrefix bool
}

// Text is the full user-turn text, prefix and suffix joined.
func (p Prompt) Text() string { return p.Prefix + p.Suffix }

// Completion is the result of a Complete call: the validated raw JSON plus
// the usage figures the client already computes for the audit log (ADR 0004).
type Completion struct {
	Raw          json.RawMessage // validated model JSON (nil on error)
	Model        string          // the model that served the request
	InputTokens  int
	OutputTokens int
	Latency      time.Duration

	CacheCreationInputTokens int // tokens written to the prompt cache (0 on providers without client-side caching)
	CacheReadInputTokens     int // tokens served from the prompt cache (0 on providers without client-side caching)
}

// ErrSchemaViolation is returned when the model's JSON response is missing
// one or more required top-level keys.
var ErrSchemaViolation = errors.New("llm: schema violation")

// ErrResponseTruncated is returned when the model stopped at the output-token
// ceiling (anthropic stop_reason=max_tokens, openai finish_reason=length),
// leaving the JSON reply incomplete. The remedy is to raise llm.max_tokens;
// retrying reproduces the same truncation.
var ErrResponseTruncated = errors.New("llm: response truncated at max_tokens")

// RetryableError wraps an HTTP status code that warrants a retry.
type RetryableError struct {
	StatusCode int
}

func (e *RetryableError) Error() string {
	return fmt.Sprintf("llm: retryable HTTP %d", e.StatusCode)
}

// ValidateKeys checks that every key in required appears at the top level
// of the JSON object raw. Returns ErrSchemaViolation if any are missing.
func ValidateKeys(raw json.RawMessage, required []string) error {
	if len(required) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%w: response is not a JSON object", ErrSchemaViolation)
	}
	var missing []string
	for _, k := range required {
		if _, ok := obj[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing keys %v", ErrSchemaViolation, missing)
	}
	return nil
}

// StripMarkdownFence removes ```json ... ``` wrappers if present.
func StripMarkdownFence(s string) string {
	trimmed := bytes.TrimSpace([]byte(s))
	prefixes := [][]byte{[]byte("```json"), []byte("```")}
	suffix := []byte("```")
	for _, p := range prefixes {
		if bytes.HasPrefix(trimmed, p) {
			inner := bytes.TrimPrefix(trimmed, p)
			inner = bytes.TrimSuffix(bytes.TrimSpace(inner), suffix)
			return string(bytes.TrimSpace(inner))
		}
	}
	return string(trimmed)
}

// PromptHash returns a hex-encoded SHA-256 of the concatenated prompts.
// Used in audit rows so the prompt content is never stored in the DB.
func PromptHash(system, user string) string {
	h := sha256.New()
	h.Write([]byte(system))
	h.Write([]byte{0x1f}) // ASCII unit separator
	h.Write([]byte(user))
	return hex.EncodeToString(h.Sum(nil))
}
