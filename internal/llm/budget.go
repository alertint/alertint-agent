// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"time"
)

var ErrBudgetExhausted = errors.New("llm: shared budget exhausted")
var ErrBudgetUsageUnknown = errors.New("llm: budget usage unknown; inspect provider usage and persisted llm.budget.v1 state before recovery")

// BudgetLimits apply to all generation attempts sharing a store, across
// workloads, retries and restarts. Zero means unlimited for that dimension.
type BudgetLimits struct {
	CallsPerHour int   `yaml:"calls_per_hour"`
	TotalTokens  int64 `yaml:"total_tokens"`
}

// BudgetStore commits an atomic read-modify-write before returning success.
type BudgetStore interface {
	UpdateLLMBudget(ctx context.Context, update func([]byte) ([]byte, error)) error
}

// Budget reserves a conservative token allowance and one rolling-hour call
// atomically before each HTTP generation attempt. Successful usage settlement
// refunds unused allowance; ambiguous outcomes keep the charge and latch an
// unknown-usage block for finite token budgets. Unsettled crash reservations
// remain charged across restart, but do not exclude other affordable calls.
type Budget struct {
	store  BudgetStore
	limits BudgetLimits
	now    func() time.Time
}

// NewBudget shares the store's installation-wide ledger. Constructing a new
// Budget does not reset it. Production clients should share one instance.
func NewBudget(store BudgetStore, limits BudgetLimits) *Budget {
	return &Budget{store: store, limits: limits, now: time.Now}
}

type budgetState struct {
	Version int              `json:"version"`
	Calls   []time.Time      `json:"calls"`
	Tokens  int64            `json:"tokens"`
	Pending map[string]int64 `json:"pending"`
	Unknown bool             `json:"unknown"`
}

func (b *Budget) update(ctx context.Context, fn func(*budgetState) error) error {
	if b.store == nil {
		return errors.New("llm budget store unavailable")
	}
	return b.store.UpdateLLMBudget(ctx, func(raw []byte) ([]byte, error) {
		state := budgetState{Version: 1, Pending: make(map[string]int64)}
		if string(raw) != "{}" {
			if err := json.Unmarshal(raw, &state); err != nil {
				return nil, fmt.Errorf("llm budget state: %w", err)
			}
			if state.Version != 1 || state.Tokens < 0 || state.Pending == nil {
				return nil, errors.New("llm budget state invalid; inspect llm.budget.v1 before recovery")
			}
		}
		if err := fn(&state); err != nil {
			return nil, err
		}
		return json.Marshal(state)
	})
}

// Transport guards each generation POST below provider retry loops. A nil or
// disabled budget leaves the transport unchanged; metadata GETs cost no tokens.
func (b *Budget) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if b == nil || (b.limits.CallsPerHour == 0 && b.limits.TotalTokens == 0) {
		return base
	}
	return &budgetTransport{budget: b, base: base}
}

type budgetTransport struct {
	budget *Budget
	base   http.RoundTripper
}

func (t *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost {
		return t.base.RoundTrip(req)
	}
	if req.Body != nil {
		defer func() { _ = req.Body.Close() }()
	}
	b := t.budget
	allowance, err := requestAllowance(req)
	if err != nil {
		return nil, fmt.Errorf("%w: LLM budget request allowance: %w", ErrRequestNotSent, err)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("%w: LLM budget reservation ID: %w", ErrRequestNotSent, err)
	}
	id := hex.EncodeToString(random[:])
	if err := b.reserve(req.Context(), id, allowance); err != nil {
		return nil, fmt.Errorf("%w: reserve LLM budget: %w", ErrRequestNotSent, err)
	}
	resp, dispatchErr := t.base.RoundTrip(req)
	var used int64
	var usageErr error
	if dispatchErr == nil && resp != nil {
		var body []byte
		body, usageErr = io.ReadAll(io.LimitReader(resp.Body, 512*1024+1))
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if len(body) > 512*1024 {
			usageErr = fmt.Errorf("%w: response exceeds 512 KiB", ErrBudgetUsageUnknown)
		}
		if usageErr == nil {
			used, usageErr = responseTokens(body)
		}
	} else {
		usageErr = ErrBudgetUsageUnknown
	}
	// Settlement must outlive a canceled HTTP context, but remain bounded. If
	// persistence fails, the committed allowance remains charged.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 5*time.Second)
	defer cancel()
	var overrun bool
	settleErr := b.update(ctx, func(state *budgetState) error {
		reserved, ok := state.Pending[id]
		if !ok {
			return errors.New("llm budget reservation missing")
		}
		delete(state.Pending, id)
		if usageErr != nil {
			state.Unknown = true
			return nil
		}
		state.Tokens -= reserved
		if used > math.MaxInt64-state.Tokens {
			state.Tokens = math.MaxInt64
			state.Unknown = true
		} else {
			state.Tokens += used
		}
		overrun = b.limits.TotalTokens > 0 && state.Tokens > b.limits.TotalTokens
		return nil
	})
	if settleErr != nil {
		if resp != nil {
			_ = resp.Body.Close()
			settleErr = errors.Join(ErrResponseInvalid, settleErr)
		}
		return nil, fmt.Errorf("llm budget settlement failed; reservation retained, inspect store: %w", errors.Join(dispatchErr, settleErr))
	}
	if overrun {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("%w: %w: provider usage exceeded llm.budget.total_tokens=%d; inspect provider accounting before raising the limit", ErrResponseInvalid, ErrBudgetExhausted, b.limits.TotalTokens)
	}
	if usageErr != nil && (dispatchErr == nil && resp != nil && resp.StatusCode == http.StatusOK || b.limits.TotalTokens > 0) {
		if resp != nil {
			_ = resp.Body.Close()
		}
		if resp != nil {
			usageErr = errors.Join(ErrResponseInvalid, usageErr)
		}
		return nil, fmt.Errorf("%w: %w", ErrBudgetUsageUnknown, errors.Join(dispatchErr, usageErr))
	}
	return resp, dispatchErr
}

func (b *Budget) reserve(ctx context.Context, id string, allowance int64) error {
	return b.update(ctx, func(state *budgetState) error {
		if b.limits.TotalTokens > 0 && state.Unknown {
			return &BudgetDeferredError{Message: "llm.budget.total_tokens has unknown usage; inspect provider usage and llm.budget.v1 before recovery"}
		}
		now := b.now().UTC()
		live := state.Calls[:0]
		for _, at := range state.Calls {
			if at.After(now.Add(-time.Hour)) {
				live = append(live, at)
			}
		}
		state.Calls = live
		if b.limits.CallsPerHour > 0 && len(live) >= b.limits.CallsPerHour {
			slices.SortFunc(live, time.Time.Compare)
			retryAt := live[len(live)-b.limits.CallsPerHour].Add(time.Hour)
			return &BudgetDeferredError{RetryAt: &retryAt, Message: fmt.Sprintf("llm.budget.calls_per_hour=%d; wait until %s or review the configured limit", b.limits.CallsPerHour, retryAt.Format(time.RFC3339Nano))}
		}
		reserved := allowance
		if b.limits.TotalTokens > 0 {
			if b.limits.TotalTokens-state.Tokens < allowance {
				return &BudgetDeferredError{Message: fmt.Sprintf("llm.budget.total_tokens=%d, charged=%d, next request needs an allowance of %d; reduce prompt/output size or review and raise the total limit", b.limits.TotalTokens, state.Tokens, allowance)}
			}
		}
		if reserved > math.MaxInt64-state.Tokens {
			return errors.New("llm budget token counter overflow; inspect persisted state")
		}
		state.Tokens += reserved
		state.Pending[id] = reserved
		state.Calls = append(state.Calls, now)
		return nil
	})
}

// For these text-only request shapes, byte length plus framing allowance is
// deliberately larger than normal tokenization. This is not a tokenizer or a
// guarantee for arbitrary compatible servers. The output cap must be honored.
func requestAllowance(req *http.Request) (int64, error) {
	if req.GetBody == nil {
		return 0, errors.New("generation request must have a replayable body")
	}
	body, err := req.GetBody()
	if err != nil {
		return 0, err
	}
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(body)
	if err != nil {
		return 0, err
	}
	var shape struct {
		MaxTokens int64 `json:"max_tokens"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return 0, err
	}
	if shape.MaxTokens <= 0 || shape.MaxTokens > math.MaxInt64-int64(len(raw))-1024 {
		return 0, errors.New("invalid max_tokens")
	}
	return int64(len(raw)) + shape.MaxTokens + 1024, nil
}

func responseTokens(raw []byte) (int64, error) {
	var response struct {
		Usage map[string]json.RawMessage `json:"usage"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return 0, err
	}
	usage := response.Usage
	input, output := "input_tokens", "output_tokens"
	if _, ok := usage["prompt_tokens"]; ok {
		input, output = "prompt_tokens", "completion_tokens"
	}
	keys := []string{input, output}
	if input == "input_tokens" {
		keys = append(keys, "cache_creation_input_tokens", "cache_read_input_tokens")
	}
	var total int64
	for i, key := range keys {
		raw, exists := usage[key]
		if !exists && i >= 2 {
			continue
		}
		var count *int64
		if err := json.Unmarshal(raw, &count); err != nil || count == nil || *count < 0 || *count > math.MaxInt64-total {
			return 0, ErrBudgetUsageUnknown
		}
		total += *count
	}
	if total == 0 {
		return 0, ErrBudgetUsageUnknown
	}
	// OpenAI prompt_tokens already includes cached prompt tokens; reasoning
	// tokens are likewise included in completion_tokens. Do not count twice.
	return total, nil
}
