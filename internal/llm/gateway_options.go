// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

// Reasoning is the unified `reasoning` request object that OpenAI-compatible
// gateways such as OpenRouter accept. It is the gateway-level way to set how
// much a model thinks, as opposed to llm.thinking and llm.reasoning_effort,
// which reach self-hosted runtimes through chat_template_kwargs and which a
// gateway ignores. Set Effort or MaxTokens, not both: the gateway accepts one
// or the other. Effort is passed through unvalidated because its vocabulary is
// the gateway's (OpenRouter documents xhigh, high, medium, low, minimal and
// none) and a model may accept only some of them.
type Reasoning struct {
	// Enabled turns thinking on or off; nil leaves the model's default.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled"`
	// Effort is the depth of thinking, e.g. "none" or "low".
	Effort string `json:"effort,omitempty" yaml:"effort"`
	// MaxTokens is a token budget for thinking; 0 omits it.
	MaxTokens int `json:"max_tokens,omitempty" yaml:"max_tokens"`
	// Exclude hides the thinking from the response; it is still generated and
	// still counts against the output ceiling.
	Exclude bool `json:"exclude,omitempty" yaml:"exclude"`
}

// IsZero reports whether no field is set.
func (r Reasoning) IsZero() bool {
	return r.Enabled == nil && r.Effort == "" && r.MaxTokens == 0 && !r.Exclude
}

// Routing is the `provider` request object that OpenRouter accepts to choose
// which hosting providers may serve a request. A hosted model is often served
// by several providers at different quantizations, so an unpinned run can mix
// them. The vocabulary (provider slugs, quantization names) is the gateway's
// and is passed through unvalidated.
type Routing struct {
	// Order tries the listed provider slugs in order.
	Order []string `json:"order,omitempty" yaml:"order"`
	// Only restricts the request to the listed provider slugs.
	Only []string `json:"only,omitempty" yaml:"only"`
	// Ignore excludes the listed provider slugs.
	Ignore []string `json:"ignore,omitempty" yaml:"ignore"`
	// AllowFallbacks, when false, stops after the first eligible provider
	// instead of trying another; nil leaves the gateway default (true).
	AllowFallbacks *bool `json:"allow_fallbacks,omitempty" yaml:"allow_fallbacks"`
	// Quantizations restricts the request to providers serving one of the
	// listed quantization levels, e.g. "bf16" or "fp8".
	Quantizations []string `json:"quantizations,omitempty" yaml:"quantizations"`
}

// IsZero reports whether no field is set.
func (r Routing) IsZero() bool {
	return len(r.Order) == 0 && len(r.Only) == 0 && len(r.Ignore) == 0 &&
		r.AllowFallbacks == nil && len(r.Quantizations) == 0
}
