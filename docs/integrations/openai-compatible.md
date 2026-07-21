---
title: "OpenAI-compatible endpoint"
description: "Run triage against a self-hosted LLM endpoint — SGLang, vLLM, Ollama, LM Studio — instead of the Anthropic API."
section: "Integrations"
order: 6
slug: "openai-compatible"
---

# OpenAI-compatible endpoint

**AlertINT** can run triage against any self-hosted endpoint that speaks the
OpenAI chat-completions wire format — SGLang, vLLM, Ollama, LM Studio, and
anything else implementing `POST /v1/chat/completions`. Set
`llm.provider: openai-compatible` and point `llm.base_url` at it: nothing
leaves your network, completing the self-hosted story alongside your own
Prometheus, Loki, and Alertmanager.

One provider serves an install. There is no routing, no fallback, and no
mixing Anthropic and a local endpoint on the same deployment — pick one at
config time (see [scope and limits](../concepts/scope-and-limits.md)).

## Configuration

```yaml
llm:
  provider: openai-compatible
  base_url: http://localhost:30000     # endpoint root; a trailing /v1 also works
  model: qwen3-32b                     # the model name your endpoint serves
  max_tokens: 4096
  timeout_seconds: 300                 # local decode is slower, and a storm's concurrent triages share the GPU
  # api_key_env: ALERTINT_LLM_API_KEY  # only if your endpoint requires auth
  # response_format: json_object       # default; set "off" if your runtime lacks enforced-JSON output
  # thinking: false                    # default. If you enable it, raise max_tokens to 8000–16000 —
  #                                    # thinking output competes with the reply for the token budget,
  #                                    # and an overrun fails triage with
  #                                    # "llm: response truncated at max_tokens" in the logs.
```

The memory shadow classifier (when enabled) follows the same endpoint and
reuses `llm.model` — a single-model local install has nothing cheaper to
route classifier calls to.

## SGLang

```bash
python -m sglang.launch_server \
  --model-path Qwen/Qwen3-32B \
  --port 30000
```

SGLang serves an OpenAI-compatible API by default, including native
`response_format: json_object` support, so the config block above works
unmodified.

## Ollama

```yaml
llm:
  provider: openai-compatible
  base_url: http://localhost:11434     # either spelling works: with or without /v1
  model: qwen3:32b                     # the model name as pulled, e.g. `ollama pull qwen3:32b`
```

## Honest quality note

Triage calibration — the verification round's contrast queries, confidence
language, and the overall finding quality — is tuned against Claude. A
self-hosted endpoint works with any instruct model your runtime serves, but
we recommend a ≥30B-class instruct model for triage-grade reasoning. The
Anthropic path remains the reference setup this project is built and tested
against; treat a local endpoint as a self-hosted alternative with its own
tuning curve, not a drop-in equivalent.

## Prompt caching

This wire format has no client-side `cache_control` breakpoint, so
`Prompt.CachePrefix` is a no-op here — every call sends the full prompt.
SGLang and vLLM both prefix-cache server-side automatically (radix-tree /
KV-cache reuse across requests with a shared prefix), so the verification
round's shared-prefix design still pays off; it just happens on the serving
side instead of being billed as a discrete cache read like Anthropic's API.

## Troubleshooting

**`llm: api error: HTTP 400 ... (set llm.response_format: "off" ...)`** — your
runtime does not support enforced-JSON output. Set
`llm.response_format: "off"` and rely on the model's instruction-following
instead.

**`llm: response truncated at max_tokens=N (raise llm.max_tokens)`** — the
reply was cut off before the JSON closed. Raise `llm.max_tokens`, or if
`llm.thinking: true` is set, either raise it further (8000–16000) or disable
thinking — reasoning output competes with the JSON reply for the same token
budget.

**404 on the very first triage call** — `llm.base_url` is pointed at the
wrong path. The client always appends `/v1/chat/completions` itself; set
`base_url` to the endpoint root (`http://localhost:30000`), not a path that
already ends in `/v1/chat/completions`.
