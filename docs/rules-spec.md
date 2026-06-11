# Rule Pack Specification

AlertINT separates **mechanism** from **content**: the engine (schema,
validation, loading, evaluation) lives in this repo; rules and prompt
templates are content shipped in *packs*. The **baseline pack**
(`packs/baseline/`) is embedded in the binary, so the runtime triages
incidents with zero rules configuration. Additional packs load through the
same `RuleSource` interface (see [Sources](#sources)).

## Pack layout

```
packs/<name>/
├── pack.yaml            # metadata + defaults
├── rules/*.yaml         # rule lists, loaded in lexical order
└── templates/*.md       # LLM prompt templates, keyed by basename
```

`pack.yaml`:

```yaml
name: baseline
version: 0.1.0
updated: 2026-06-11
description: One-line purpose.
defaults:
  flap:                  # generic flap-detection thresholds (content, not code)
    window_seconds: 600
    min_transitions: 4
```

Each `rules/*.yaml` file holds a `rules:` list. Unknown YAML fields are
rejected at load — schema drift fails loud.

## Rule schema

```yaml
rules:
  - id: baseline.alert-storm-collapse   # required, unique across all packs
    kind: correlation                   # grouping | correlation | known_issue | enrichment
    description: Optional one-liner shown in findings and logs.
    priority: 100                       # higher evaluates first (default 0)
    window: 5m                          # Go duration; max spread of member alerts
    when:                               # match side — every condition must hold
      min_alerts: 20                    # at least N member alerts
      min_distinct:                     # at least N distinct values of a label
        label: service
        count: 5
      sharing_labels: [cluster]         # all alerts carry identical values
      all:                              # every predicate satisfied by ≥1 alert
        - label: severity
          op: in
          values: [warning, critical]
      any:                              # at least one predicate satisfied
        - label: alertname
          op: regex
          value: "^High"
    then:                               # action side
      action: collapse                  # group | collapse | annotate
      suppress: true                    # one incident-level notification only
      group_by: [cluster, service]      # grouping rules: incident group key labels
      root_cause_hint: "..."            # curated diagnosis passed to analysis
      analysis_template: storm          # prompt template name from templates/
      short_circuit_llm: false          # true = finding comes from the rule, no LLM call
      severity: high                    # low | medium | high (short-circuit findings)
      references: ["https://..."]       # links attached to the finding
    applies_to:                         # optional component/version constraints
      component: cni                    # matches "component" label, falls back to "service"
      versions: ["1.2.*", "1.3.0"]      # exact or prefix wildcard against "version" label
    updated: "2026-06-11"               # required, YYYY-MM-DD
```

### Predicates

Exactly one of `label`, `field`, or `metric` per predicate.

| Key | Meaning |
|---|---|
| `label: <name>` | match against an alert label |
| `field: status` | match against the alert status (`firing` / `resolved`) |
| `metric: {...}` | **reserved** — accepted by the schema, rejected by the v1 engine at load |

Operators: `equals`, `not_equals`, `regex` (RE2), `in` (with `values:`),
`exists`.

### Evaluation semantics

- Rules are evaluated against an **incident** (its member alerts), highest
  `priority` first; the first match wins.
- A predicate matches the incident when **at least one** member alert
  satisfies it (existential). `all` requires every predicate to be
  satisfied; `any` requires one.
- `window` bounds the spread between the earliest and latest member alert.
- `grouping` rules are not evaluated per incident — they describe how the
  correlator forms incidents (group key labels) and document pack-level
  grouping intent.
- Invalid rules abort startup with `rule <id>: <field>: <reason>` messages.

## Worked examples

### 1. Label grouping

Group alerts by topology so one incident never mixes clusters or services,
and keep environments apart:

```yaml
rules:
  - id: myorg.group-by-topology
    kind: grouping
    description: Group alerts by alertname and topology labels.
    when:
      sharing_labels: [cluster, namespace, service]
    then:
      action: group
      group_by: [alertname, cluster, namespace, service]
    updated: "2026-06-11"
```

### 2. Generic storm collapse

Twenty or more alerts across five or more services inside five minutes is
a storm: collapse to a single finding, suppress individual paging, and
analyze with the storm prompt:

```yaml
rules:
  - id: myorg.alert-storm-collapse
    kind: correlation
    priority: 100
    window: 5m
    when:
      min_alerts: 20
      min_distinct: {label: service, count: 5}
    then:
      action: collapse
      suppress: true
      analysis_template: storm
      root_cause_hint: A shared dependency is the likely common cause.
    updated: "2026-06-11"
```

### 3. Known-issue rule

A curated diagnosis for a known failure mode: when it matches, the engine
short-circuits the LLM and the finding comes straight from the rule —
deterministic, instant, and free:

```yaml
rules:
  - id: myorg.cni-conntrack-exhaustion
    kind: known_issue
    description: Conntrack table exhaustion on CNI 1.2.x
    when:
      all:
        - label: alertname
          op: equals
          value: ConntrackTableFull
    then:
      short_circuit_llm: true
      root_cause_hint: >-
        nf_conntrack table is full; new connections are dropped. Raise
        nf_conntrack_max or reduce connection churn.
      severity: high
      references:
        - https://example.org/kb/conntrack
    applies_to:
      component: cni
      versions: ["1.2.*"]
    updated: "2026-06-11"
```

## Prompt templates

`templates/*.md` files are LLM system prompts selected per incident:

| Template | Used when |
|---|---|
| `correlated` | default for multi-alert incidents |
| `single_alert` | incidents with exactly one alert |
| `storm` | selected by a rule via `analysis_template` |
| `recovery` | reserved for resolved-incident summaries |

Every template must instruct the model to emit the same JSON schema
(`analysis_name`, `overall_issue`, `correlation_findings`, `severity`,
`confidence`, `alerts[]`) — the pipeline parses all analyses identically.

## Sources

The engine merges packs from every configured `RuleSource` in priority
order; a higher-priority source overrides a lower one per rule `id` and
per template name.

- **EmbeddedSource**: `packs/baseline/` compiled into the binary. Always
  loads, priority 0.
- **Local pack directory**: set `rules.local_pack_dir` in the agent config
  to a directory with the standard pack layout (`pack.yaml`, `rules/*.yaml`,
  `templates/*.md`). Loads at a higher priority than the baseline, so your
  rules and templates override baseline ones with the same id/name. A
  working starter pack lives in [`examples/rules/`](../examples/rules/).
- **FeedSource** (planned): HTTPS fetch → ed25519 signature verification
  (`VerifyPackSignature`, already in the engine) → local cache → hot
  reload. Slots in without engine changes.

## Testing your rules

The fixture harness in `internal/rules` doubles as the pack QA tool: drop
a synthetic alert stream under `internal/rules/testdata/streams/` stating
the expected decision, and `go test ./internal/rules/` verifies it:

```yaml
name: storm-collapse
alerts:
  - labels: {alertname: HighErrorRate, cluster: prod, service: svc}
    repeat: 24            # expand into 24 alerts...
    spread: [service]     # ...with distinct service values
expect:
  rule_id: baseline.alert-storm-collapse
  template: storm
  suppress: true
```
