# Limits and Known Weaknesses

Understanding where the agent does well — and where it doesn't — saves you from misconfigured expectations.

---

## Where it doesn't do well

### 1. High-cardinality label churn

**Problem:** If your alerts use dynamic label values (e.g. `pod=web-68f9c-xk2pq`) the correlator will create one incident per unique pod name rather than grouping the fleet-wide event. The fixed-window group key is an exact-match on all configured `group_labels`.

**Workaround:** Exclude high-cardinality labels from `correlator.group_labels`. Use stable labels like `service`, `namespace`, `alertname`.

---

### 2. Flapping alerts

**Problem:** An alert that fires, resolves, and re-fires within the correlation window will be treated as separate alerts and may produce a confusing evidence pack with both `firing` and `resolved` entries for the same fingerprint.

**Workaround:** Increase `correlator.window_seconds` to outlast typical flap cycles, or set `repeat_interval` in Alertmanager to suppress re-fires.

---

### 3. LLM confidence calibration

**Problem:** The `confidence` field in the finding is the model's self-reported confidence. It is not calibrated against historical outcomes. A 0.9 confidence does not mean 90% accuracy; it means the model expressed high certainty. Early in deployment, treat all findings as advisory regardless of confidence value.

**Philosophy:** We surface confidence as a signal for operator attention prioritisation, not as an automated gate. Human review before action is expected. The agent does not unilaterally remediate.

---

### 4. Single-alert incidents with `min_alerts > 1`

**Problem:** If an alert fires alone and `min_alerts` is set above 1, the agent still creates an incident but marks it `ready` at the end of the window regardless. The triage skill will run on a single-alert evidence pack and may produce a lower-quality analysis.

**Workaround:** Set `min_alerts: 1` to always triage, or accept that single-alert findings will have less correlation context.

---

### 5. Prometheus context depends on operator queries

**Problem:** Prometheus support is exposed as read-only MCP tools, not automatic metric enrichment in every LLM prompt. The connected agent or operator must still choose useful PromQL queries.

**Workaround:** Start with simple service-level queries for CPU, memory, latency, and error rate around the incident window. Automatic query suggestions are on the roadmap.

---

## We do not unilaterally remediate

The agent is **read-only by design**. It observes alert streams and reports structured findings. It does not:

- Execute scripts or runbooks
- Scale, restart, or delete infrastructure resources
- Open or close tickets automatically
- Modify Alertmanager silences or routing
- Write to Prometheus, Alertmanager, Kubernetes, PagerDuty, Jira, Linear, or any other operational system

Remediation actions, if added in the future, will require explicit operator approval flows. This is a far-future direction, not something AlertINT does today.

---

## Scope boundaries

The following are out of scope today and tracked on the roadmap:

- Pattern / slow-burn rollups (repeated alerts over hours or days)
- Multi-tenancy and RBAC
- Multiple LLM providers (only Anthropic today)
- Multiple skill types (only `acute-triage` today)
- Pull-based Alertmanager reconciliation on startup
- Alertmanager API control, silences, or routing changes
- Kubernetes API integration
- PagerDuty, Jira, Linear, or ticketing integrations
- Automatic Prometheus enrichment in the LLM prompt
- Cryptographic signing of audit rows (hash chain only today)
- Cost metering and per-org budget caps
- Web UI

The MCP HTTP server and read-only Prometheus query tools are core to the end-to-end investigation loop: alerts in, incident context out, your AI agent investigating over MCP.
