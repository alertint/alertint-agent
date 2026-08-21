<p align="center">
  <img src="docs/assets/alertint-logo.svg" alt="AlertINT" width="110">
</p>

<h1 align="center">AlertINT</h1>

<p align="center"><strong>Infrastructure incidents, decoded.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-blue" alt="license"></a>
  <a href="https://github.com/alertint/alertint-agent/releases"><img src="https://img.shields.io/github/v/release/alertint/alertint-agent?include_prereleases" alt="release"></a>
  <a href="https://github.com/alertint/alertint-agent/actions/workflows/ci.yml"><img src="https://github.com/alertint/alertint-agent/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

> AlertINT turns infrastructure alerts into investigated incidents and serves them to the AI tools you already use, over MCP — a self-hosted agent that runs inside your own network.

A single Go binary that sits between your monitoring stack and your AI agent. It ingests alert webhooks from Alertmanager and Zabbix, correlates them into incidents through an open rule engine, and runs an LLM triage that falsifies its own draft verdict before the finding ships. A proactive Situation controller owns every operational episode end to end: it decides whether and when that acute analysis has decision value, keeps one evolving Slack thread per Situation — with viewer-local update promises and a visible recovery-pending state before declaring stability — and is the only Slack writer in this build. The full Situation and Incident state, plus read-only Prometheus, Loki, and Zabbix access, is exposed to any MCP client. Judgments, Expected-behaviour envelopes, and corrections your agent captures over MCP steer the existing Situation and the next triage of the same failure. Read-only toward your infrastructure, always. Local state. You bring the LLM key.

**Full documentation: [alertint.com/docs](https://alertint.com/docs)**

## Get started

The **[Quickstart](https://alertint.com/docs/getting-started/quickstart)** is
the canonical walkthrough — install (single binary or bundled Docker Compose
stack), configure, and prove the whole pipeline with one command:

```bash
alertint drill --config config.yaml
```

The built-in drill plants a fake deploy, fires a burst of clearly-marked
synthetic alerts through the production ingress, and polls the resulting
Situation until it publishes — a causal analysis naming the planted deploy.
From zero to that Situation takes about ten minutes; then connect an MCP
client to investigate it, and point Alertmanager or
[Zabbix](https://alertint.com/docs/integrations/zabbix) at the agent for real
alerts.

## How it works

Two feedback loops close on the acute triage step: the **[verification
round](https://alertint.com/docs/concepts/verification-round)** gathers evidence
chosen to disprove the model's own draft and makes it re-judge before anything
persists, and an operator correction captured over MCP lands in **[incident
memory](https://alertint.com/docs/concepts/incident-memory)**, where it steers
the next triage of that failure group. A third loop closes at the Situation
level: a proactive Situation controller decides whether acute analysis has
decision value, publishes as soon as facts justify it (never waiting on the
model), and lets an operator judgment or a reusable Expected-behaviour
envelope steer the existing Situation root directly.

The whole pipeline — receivers, correlation, the evidence pack, all three
loops, the Situation controller, and the MCP surface — is diagrammed and
walked through step by step in
**[Architecture](https://alertint.com/docs/concepts/architecture)**.

## Documentation

- **[Docs home](https://alertint.com/docs)** — quickstart, configuration reference
- **[Architecture](https://alertint.com/docs/concepts/architecture)** — how the pipeline is built
- **[Integrations](https://alertint.com/docs/integrations/mcp-clients)** — MCP clients, [Zabbix](https://alertint.com/docs/integrations/zabbix), [Prometheus](https://alertint.com/docs/integrations/prometheus), [Loki](https://alertint.com/docs/integrations/loki), [Slack](https://alertint.com/docs/notifications/slack)
- **[Verification round](https://alertint.com/docs/concepts/verification-round)** and **[incident memory](https://alertint.com/docs/concepts/incident-memory)** — how triage checks itself and learns from corrections
- **[Scope and limits](https://alertint.com/docs/concepts/scope-and-limits)** — what it will and won't do
- **[FAQ](https://alertint.com/docs/concepts/faq)**

The [`/docs`](docs/) folder in this repo is the canonical source for those pages — the website renders it at build time. Documentation PRs are welcome here; see [`docs/README.md`](docs/README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

AlertINT is **[Fair Source](https://fair.io)**, licensed under [FSL-1.1-ALv2](LICENSE) (Functional Source License). Free to read, use, modify, and self-host at any scale. The only restriction is offering the software to others as a competing commercial product or service. Each release converts to Apache 2.0 — full open source — two years after publication. See [fsl.software](https://fsl.software) for the license text.
