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

A single Go binary that sits between your monitoring stack and your AI agent. It ingests alert webhooks from Alertmanager and Zabbix, correlates them into incidents through an open rule engine, and runs an LLM triage that falsifies its own draft verdict before the finding ships. Findings go to Slack; the incident state — plus read-only Prometheus, Loki, and Zabbix access — is exposed to any MCP client. Corrections your agent captures over MCP steer the next triage of the same failure. Read-only by design. Local state. You bring the LLM key.

**Full documentation: [alertint.com/docs](https://alertint.com/docs)**

## Get started

Install the binary with Go:

```bash
go install github.com/alertint/alertint-agent/cmd/alertint@latest
```

The released multi-architecture Docker image is
`ghcr.io/alertint/alertint-agent:latest`. The
**[Quickstart](https://alertint.com/docs/getting-started/quickstart)** is the
canonical walkthrough for the bundled Docker Compose stack, configuration,
and proving the whole pipeline with one command:

```bash
alertint drill --config config.yaml
```

The built-in incident drill plants a fake deploy, fires a burst of
clearly-marked synthetic alerts through the production ingress, and polls
until triage prints the finding — a causal analysis naming the planted
deploy. From zero to that finding takes about ten minutes; then connect an
MCP client to investigate it, and point Alertmanager or
[Zabbix](https://alertint.com/docs/integrations/zabbix) at the agent for real
alerts.

## How it works

Two loops close on the triage step: the **[verification
round](https://alertint.com/docs/concepts/verification-round)** gathers evidence
chosen to disprove the model's own draft and makes it re-judge before anything
persists, and an operator correction captured over MCP lands in **[incident
memory](https://alertint.com/docs/concepts/incident-memory)**, where it steers
the next triage of that failure group.

The whole pipeline — receivers, correlation, the evidence pack, both loops, and
the MCP surface — is diagrammed and walked through step by step in
**[Architecture](https://alertint.com/docs/concepts/architecture)**.

## Documentation

- **[Docs home](https://alertint.com/docs)** — quickstart, configuration reference
- **[Architecture](https://alertint.com/docs/concepts/architecture)** — how the pipeline is built
- **[Integrations](https://alertint.com/docs/integrations/mcp-clients)** — MCP clients, [Zabbix](https://alertint.com/docs/integrations/zabbix), [Prometheus](https://alertint.com/docs/integrations/prometheus), [Loki](https://alertint.com/docs/integrations/loki), [Slack](https://alertint.com/docs/notifications/slack)
- **[Verification round](https://alertint.com/docs/concepts/verification-round)** and **[incident memory](https://alertint.com/docs/concepts/incident-memory)** — how triage checks itself and learns from corrections
- **[Scope and limits](https://alertint.com/docs/concepts/scope-and-limits)** — what it will and won't do
- **[FAQ](https://alertint.com/docs/concepts/faq)**
- **[Changelog](CHANGELOG.md)** — notable changes and upgrade notes by release

The [`/docs`](docs/) folder in this repo is the canonical source for those pages — the website renders it at build time. Documentation PRs are welcome here; see [`docs/README.md`](docs/README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Questions and support

- **Questions** — [GitHub Discussions](https://github.com/alertint/alertint-agent/discussions) (Q&A for "does it work with X", Ideas for what you wish it did)
- **Bugs** — [Issues](https://github.com/alertint/alertint-agent/issues/new/choose)
- **Security** — never in public; see [SECURITY.md](SECURITY.md)

## License

AlertINT is **[Fair Source](https://fair.io)**, licensed under [FSL-1.1-ALv2](LICENSE) (Functional Source License). Free to read, use, modify, and self-host at any scale. The only restriction is offering the software to others as a competing commercial product or service. Each release converts to Apache 2.0 — full open source — two years after publication. See [fsl.software](https://fsl.software) for the license text.
