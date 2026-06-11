# alertint-agent

[![CI](https://github.com/alertint/alertint-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/alertint/alertint-agent/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/alertint/alertint-agent?include_prereleases)](https://github.com/alertint/alertint-agent/releases)
[![license](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)](LICENSE)

**Self-hosted, open-core agent runtime for Alertmanager, Slack, MCP clients, and Prometheus context.** Receives webhook payloads, correlates related alerts within a time window, produces an AI finding, and exposes incident context to your AI coding agent over MCP.

## Status

Open-core and in active development (v0.1.0-rc). AlertINT runs self-hosted: it receives Alertmanager webhooks, correlates related alerts, produces an AI finding, and exposes incident plus read-only Prometheus context to your AI coding agent over MCP. The core runtime is source-available under [FSL-1.1-ALv2](LICENSE); enterprise features come later, on top.

→ **[QUICKSTART](docs/QUICKSTART.md)** · **[CONFIGURATION](docs/CONFIGURATION.md)** · **[ARCHITECTURE](docs/ARCHITECTURE.md)** · **[LIMITS](docs/LIMITS.md)**

## What it does

- Ingests Alertmanager webhook payloads and stores alerts and incidents locally
- Correlates related alerts within a time window using shared labels
- Applies an open-schema rule engine (storm collapse, known-issue short-circuits, prompt selection) driven by an embedded baseline pack — see [`docs/rules-spec.md`](docs/rules-spec.md)
- Produces an AI finding for each incident with the built-in `acute-triage` skill, backed by Anthropic Claude
- Delivers the finding to stdout and optionally Slack
- Exposes incidents, alerts, evidence packs, findings, and audit verification to your AI agent over MCP
- Answers read-only Prometheus instant and range queries over MCP for deeper metric context
- Records every action in a hash-chained audit log
- Ships as one self-hosted binary with SQLite state

## Scope and principles

- **Read-only by design** — AlertINT observes and reports; it never touches your infrastructure.
- **Self-hosted and local** — your alert data and incident context stay on your machine.
- **Open-core** — the core runtime is source-available under [FSL-1.1-ALv2](LICENSE); enterprise features come later, on top.

What it does **not** do: remediation, silences, or routing changes; Alertmanager, Kubernetes, or infrastructure writes; ticketing/paging integrations (PagerDuty, Jira, Linear); web UI; multi-tenancy; or multi-provider LLM routing. Operator-controlled, approval-gated write workflows are a far-future direction. See [`docs/LIMITS.md`](docs/LIMITS.md).

## Quickstart — Docker Compose (60 seconds)

**Prerequisites:** Docker with Compose v2, an [Anthropic API key](https://console.anthropic.com/).

```bash
# 1. Clone and enter the repo
git clone https://github.com/alertint/alertint-agent
cd alertint-agent

# 2. Create your .env file
cp .env.example .env
# Edit .env — set ALERTINT_WEBHOOK_TOKEN and ANTHROPIC_API_KEY

# 3. Start the stack (Alertmanager + agent)
docker compose -f docker/docker-compose.yaml --env-file .env up --build
```

The agent listens on **:9911** (webhook) and **:9912** (MCP); Alertmanager on **:9093**.

**Send a test alert** — POST an Alertmanager-style payload straight to the agent (no extra tooling):

```bash
curl -sS -X POST http://localhost:9911/webhook/alertmanager \
  -H "Authorization: Bearer $ALERTINT_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "4",
    "status": "firing",
    "alerts": [
      {
        "status": "firing",
        "labels": {"alertname":"DiskFull","cluster":"local","namespace":"default","service":"api","severity":"critical"},
        "annotations": {"summary":"Disk at 95% on web1"},
        "startsAt": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }
    ]
  }'
```

Within ~90 seconds you will see a JSON finding line in the agent container stdout. See [QUICKSTART](docs/QUICKSTART.md) for hooking up a real Alertmanager.

**Stop the stack:**

```bash
docker compose -f docker/docker-compose.yaml down
```

## Development

Requirements:

- Go 1.26+ (toolchain pin: `go1.26.3`)
- [Task](https://taskfile.dev) for the developer workflow

Common tasks:

```bash
task            # list tasks
task build      # build ./bin/alertint
task test       # go test -race ./...
task lint       # go vet ./...
task run        # build and run
```

## Layout

```
alertint-agent/
├── cmd/alertint/              # binary entrypoint (serve, health, verify-audit, version)
├── internal/
│   ├── audit/                 # hash-chained audit log
│   ├── config/                # YAML config loading + validation
│   ├── correlator/            # fixed-window alert correlator
│   ├── ingress/               # Alertmanager webhook receiver
│   ├── llm/anthropic/         # Anthropic Messages API client
│   ├── logging/               # slog baseline
│   ├── mcp/                   # HTTP MCP server (:9912/mcp, started inside serve)
│   ├── notify/                # Notifier interface; console, resolution, slack, stdout
│   ├── prometheus/            # read-only Prometheus HTTP client (MCP tools)
│   ├── rules/                 # open rule schema, RuleSource, engine (docs/rules-spec.md)
│   └── store/                 # SQLite store (alerts, incidents, audit_log)
├── packs/baseline/            # embedded baseline rule pack + prompt templates
├── skills/acutetriage/        # acute-triage LLM skill
├── docker/                    # Docker Compose local dev stack
├── docs/                      # QUICKSTART, CONFIGURATION, ARCHITECTURE, LIMITS
├── config.example.yaml
├── Dockerfile
├── go.mod
└── Taskfile.yml
```

## License

[Functional Source License, Version 1.1, ALv2 Future License](LICENSE) (FSL-1.1-ALv2).

Free for any internal use and self-hosting at any scale. Each release converts to
Apache 2.0 two years after publication. The only restriction is offering the
software to others as a competing commercial product or service. See
[fsl.software](https://fsl.software) for details.
