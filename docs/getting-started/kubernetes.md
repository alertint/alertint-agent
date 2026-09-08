---
title: "Kubernetes (Helm)"
description: "Install the agent on Kubernetes with the AlertINT Helm chart: an OCI chart on GHCR, listed on Artifact Hub under a verified publisher, with signed releases and a values schema."
section: "Getting started"
order: 2
slug: "kubernetes"
---

# Kubernetes (Helm)

AlertINT publishes its own Helm chart for the agent. The chart lives in the
agent's repository and is released from the same pipeline as the application,
so a chart version always references an image that actually exists.

- Chart: `oci://ghcr.io/alertint/charts/alertint-agent`
- Listing: [Artifact Hub](https://artifacthub.io/packages/helm/alertint-agent/alertint-agent),
  published by the AlertINT organization as a verified publisher
- Every release is signed with cosign; a values schema validates your values
  on install, upgrade, lint and template
- Full values reference and every supported mode:
  [chart README](https://github.com/alertint/alertint-agent/blob/main/charts/alertint-agent/README.md)

## Prerequisites

- Kubernetes 1.23+ and Helm 3.8+ (OCI support)
- A PersistentVolume provisioner, unless you deliberately disable persistence
- An LLM provider: an Anthropic API key, or a self-hosted
  [OpenAI-compatible endpoint](../integrations/openai-compatible.md)

## Quick install

The shortest path, with the chart creating the Secret from values:

```bash
helm install my-alertint oci://ghcr.io/alertint/charts/alertint-agent \
  --set secret.create=true \
  --set secret.data.ALERTINT_WEBHOOK_TOKEN="$(openssl rand -hex 32)" \
  --set secret.data.ANTHROPIC_API_KEY=sk-ant-...
```

Pin a chart version for anything you intend to keep. List what is available
and install one explicitly:

```bash
helm show chart oci://ghcr.io/alertint/charts/alertint-agent
helm install my-alertint oci://ghcr.io/alertint/charts/alertint-agent --version <chart version> ...
```

## Verify the chart signature

Releases are signed keyless with the release workflow's GitHub Actions
identity; there is no long-lived signing key. Check a version before
installing it:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/alertint/alertint-agent/\.github/workflows/chart-release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/alertint/charts/alertint-agent:<chart version>
```

## Production installation

Use a reviewed values file rather than `--set`, and keep credentials out of
Helm:

```yaml
# values.yaml
secret:
  # A Secret you manage yourself (External Secrets, Sealed Secrets, SOPS, ...)
  # holding every *_env name the config references:
  # ALERTINT_WEBHOOK_TOKEN, ANTHROPIC_API_KEY, and any tokens for Slack,
  # MCP, changes or Zabbix you enable.
  existingSecret: alertint-agent

persistence:
  enabled: true
  size: 1Gi

config:
  llm:
    provider: anthropic
    api_key_env: ANTHROPIC_API_KEY
    model: claude-sonnet-5
```

```bash
helm upgrade --install my-alertint oci://ghcr.io/alertint/charts/alertint-agent \
  --version <chart version> -f values.yaml
```

Things worth knowing before the first real install:

- **One replica, by design.** The agent's SQLite store is single-writer. The
  chart hardcodes one replica and does not offer a replica count; a second
  pod against the same volume duplicates incidents and notifications
  instead of adding availability.
- **Persistence is on by default.** Disabling it means every restart starts
  from an empty incident and memory history. Back the volume up the way
  [Backup & restore](backup-restore.md) describes.
- **Configuration is the same YAML** as everywhere else, rendered into a
  ConfigMap from the `config` value. Helm deep-merges a partial `config`
  override with the chart defaults; when you need the file taken exactly as
  written, use `configOverride` or `existingConfigMap` instead. See
  [Configuration](configuration.md) for every field.
- **Ports.** The Service exposes the webhook receivers and `GET /health` on
  `service.webhookPort` (default 9911) and the MCP server on
  `service.mcpPort` (default 9912). The webhook and MCP Ingresses are
  independent: `ingress.webhook.enabled` and `ingress.mcp.enabled`.

Values are validated against the chart's schema, so a mistyped key or a
value of the wrong type fails at `helm install` or `helm template` time with
a schema error rather than rendering silently.

## Point Alertmanager at the agent

Inside the cluster, Alertmanager reaches the Service directly. `helm install`
prints the exact URL in its notes; for a release named `my-alertint` in the
`monitoring` namespace it is:

```yaml
receivers:
  - name: alertint-agent
    webhook_configs:
      - url: "http://my-alertint-alertint-agent.monitoring.svc.cluster.local:9911/webhook/alertmanager"
        send_resolved: true
        http_config:
          authorization:
            credentials_file: /etc/alertmanager/alertint_token
```

The token file holds the same value as `ALERTINT_WEBHOOK_TOKEN` in the
agent's Secret.

Then continue with the [Quickstart](quickstart.md#2-fire-a-drill) to fire a
drill and connect an MCP client.

## Upgrading

```bash
helm upgrade my-alertint oci://ghcr.io/alertint/charts/alertint-agent --version <chart version> -f values.yaml
```

Chart versions and application versions move independently; the
[chart changelog](https://github.com/alertint/alertint-agent/blob/main/charts/alertint-agent/CHANGELOG.md)
records what each chart release changes and which application version it
selects.
