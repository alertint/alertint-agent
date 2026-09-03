# alertint-agent

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.13.7](https://img.shields.io/badge/AppVersion-0.13.7-informational?style=flat-square)

AI-powered alert-triage agent that correlates Alertmanager/Zabbix alerts into incidents, enriches them with Mimir/Loki/Sentry evidence, and produces LLM findings.

**Homepage:** <https://alertint.com>

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8+
- An LLM provider: either an Anthropic API key, or a self-hosted
  OpenAI-compatible endpoint (SGLang, vLLM, Ollama, LM Studio) — see
  [docs/integrations/openai-compatible.md](https://alertint.com/docs/integrations/openai-compatible)
- Somewhere to send alerts from: Alertmanager, Zabbix, or both

## Installing

```bash
helm install my-alertint ./charts/alertint-agent \
  --set secret.create=true \
  --set secret.data.ALERTINT_WEBHOOK_TOKEN=$(openssl rand -hex 32) \
  --set secret.data.ANTHROPIC_API_KEY=sk-ant-...
```

For anything beyond a quick test, provide the secret yourself instead of
`secret.create` (see the `secret` block below) and set a real
`values.yaml` rather than passing everything via `--set`.

## Configuring alertint-agent itself

This chart intentionally does **not** turn every alertint-agent config field
into its own typed Helm value — the config schema is large and evolves with
the app. Instead, `values.yaml`'s `config:` block is rendered verbatim into
the ConfigMap the container reads at `/etc/alertint/config.yaml`. It ships
with a working default (Anthropic + Alertmanager only); extend or override
any section the same way you would edit `config.example.yaml` directly. See
[config.example.yaml](../../config.example.yaml) in this repo, or
[docs/getting-started/configuration.md](https://alertint.com/docs/getting-started/configuration),
for the complete schema.

Every `*_env` field you reference anywhere in `config` (e.g.
`webhook_token_env: ALERTINT_WEBHOOK_TOKEN`) needs a matching key in the
Secret named by `secret.existingSecret` (or created via `secret.data`) — the
chart exposes every key of that Secret to the container via `envFrom`, so
there's nothing else to wire up.

## A note on replicas

`replicaCount` is fixed at 1 in the templates, not just defaulted — it
cannot be overridden. alertint-agent's SQLite store is single-writer by
design; running a second replica against the same database produces
duplicate incident processing and duplicate notifications, not higher
availability. Restart handling (`strategy.type: Recreate`) and persistence
are built around this single-writer assumption.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| AlertINT maintainers |  | <https://github.com/alertint/alertint-agent> |

## Source Code

* <https://github.com/alertint/alertint-agent>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.repository | string | `"ghcr.io/alertint/alertint-agent"` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.tag | string | `""` | Overrides the image tag; defaults to .Chart.AppVersion. |
| imagePullSecrets | list | `[]` |  |
| nameOverride | string | `""` |  |
| fullnameOverride | string | `""` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.name | string | `""` |  |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.runAsUser | int | `65532` |  |
| podSecurityContext.runAsGroup | int | `65532` |  |
| podSecurityContext.fsGroup | int | `65532` |  |
| podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` |  |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| service.type | string | `"ClusterIP"` |  |
| service.webhookPort | int | `9911` | Alertmanager/change/Zabbix webhooks + GET /health. Only served when at least one receiver under config.* is enabled (see values below). |
| service.mcpPort | int | `9912` | MCP HTTP server (AI coding agents). Harmless to expose even if config.mcp is left disabled — nothing listens on it in that case. |
| ingress.enabled | bool | `false` |  |
| ingress.className | string | `""` |  |
| ingress.annotations | object | `{}` |  |
| ingress.webhook.host | string | `""` |  |
| ingress.webhook.path | string | `"/"` |  |
| ingress.webhook.pathType | string | `"ImplementationSpecific"` |  |
| ingress.webhook.tls | list | `[]` |  |
| ingress.mcp.enabled | bool | `false` |  |
| ingress.mcp.host | string | `""` |  |
| ingress.mcp.path | string | `"/"` |  |
| ingress.mcp.pathType | string | `"ImplementationSpecific"` |  |
| ingress.mcp.tls | list | `[]` |  |
| resources.requests.cpu | string | `"100m"` |  |
| resources.requests.memory | string | `"128Mi"` |  |
| resources.limits.memory | string | `"256Mi"` |  |
| nodeSelector | object | `{}` |  |
| tolerations | list | `[]` |  |
| affinity | object | `{}` |  |
| topologySpreadConstraints | list | `[]` |  |
| probes | object | `{"enabled":true,"failureThreshold":3,"initialDelaySeconds":5,"periodSeconds":15,"timeoutSeconds":5}` | Liveness/readiness probing. Uses GET /health, served alongside the webhook receivers on service.webhookPort — this requires at least one receiver (config.alertmanager, config.changes.ingress or config.zabbix.ingress) to be enabled, which is the default here (alertmanager). If you disable every receiver, disable these probes too, or the pod will never go Ready. |
| persistence.enabled | bool | `true` | Persists the SQLite store across restarts. Disabling this means every restart starts from an empty incident/memory history — fine for a throwaway demo, not for a real deployment. |
| persistence.storageClassName | string | `""` |  |
| persistence.accessMode | string | `"ReadWriteOnce"` |  |
| persistence.size | string | `"1Gi"` |  |
| persistence.existingClaim | string | `""` | Use a pre-existing PVC instead of creating one. |
| persistence.mountPath | string | `"/data"` |  |
| secret | object | `{"create":false,"data":{},"existingSecret":""}` | Secret providing every *_env value referenced anywhere in `config` below (webhook_token_env, api_key_env, bot_token_env, token_env, ...). All of its keys are exposed to the container via envFrom, so any name you reference in `config` just needs to exist as a key here.  Two ways to provide it:   1) secret.existingSecret: the name of a Secret you manage yourself      (External Secrets, Sealed Secrets, SOPS, etc.) — the recommended path      for anything beyond local testing.   2) secret.create: true with secret.data — the chart creates a plain      Secret from values. Convenient for a quick start; do not commit real      tokens into a values file under version control. |
| secret.create | bool | `false` | Create a Secret from secret.data below. |
| secret.existingSecret | string | `""` | Name of a pre-existing Secret to use instead of creating one. |
| secret.data | object | `{}` | Secret keys/values to create, only used when secret.create is true. data:   ALERTINT_WEBHOOK_TOKEN: "changeme"   ANTHROPIC_API_KEY: "changeme" |
| extraEnv | list | `[]` |  |
| extraEnvFrom | list | `[]` |  |
| extraVolumes | list | `[]` |  |
| extraVolumeMounts | list | `[]` |  |
| config | object | see config.example.yaml in the repo root for the full schema | The complete alertint-agent config, rendered verbatim to /etc/alertint/config.yaml. This mirrors config.example.yaml in the alertint-agent repo (see also docs/getting-started/configuration.md) — that file documents every available field; this chart intentionally does not duplicate the schema into typed Helm values, since it evolves with the app itself. Extend or override any section with your own values. |
