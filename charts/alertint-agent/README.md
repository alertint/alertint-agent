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
the app. Instead, `values.yaml`'s `config:` block is rendered into the
ConfigMap the container reads at `/etc/alertint/config.yaml`. It ships with a
working default (Anthropic + Alertmanager only); extend or override any
section the same way you would edit `config.example.yaml` directly. See
[config.example.yaml](../../config.example.yaml) in this repo, or
[docs/getting-started/configuration.md](https://alertint.com/docs/getting-started/configuration),
for the complete schema.

**`config` is a YAML map, and Helm deep-merges a partial override with the
chart's defaults rather than replacing them.** Setting only
`config.llm.provider` and `config.llm.base_url` for an OpenAI-compatible
setup still inherits this chart's default `config.llm.api_key_env:
ANTHROPIC_API_KEY` alongside them — almost certainly not what you want. If
you need a configuration taken exactly as given, with nothing inherited, use
one of:

- `configOverride`: a raw YAML string, rendered verbatim. A plain string
  value is never merged, so this is a true replacement of `config`.
- `existingConfigMap`: the name of a ConfigMap you manage entirely yourself
  (must contain a `config.yaml` key) — the chart mounts it instead of
  creating one, and doesn't create or need `config`/`configOverride` at all.

Every `*_env` field you reference anywhere in your configuration (e.g.
`webhook_token_env: ALERTINT_WEBHOOK_TOKEN`) needs a matching key in a
Secret — see the `secret` block below for the three supported modes
(`secret.create`, `secret.existingSecret`, or `secret.enabled: false` to
opt out entirely). Exactly one applies; the chart fails the render with a
clear message if that's ambiguous, rather than deploying a pod that can't
start.

## A note on replicas

There is no `replicaCount` value — replicas is hardcoded at 1 in the
Deployment template and cannot be overridden. alertint-agent's SQLite store
is single-writer by design; running a second replica against the same
database produces duplicate incident processing and duplicate
notifications, not higher availability. Restart handling
(`strategy.type: Recreate`) and persistence are built around this
single-writer assumption.

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
| image.tag | string | `""` | Overrides the image tag. Defaults to the "v"-prefixed release tag matching .Chart.AppVersion (e.g. AppVersion 0.13.7 -> tag v0.13.7), matching how alertint-agent's own images are actually published. An explicit value here is always used as-is, with no prefix added. |
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
| service.webhookPort | int | `9911` | External Service port for Alertmanager/change/Zabbix webhooks + GET /health. The container itself always listens on 9911 regardless of this value (it's fixed in the Deployment template and mapped by name) — this only changes what port the Service exposes it as. Only served when at least one receiver under config.* is enabled (see values below). |
| service.mcpPort | int | `9912` | External Service port for the MCP HTTP server (AI coding agents). The container always listens on 9912 regardless of this value, mapped by name the same way as webhookPort. Harmless to expose even if config.mcp is left disabled — nothing listens on it in that case. |
| ingress.enabled | bool | `false` |  |
| ingress.className | string | `""` |  |
| ingress.annotations | object | `{}` |  |
| ingress.webhook.host | string | `""` |  |
| ingress.webhook.path | string | `"/webhook"` | Prefix-matches /webhook/alertmanager, /webhook/change, etc. Kept away from "/" deliberately so GET /health isn't reachable through this Ingress just because it shares the Service. |
| ingress.webhook.pathType | string | `"Prefix"` |  |
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
| secret | object | `{"create":false,"data":{},"enabled":true,"existingSecret":""}` | Secret providing every *_env value referenced anywhere in `config` below (webhook_token_env, api_key_env, bot_token_env, token_env, ...). All of its keys are exposed to the container via envFrom, so any name you reference in `config` just needs to exist as a key here.  Exactly one of these three shapes is required — the chart fails the render with a clear message otherwise (both create and existingSecret set, or neither with enabled left true):   1) secret.existingSecret: the name of a Secret you manage yourself      (External Secrets, Sealed Secrets, SOPS, etc.) — the recommended path      for anything beyond local testing.   2) secret.create: true with secret.data — the chart creates a plain      Secret from values. Convenient for a quick start; do not commit real      tokens into a values file under version control.   3) secret.enabled: false — a deliberate opt-out of the built-in Secret      entirely (e.g. every *_env value is supplied via extraEnv/extraEnvFrom      instead). No envFrom is rendered in this case. |
| secret.enabled | bool | `true` | Set to false to opt out of the built-in Secret entirely (see mode 3 above). Only meaningful when both create and existingSecret are also left unset — otherwise the chosen Secret is used regardless. |
| secret.create | bool | `false` | Create a Secret from secret.data below. |
| secret.existingSecret | string | `""` | Name of a pre-existing Secret to use instead of creating one. |
| secret.data | object | `{}` | Secret keys/values to create, only used when secret.create is true. data:   ALERTINT_WEBHOOK_TOKEN: "changeme"   ANTHROPIC_API_KEY: "changeme" |
| extraEnv | list | `[]` |  |
| extraEnvFrom | list | `[]` |  |
| extraVolumes | list | `[]` |  |
| extraVolumeMounts | list | `[]` |  |
| existingConfigMap | string | `""` | Name of a pre-existing ConfigMap to mount at /etc/alertint instead of the one this chart would otherwise create from `config`/`configOverride`. You own its content and its key (must be named config.yaml) entirely — the chart doesn't read or validate it. Takes priority over both `config` and `configOverride` below. |
| configOverride | string | `""` | Raw YAML config, used verbatim as config.yaml instead of `config` below when non-empty. Unlike `config` (a YAML map, which Helm deep-merges with the chart's defaults on a partial override — see the warning below), a plain string value is never merged: whatever you put here is exactly what ships, with nothing inherited from the chart's defaults. Prefer this (or existingConfigMap above) over partially overriding `config` whenever you want to be certain no default leaks through — e.g. switching llm.provider to openai-compatible without also inheriting the default llm.api_key_env: ANTHROPIC_API_KEY. configOverride: |   receivers:     address: "0.0.0.0:9911"   alertmanager:     enabled: true     webhook_token_env: ALERTINT_WEBHOOK_TOKEN   ... |
| config | object | see config.example.yaml in the repo root for the full schema | The complete alertint-agent config, rendered verbatim to /etc/alertint/config.yaml — but ONLY when both existingConfigMap and configOverride above are empty. This mirrors config.example.yaml in the alertint-agent repo (see also docs/getting-started/configuration.md) — that file documents every available field; this chart intentionally does not duplicate the schema into typed Helm values, since it evolves with the app itself.  WARNING: this is a YAML map, so Helm deep-merges a partial override with the defaults below rather than replacing them — e.g. setting only config.llm.provider and config.llm.base_url still inherits this chart's default config.llm.api_key_env: ANTHROPIC_API_KEY alongside them, which is very likely not what you want for a non-Anthropic setup. If you need a config taken exactly as given with nothing inherited, use configOverride or existingConfigMap above instead. |
