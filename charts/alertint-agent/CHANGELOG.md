# Changelog

All notable changes to the alertint-agent Helm chart will be documented in
this file. This tracks the chart's own version (`Chart.yaml`'s `version`),
independent of the alertint-agent application version (`appVersion`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this chart adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-03

### Added

- Initial chart: Deployment, Service (webhook + MCP ports), optional Ingress
  for both, optional PVC for the SQLite store, optional Secret creation (or
  bring-your-own via `secret.existingSecret`).
- Free-form `config` values block, rendered verbatim into the ConfigMap at
  `/etc/alertint/config.yaml` — mirrors `config.example.yaml` rather than
  duplicating the app's config schema into typed Helm values, so the chart
  doesn't go stale against it as the schema evolves.
- `replicas` fixed at 1 in the template (not a values knob): the SQLite
  store is single-writer by design, and a second replica produces duplicate
  incident processing and duplicate notifications rather than higher
  availability.
- `strategy.type: Recreate`, to avoid a RollingUpdate attempting to attach a
  `ReadWriteOnce` PVC to a new pod before the old one releases it.
- Liveness/readiness probes against `GET /health` on the webhook port.
- `configOverride` (raw YAML string) and `existingConfigMap`, for a
  configuration taken exactly as given — `config` is a YAML map, and Helm
  deep-merges a partial override with the chart's defaults rather than
  replacing them, which can silently leak defaults like
  `llm.api_key_env: ANTHROPIC_API_KEY` into an otherwise-complete
  OpenAI-compatible configuration.
- `secret.enabled` (default `true`): the three supported Secret modes
  (`secret.create`, `secret.existingSecret`, or `secret.enabled: false` to
  opt out) are now explicit and mutually exclusive — the chart fails the
  render with a clear message if both create and existingSecret are set,
  or if neither is set while enabled stays true, rather than deploying a
  pod referencing a Secret that doesn't exist.
- `helm.sh/resource-policy: keep` on the chart-created PVC, so stored
  incident/memory history survives `helm uninstall`; deleting it is a
  separate, manual action.
- `automountServiceAccountToken: false` — the pod needs no Kubernetes API
  access.
- `checksum/secret` pod-template annotation (alongside the existing
  `checksum/config`) when `secret.create` is true, so credential changes
  restart the pod the same way config changes already did.
- CI (`.github/workflows/chart-ci.yml`, triggered on changes under `charts/**`):
  `helm lint` and `helm template` across every toggle combination (secret
  modes, existing PVC claim, both Ingress paths, persistence disabled,
  `configOverride`/`existingConfigMap`), the rendered manifests validated
  against real Kubernetes API schemas with `kubeconform -strict`, a check
  that `README.md` matches what `helm-docs` would regenerate from
  `values.yaml`, and `helm unittest` rendering tests (see `tests/`) for all
  of the above.

### Fixed

- Default image tag now resolves to the `v`-prefixed release tag actually
  published (e.g. `v0.13.7`), matching `.Chart.AppVersion`; an explicit
  `image.tag` is still used exactly as given.
- `service.webhookPort`/`service.mcpPort` no longer change the port the
  container actually listens on — the container ports are fixed at
  9911/9912 (matching the binary's own defaults) and mapped to by name;
  previously, changing a Service port silently broke connectivity because
  nothing told the binary itself to listen elsewhere.
- Ingress hosts are now quoted, so a wildcard host like `*.example.com`
  produces valid YAML instead of being parsed as a YAML alias reference.
- Webhook Ingress now defaults to path `/webhook` with `pathType: Prefix`
  (previously `/` with `ImplementationSpecific`), so `GET /health` isn't
  unintentionally exposed through it.
- `NOTES.txt`'s MCP instructions now reflect the app's own presence-based
  enablement logic (an explicit `config.mcp.enabled`, or a token actually
  present via `secret.create`) instead of the mere existence of
  `config.mcp.addr`, which is set by default regardless of whether MCP
  actually starts. When enablement can't be determined from chart values
  alone (`secret.existingSecret`), the notes say so rather than guessing.
- Split the combined webhook+MCP Ingress template into
  `ingress-webhook.yaml` and `ingress-mcp.yaml` (previously one file with a
  hand-written `---` separator) — functionally identical output, but
  avoids a rendering issue in the `helm-unittest` tooling used for this
  chart's test suite.
