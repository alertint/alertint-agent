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
- CI (`.github/workflows/chart-ci.yml`, triggered on changes under `charts/**`):
  `helm lint`, `helm template` with default values and with every toggle
  exercised at once (secret creation, existing PVC claim, both Ingress
  paths, persistence disabled), the rendered manifests validated against
  real Kubernetes API schemas with `kubeconform -strict`, and a check that
  `README.md` matches what `helm-docs` would regenerate from `values.yaml`.
