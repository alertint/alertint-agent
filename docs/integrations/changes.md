---
title: "Change events"
description: "Push deploy/config/flag change events over a webhook so triage can answer \"what changed right before this?\"."
section: "Integrations"
order: 3
slug: "changes"
---

# Change events

The optional **change-events connector** answers the first question of nearly
every incident review — *what changed right before this?* — by feeding recent
deploys, config edits, and flag flips that overlap an incident's labels into the
LLM triage prompt, and exposing them over a read-only MCP tool.

Unlike Prometheus and Loki, which are **pull** connectors backed by universal
query languages, "what changed?" has no standard API across GitHub Actions,
GitLab CI, Jenkins, ArgoCD, Flux, and LaunchDarkly. So changes are **pushed**:
anything that can fire a webhook — down to a one-line `curl` at the end of a
deploy script — can feed AlertINT. Correlation reads from local SQLite at triage
time, so it stays reliable mid-incident even when an external API is slow or
itself inside the blast radius.

Read-only by design: AlertINT receives, stores, and reads change events. It
never mutates infrastructure.

## Enable it

```yaml
receivers:
  address: "0.0.0.0:9911"        # shared inbound webhook bind address

changes:
  ingress:                        # Role A: receive change webhooks (write surface)
    enabled: true
    webhook_token_env: ALERTINT_CHANGES_WEBHOOK_TOKEN
  enrichment:                     # Role B: use stored changes (triage prompt + MCP)
    # enabled: false              # optional force-off; omitted = ON when a change source is on
    window_minutes: 120           # look-back before the first alert
    max_events: 10                # cap on ranked changes attached to a prompt
  retention_days: 30              # prune changes older than this
```

The bearer token is supplied via the named environment variable, never inline:

```bash
export ALERTINT_CHANGES_WEBHOOK_TOKEN="$(openssl rand -hex 24)"
```

`ingress` and `enrichment` are independent: a satellite deployment can receive
changes (`ingress.enabled`) while a central one reads them, or one agent can do
both. Enrichment is presence-based: it turns on automatically when any change
source is active (`ingress.enabled` or the Sentry releases poller); an explicit
`enrichment.enabled: false` forces it off. See the
[configuration reference](../getting-started/configuration.md#changes).

This webhook is also how `alertint demo` plants its fake deploy: the
flagship drill POSTs a synthetic change event through this same door, so
the demo's finding can causally name "what changed" with zero extra
infrastructure. Demo events carry the reserved `alertint_demo="true"`
label — the whole `alertint_` label-key prefix is AlertINT-owned; keep it
out of your own change and alert labels.

## The change body

One canonical, source-agnostic JSON object. POST it to `/webhook/change` with a
bearer token and `Content-Type: application/json`:

```json
{
  "source": "github-actions",
  "kind": "deploy",
  "title": "checkout v1.42.0 deployed to prod",
  "labels": { "service": "checkout", "namespace": "prod" },
  "version": "v1.42.0",
  "link": "https://github.com/acme/checkout/actions/runs/123",
  "occurred_at": "2026-06-18T10:42:00Z"
}
```

| Field | Required | Notes |
|---|---|---|
| `kind` | **yes** | `deploy` / `config` / `flag` / `scale` / `rollback` (open vocabulary). The highest-signal categorical the LLM reads. |
| `labels` | **yes** | Non-empty map. AlertINT matches these against an incident's shared alert labels, so use the same vocabulary (`service`, `namespace`, `cluster`, `region`, …). |
| `source` | no | Free string; defaults to `unknown`. |
| `title` | no | Human summary the LLM reads; synthesized from `kind`/labels/`version` if omitted. |
| `version` | no | e.g. `v1.42.0` or a git SHA. |
| `link` | no | URL to the run / PR / dashboard. |
| `occurred_at` | no | RFC3339. Defaults to receive time. A value **in the future** (clock skew) is clamped to receive time; ancient values are trusted (backfill) and self-correct by falling outside the window. |

A missing `kind` or empty `labels` is rejected with `400`. Everything else is
accepted and normalized — the endpoint never returns `5xx`.

> **Match the labels you correlate on.** A change only enriches an incident when
> it shares at least one `key=value` with the incident's shared alert labels.
> A deploy emitting `{service: checkout}` will surface for an incident whose
> alerts all carry `service=checkout`.

## Emit a change

### GitHub Actions

```yaml
- name: Notify AlertINT of deploy
  if: success()
  run: |
    curl -sS -X POST "$ALERTINT_URL/webhook/change" \
      -H "Authorization: Bearer $ALERTINT_CHANGES_WEBHOOK_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "source": "github-actions",
        "kind": "deploy",
        "title": "checkout ${{ github.ref_name }} deployed to prod",
        "labels": { "service": "checkout", "namespace": "prod" },
        "version": "${{ github.ref_name }}",
        "link": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
      }'
  env:
    ALERTINT_URL: https://alertint.internal:9911
    ALERTINT_CHANGES_WEBHOOK_TOKEN: ${{ secrets.ALERTINT_CHANGES_WEBHOOK_TOKEN }}
```

### GitLab CI

```yaml
notify-alertint:
  stage: .post
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - |
      curl -sS -X POST "$ALERTINT_URL/webhook/change" \
        -H "Authorization: Bearer $ALERTINT_CHANGES_WEBHOOK_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
          \"source\": \"gitlab-ci\",
          \"kind\": \"deploy\",
          \"title\": \"checkout $CI_COMMIT_TAG deployed\",
          \"labels\": { \"service\": \"checkout\", \"namespace\": \"prod\" },
          \"version\": \"$CI_COMMIT_TAG\",
          \"link\": \"$CI_PIPELINE_URL\"
        }"
```

### Generic post-deploy hook

Any deploy script can end with a `curl`. `title`, `version`, and `link` are
optional — only `kind` and `labels` are required:

```bash
#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:?usage: notify-deploy <version>}"

curl -sS -X POST "$ALERTINT_URL/webhook/change" \
  -H "Authorization: Bearer $ALERTINT_CHANGES_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "deploy-script",
    "kind": "deploy",
    "title": "checkout '"$VERSION"' deployed to prod",
    "labels": { "service": "checkout", "namespace": "prod" },
    "version": "'"$VERSION"'"
  }'
```

### ArgoCD (`argocd-notifications`)

Add a webhook service and a template that posts on sync. In your
`argocd-notifications-cm` ConfigMap:

```yaml
service.webhook.alertint: |
  url: https://alertint.internal:9911/webhook/change
  headers:
    - name: Authorization
      value: "Bearer $alertint-changes-webhook-token"
    - name: Content-Type
      value: application/json
template.alertint-deploy: |
  webhook:
    alertint:
      method: POST
      body: |
        {
          "source": "argocd",
          "kind": "deploy",
          "title": "{{.app.metadata.name}} synced to {{.app.status.sync.revision}}",
          "labels": { "service": "{{.app.metadata.name}}", "namespace": "{{.app.spec.destination.namespace}}" },
          "version": "{{.app.status.sync.revision}}",
          "link": "{{.context.argocdUrl}}/applications/{{.app.metadata.name}}"
        }
trigger.on-deployed: |
  - when: app.status.operationState.phase in ['Succeeded'] and app.status.health.status == 'Healthy'
    send: [alertint-deploy]
```

Store the token in the `argocd-notifications-secret` Secret under
`alertint-changes-webhook-token`.

### LaunchDarkly

LaunchDarkly webhooks post their own payload shape, so point them at a small
relay (or an integration platform step) that reshapes the flag-change event into
the AlertINT body — for example a flag flip:

```json
{
  "source": "launchdarkly",
  "kind": "flag",
  "title": "flag checkout-new-pricing turned on (production)",
  "labels": { "service": "checkout", "namespace": "prod" },
  "link": "https://app.launchdarkly.com/default/production/features/checkout-new-pricing"
}
```

## Investigate over MCP

When change enrichment is enabled, the MCP server exposes a read-only
`alertint_recent_changes` tool. An investigating AI coding agent can widen the
window or pivot services beyond what auto-enrichment attached to the finding:

- `selector` — optional exact label AND-match, e.g. `{"service":"checkout","namespace":"prod"}`. Every key/value must be present on a change for it to match. Omit to return all recent changes.
- `window` — look-back in minutes (used when `start`/`end` are omitted).
- `start` / `end` — explicit RFC3339 range (overrides `window`).
- `limit` — maximum changes to return (default 50).

Triage auto-enrichment favors **recall** (any shared label, ranked by match
count then recency); the interactive tool favors **precision** (exact AND-match
on the selector you supply). Both are read-only.

## What you'll see in triage

Matched changes render in the prompt as a compact **Recent changes** block,
most-relevant-first, each carrying a `Δ8m before incident start` hint — the
single highest-signal fact for the model. When nothing matched but the connector
looked, a note ("no changes in window") renders instead, so absence of changes
is never silently mistaken for "nothing changed". The change snapshot is
persisted with the finding and replayed verbatim in
`alertint_get_evidence_pack` under the `enrichment.changes` key.
