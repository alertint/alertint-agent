#!/usr/bin/env python3
# push-synthetic-logs.py — optional local-demo convenience (logs counterpart of
# push-synthetic-metrics.sh).
#
# Seeds the demo stack's Loki with fake, multi-level log lines (DEBUG/INFO/WARN/
# ERROR/FATAL) for the instances in the bundled `burst` alert scenarios, so you
# can see:
#   1. prompt enrichment — the worker incident's triage prompt gains a
#      "Recent logs" section (see note on label mapping below), and
#   2. the read-only `loki_query_range` MCP tool returning real lines.
#
# Stream labels are {app, instance, cluster}. The agent's label_map renames the
# alert label `service` -> the Loki stream label `app` (and drops `instance`),
# so e.g. the worker incident's selector {service="worker"} becomes the LogQL
# matcher {app="worker"} which matches the worker-3 stream pushed here.
#
# Two targets (the "variant" — same fake data, different backend):
#   local  (default)  http://localhost:3100, no auth (single-binary demo Loki)
#   cloud             Grafana Cloud Logs, HTTP basic auth from env:
#                       GRAFANA_CLOUD_LOKI_URL    e.g. https://logs-prod-006.grafana.net
#                       GRAFANA_CLOUD_LOKI_USER   numeric instance/user ID
#                       GRAFANA_CLOUD_LOKI_TOKEN  access-policy token (logs:write)
#
# Usage:
#   python3 docker/push-synthetic-logs.py                      # local
#   python3 docker/push-synthetic-logs.py --target cloud       # Grafana Cloud
#   python3 docker/push-synthetic-logs.py --url http://host:3100
#
# Run it just before `task alerts:fire` so the lines fall inside the agent's
# default 15-minute look-back window.

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

# How the synthetic lines are laid out in time: newest TAIL_S before "now",
# oldest WINDOW_S further back, so they land inside default_range_minutes (15).
WINDOW_S = 540  # 9 minutes of history per stream
TAIL_S = 15     # newest line is 15s old (comfortably "before now")

# Each stream is one (app, instance, cluster) tuple with a themed line history.
# Levels are embedded in the text so the agent's error-biased line_filter
# `|~ "(?i)(error|warn|fatal|panic|fail)"` selects the WARN/ERROR/FATAL lines on
# its first pass; the DEBUG/INFO lines surface only via the unfiltered fallback
# or a direct loki_query_range. Covers the instances in both the `burst` and
# `burst-db-primary-failure` scenarios so either fires with logs present.
STREAMS = [
    # ── worker-3 (cluster=dev) — the incident that actually enriches ──────────
    # The two dev-cluster alerts (KafkaConsumerLag + HighMemoryUsage) share
    # service=worker AND instance=worker-3, so the selector survives and the
    # triage prompt gets these lines.
    {
        "app": "worker", "instance": "worker-3", "cluster": "dev",
        "lines": [
            ("INFO",  "consumer group 'alert-processor' assigned partitions [0 1 2 3]"),
            ("DEBUG", "fetched 500 records from partition=2 offset=1183402 (lag=120)"),
            ("INFO",  "committed offsets for 4 partitions"),
            ("WARN",  "consumer lag rising: 12805 messages behind on partition=1"),
            ("WARN",  "heap usage 78% (3.1GiB/4.0GiB) gc_pause=420ms"),
            ("ERROR", "rebalance triggered: session timeout, broker missed heartbeat"),
            ("WARN",  "consumer lag 52341 messages behind — downstream db-proxy saturation suspected"),
            ("ERROR", "failed to flush batch to sink: context deadline exceeded after 5s"),
            ("WARN",  "heap usage 91% (3.6GiB/4.0GiB) approaching OOM, gc thrashing"),
            ("FATAL", "OOMKilled imminent: allocation failed, 52k messages buffered"),
        ],
    },
    # ── api-1 — health endpoint down ──────────────────────────────────────────
    {
        "app": "api", "instance": "api-1", "cluster": "prod",
        "lines": [
            ("INFO",  "GET /v1/health 200 8ms"),
            ("DEBUG", "db-proxy-1 pool checkout in 3ms (active=142/200)"),
            ("WARN",  "upstream db-proxy-1 slow: 1.2s response"),
            ("ERROR", "connection refused to db-proxy-1:5432 (pool exhausted)"),
            ("ERROR", "GET /v1/health 503: dependency check failed"),
            ("WARN",  "5xx error rate 47% over last 3m"),
            ("FATAL", "liveness probe failed 3x — shutting down listener"),
        ],
    },
    # ── api-2 — failover overload ─────────────────────────────────────────────
    {
        "app": "api", "instance": "api-2", "cluster": "prod",
        "lines": [
            ("INFO",  "absorbing failover traffic from api-1"),
            ("DEBUG", "worker pool: 96 active, 12 idle"),
            ("WARN",  "cpu 88% — approaching saturation"),
            ("WARN",  "p99 latency 8.2s (normal 200ms)"),
            ("ERROR", "worker pool saturated: 0 idle threads, 240 queued"),
            ("WARN",  "cpu 97% — horizontal scaling pending"),
        ],
    },
    # ── db-proxy-1 — connection pool exhausted ────────────────────────────────
    {
        "app": "db-proxy", "instance": "db-proxy-1", "cluster": "prod",
        "lines": [
            ("INFO",  "active connections 142/200"),
            ("WARN",  "connection pool 90% utilized"),
            ("ERROR", "all 200 connections in use; 47 requests queued"),
            ("WARN",  "retry storm detected from api-2 (320 conn-attempts/s)"),
            ("ERROR", "query queue timeout: 47 requests dropped"),
        ],
    },
    # ── extra instances for the burst-db-primary-failure scenario ─────────────
    {
        "app": "db-primary", "instance": "db-primary-1", "cluster": "prod",
        "lines": [
            ("INFO",  "checkpoint complete, wal segment 0000A3 archived"),
            ("WARN",  "replication slot 'replica1' lag 8.4s"),
            ("ERROR", "health probe failed: no response within 3s"),
            ("FATAL", "primary unreachable, automatic failover not configured"),
        ],
    },
    {
        "app": "db-replica", "instance": "db-replica-1", "cluster": "prod",
        "lines": [
            ("INFO",  "streaming replication connected to primary"),
            ("ERROR", "cannot connect to primary: stale config (old endpoint)"),
            ("WARN",  "promotion attempt 2 failed, restarting"),
            ("ERROR", "startup probe failing — crash loop"),
        ],
    },
    {
        "app": "api", "instance": "api-3", "cluster": "prod",
        "lines": [
            ("INFO",  "GET /v1/orders 200 42ms"),
            ("WARN",  "db query queued: waiting on db-primary (180 in flight)"),
            ("ERROR", "query timeout after 30s (db primary unavailable)"),
            ("WARN",  "heap 4.2GiB growing 200MiB/min from queued requests"),
        ],
    },
    {
        "app": "api", "instance": "api-4", "cluster": "prod",
        "lines": [
            ("INFO",  "retry loop reconnecting to db primary"),
            ("ERROR", "connection pool exhausted waiting for db primary"),
            ("ERROR", "returning 503 to client: db unavailable (error rate 62%)"),
            ("WARN",  "cpu 78% from retry loops (100ms backoff per thread)"),
        ],
    },
]


def assign_timestamps(now_ns, count):
    """Return `count` nanosecond-epoch timestamps, ascending (oldest first),
    spanning [now-TAIL_S-WINDOW_S, now-TAIL_S]."""
    if count <= 1:
        return [now_ns - TAIL_S * 1_000_000_000]
    step = WINDOW_S / (count - 1)
    out = []
    for i in range(count):
        sec_ago = TAIL_S + (WINDOW_S - i * step)
        out.append(now_ns - int(sec_ago * 1_000_000_000))
    return out


def build_payload():
    now_ns = time.time_ns()
    streams = []
    for s in STREAMS:
        ts = assign_timestamps(now_ns, len(s["lines"]))
        values = [
            [str(ts[i]), f'{level:<5} {msg}']
            for i, (level, msg) in enumerate(s["lines"])
        ]
        streams.append({
            "stream": {"app": s["app"], "instance": s["instance"], "cluster": s["cluster"]},
            "values": values,
        })
    return {"streams": streams}


def wait_ready(base_url, timeout_s=30):
    """Poll GET /ready until Loki reports ready (local only)."""
    deadline = time.time() + timeout_s
    url = base_url.rstrip("/") + "/ready"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except urllib.error.HTTPError as e:
            if e.code == 200:
                return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    return False


def push(base_url, payload, auth_header=None):
    url = base_url.rstrip("/") + "/loki/api/v1/push"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if auth_header:
        req.add_header("Authorization", auth_header)
    with urllib.request.urlopen(req, timeout=15) as resp:
        if resp.status not in (200, 204):
            raise RuntimeError(f"unexpected status {resp.status}: {resp.read().decode('utf-8', 'replace')}")


def main():
    ap = argparse.ArgumentParser(description="Push synthetic multi-level logs to Loki.")
    ap.add_argument("--target", choices=["local", "cloud"], default="local",
                    help="local single-binary Loki (default) or Grafana Cloud Logs")
    ap.add_argument("--url", default=None,
                    help="override base URL (defaults: local=http://localhost:3100, cloud=$GRAFANA_CLOUD_LOKI_URL)")
    args = ap.parse_args()

    auth_header = None
    if args.target == "cloud":
        base_url = args.url or os.environ.get("GRAFANA_CLOUD_LOKI_URL", "")
        user = os.environ.get("GRAFANA_CLOUD_LOKI_USER", "")
        token = os.environ.get("GRAFANA_CLOUD_LOKI_TOKEN", "")
        missing = [n for n, v in (
            ("GRAFANA_CLOUD_LOKI_URL", base_url),
            ("GRAFANA_CLOUD_LOKI_USER", user),
            ("GRAFANA_CLOUD_LOKI_TOKEN", token),
        ) if not v]
        if missing:
            print(f"error: cloud target needs env vars: {', '.join(missing)}", file=sys.stderr)
            print("       (set them in .env; `task logs:push:cloud` loads it for you)", file=sys.stderr)
            return 2
        raw = f"{user}:{token}".encode("utf-8")
        auth_header = "Basic " + base64.b64encode(raw).decode("ascii")
    else:
        base_url = args.url or "http://localhost:3100"

    payload = build_payload()
    n_streams = len(payload["streams"])
    n_lines = sum(len(s["values"]) for s in payload["streams"])

    print(f"Pushing {n_lines} synthetic log lines across {n_streams} streams to {base_url} ...")

    if args.target == "local":
        if not wait_ready(base_url):
            print(f"warning: {base_url}/ready did not report ready; pushing anyway", file=sys.stderr)

    try:
        push(base_url, payload, auth_header)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        print(f"error: push failed: HTTP {e.code}: {body}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 — demo convenience script
        print(f"error: push failed: {e}", file=sys.stderr)
        return 1

    print("Done. Logs are now in Loki.")
    print("")
    print("Try in Claude Code (via the loki_query_range MCP tool):")
    print('  {app="worker"}                      # the enriched incident')
    print('  {app="api"} |~ "(?i)(error|fatal)"  # api error lines')
    print('  {cluster="prod"}                    # everything in prod')
    print("")
    print("Or fire alerts and watch the worker incident's triage prompt gain a")
    print("'Recent logs' section:  task alerts:fire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
