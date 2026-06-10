#!/usr/bin/env bash
# push-synthetic-metrics.sh — optional local-demo convenience.
#
# Populates the demo stack's Prometheus (via Pushgateway) with metric values
# that match the example alert scenarios (api failover, worker memory/lag, db
# connection pool exhaustion) so you can try the prometheus_query and
# prometheus_query_range MCP tools without a real metrics source. Not part of
# the agent's runtime — purely a convenience for the bundled Docker Compose demo.
#
# Usage:
#   ./push-synthetic-metrics.sh             # uses http://localhost:9091
#   ./push-synthetic-metrics.sh http://host:9091
#
# After pushing, query in Claude Code:
#   "Show me CPU usage per instance"
#   → prometheus_query: cpu_usage_percent
#
#   "Show me the error rate trend over the last hour"
#   → prometheus_query_range: http_request_error_rate_percent

set -euo pipefail
PGW="${1:-http://localhost:9091}"

push() {
  local job="$1" instance="$2"
  shift 2
  printf '%s\n' "$@" | curl -s --data-binary @- "$PGW/metrics/job/alertint_synthetic/instance/$instance"
}

echo "Pushing synthetic metrics to $PGW ..."

# ── api-1: failed instance ───────────────────────────────────────────────────
push alertint_synthetic api-1 \
  '# HELP cpu_usage_percent CPU usage percentage (0–100)' \
  '# TYPE cpu_usage_percent gauge' \
  'cpu_usage_percent{service="api",cluster="prod",region="eu-west-1"} 2.1' \
  '# HELP http_request_error_rate_percent Percentage of 5xx responses' \
  '# TYPE http_request_error_rate_percent gauge' \
  'http_request_error_rate_percent{service="api",cluster="prod",region="eu-west-1"} 47.0' \
  '# HELP http_request_latency_p99_seconds P99 request latency in seconds' \
  '# TYPE http_request_latency_p99_seconds gauge' \
  'http_request_latency_p99_seconds{service="api",cluster="prod",region="eu-west-1"} 0.0' \
  '# HELP instance_up Whether the instance is reachable (1=up, 0=down)' \
  '# TYPE instance_up gauge' \
  'instance_up{service="api",cluster="prod",region="eu-west-1"} 0'

# ── api-2: overloaded failover ────────────────────────────────────────────────
push alertint_synthetic api-2 \
  '# TYPE cpu_usage_percent gauge' \
  'cpu_usage_percent{service="api",cluster="prod",region="eu-west-1"} 97.0' \
  '# TYPE http_request_error_rate_percent gauge' \
  'http_request_error_rate_percent{service="api",cluster="prod",region="eu-west-1"} 3.2' \
  '# TYPE http_request_latency_p99_seconds gauge' \
  'http_request_latency_p99_seconds{service="api",cluster="prod",region="eu-west-1"} 8.2' \
  '# TYPE instance_up gauge' \
  'instance_up{service="api",cluster="prod",region="eu-west-1"} 1'

# ── worker-3: consumer lag + memory pressure ──────────────────────────────────
push alertint_synthetic worker-3 \
  '# HELP memory_usage_percent Memory usage percentage (0–100)' \
  '# TYPE memory_usage_percent gauge' \
  'memory_usage_percent{service="worker",cluster="prod",region="eu-west-1"} 91.0' \
  '# HELP kafka_consumer_lag_messages Kafka consumer group lag in messages' \
  '# TYPE kafka_consumer_lag_messages gauge' \
  'kafka_consumer_lag_messages{service="worker",cluster="prod",region="eu-west-1",consumer_group="alert-processor"} 52341'

# ── db-proxy-1: connection pool exhausted ────────────────────────────────────
push alertint_synthetic db-proxy-1 \
  '# HELP db_connection_pool_used Active database connections' \
  '# TYPE db_connection_pool_used gauge' \
  'db_connection_pool_used{service="db-proxy",cluster="prod",region="eu-west-1"} 200' \
  '# HELP db_connection_pool_max Maximum database connections' \
  '# TYPE db_connection_pool_max gauge' \
  'db_connection_pool_max{service="db-proxy",cluster="prod",region="eu-west-1"} 200' \
  '# HELP db_queued_requests Requests queued waiting for a connection' \
  '# TYPE db_queued_requests gauge' \
  'db_queued_requests{service="db-proxy",cluster="prod",region="eu-west-1"} 47'

echo "Done. Metrics are now available in Prometheus at http://localhost:9090"
echo ""
echo "Try in Claude Code:"
echo '  prometheus_query: cpu_usage_percent'
echo '  prometheus_query: kafka_consumer_lag_messages'
echo '  prometheus_query: db_connection_pool_used / db_connection_pool_max * 100'
