#!/usr/bin/env bash
# Seed the master stack with sample OTLP metrics, logs, and traces via ObservaAgent.
set -euo pipefail

OTLP_HTTP="${OTLP_HTTP:-http://127.0.0.1:4318}"
API="${OBSERVASHIELD_API:-http://127.0.0.1:8080}"
NOW_NS=$(python3 -c "import time; print(int(time.time()*1e9))")

echo "==> Pushing OTLP metrics batch to ObservaAgent at $OTLP_HTTP"
curl -sf -X POST "$OTLP_HTTP/v1/metrics" \
  -H 'Content-Type: application/json' \
  -d "{
    \"resourceMetrics\": [{
      \"resource\": {\"attributes\": [{\"key\": \"service.name\", \"value\": {\"stringValue\": \"checkout-api\"}}]},
      \"scopeMetrics\": [{
        \"metrics\": [{
          \"name\": \"http_requests_total\",
          \"sum\": {
            \"dataPoints\": [{
              \"asInt\": \"142\",
              \"timeUnixNano\": \"$NOW_NS\",
              \"attributes\": [{\"key\": \"status\", \"value\": {\"stringValue\": \"500\"}}]
            }]
          }
        }]
      }]
    }]
  }" && echo " metrics ok"

echo "==> Pushing OTLP log record to ObservaAgent"
curl -sf -X POST "$OTLP_HTTP/v1/logs" \
  -H 'Content-Type: application/json' \
  -d "{
    \"resourceLogs\": [{
      \"resource\": {\"attributes\": [{\"key\": \"service.name\", \"value\": {\"stringValue\": \"checkout-api\"}}]},
      \"scopeLogs\": [{
        \"logRecords\": [{
          \"timeUnixNano\": \"$NOW_NS\",
          \"severityText\": \"ERROR\",
          \"body\": {\"stringValue\": \"payment processor timeout after 2800ms\"},
          \"attributes\": [{\"key\": \"trace_id\", \"value\": {\"stringValue\": \"4bf92f3577b34da6a3ce929d0e0e4736\"}}]
        }]
      }]
    }]
  }" && echo " logs ok"

echo "==> Pushing unified ObservaAgent correlation batch to ObservaShield"
curl -sf -X POST "$API/ingest/unified" \
  -H 'Content-Type: application/json' \
  -d '{
    "agent": {
      "agent_id": "agent-eks-prod-node-a",
      "mode": "kubernetes",
      "version": "0.1.0",
      "tenant_id": "customer-001",
      "cluster": "eks-prod",
      "hostname": "ip-10-42-1-25",
      "status": "healthy",
      "capabilities": ["metrics", "logs", "traces", "kubernetes-events", "vulnerability-scan", "cwp-runtime"]
    },
    "assets": [
      {
        "asset_id": "node:prod-aws:eks-prod:ip-10-42-1-25",
        "asset_type": "node",
        "name": "ip-10-42-1-25",
        "context": {
          "cloud_account": "prod-aws",
          "region": "eu-west-1",
          "cluster": "eks-prod",
          "resource_id": "node/ip-10-42-1-25"
        },
        "source_agent_id": "agent-eks-prod-node-a",
        "labels": {
          "kubernetes.io/os": "linux"
        }
      }
    ],
    "events": [
      {
        "signal_type": "trace",
        "severity": "high",
        "source": "tempo",
        "title": "Error span on POST /checkout",
        "details": "checkout-api returned 500; trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
        "context": {
          "cloud_account": "prod-aws",
          "region": "eu-west-1",
          "cluster": "eks-prod",
          "namespace": "payments",
          "service": "checkout-api"
        },
        "correlation": {
          "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
          "span_id": "00f067aa0ba902b7",
          "service_name": "checkout-api"
        }
      }
    ],
    "findings": [
      {
        "domain": "cwp_runtime",
        "severity": "critical",
        "source": "observaagent",
        "title": "IMDS credential access attempt",
        "details": "Process curl accessed 169.254.169.254 from checkout-api pod",
        "exploitability": 0.92,
        "context": {
          "cloud_account": "prod-aws",
          "region": "eu-west-1",
          "cluster": "eks-prod",
          "namespace": "payments",
          "service": "checkout-api",
          "resource_id": "pod/checkout-api-7f9c8"
        },
        "correlation": {
          "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
          "pod_name": "checkout-api-7f9c8"
        },
        "tags": ["imds", "credential-access", "runtime"]
      }
    ]
  }' && echo ""

echo "==> Master stack seed complete"
echo "    Grafana:  http://localhost:3000"
echo "    Stack API: $API/stack/status"
echo "    Incidents: $API/incidents"
