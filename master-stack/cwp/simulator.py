#!/usr/bin/env python3
"""CWP simulator — pushes runtime + posture findings into ObservaShield and Loki."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

import httpx

API = os.environ.get("OBSERVASHIELD_API", "http://127.0.0.1:8080")
LOKI = os.environ.get("LOKI_URL", "http://127.0.0.1:3100")
INTERVAL = int(os.environ.get("INTERVAL_SEC", "30"))

SCENARIOS = [
    {
        "finding": {
            "domain": "cwp_runtime",
            "severity": "critical",
            "source": "cwp-simulator",
            "title": "Reverse shell detected in checkout-api pod",
            "details": "Unexpected /bin/sh spawned by node process; outbound connection to 185.x.x.x:4444",
            "exploitability": 0.95,
            "context": {
                "cloud_account": "prod-aws",
                "region": "eu-west-1",
                "cluster": "eks-prod",
                "namespace": "payments",
                "service": "checkout-api",
                "identity": "svc-checkout",
                "resource_id": "pod/checkout-api-7f9c8",
            },
            "correlation": {
                "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                "pod_name": "checkout-api-7f9c8",
                "host_id": "i-0abc123def456",
                "image_digest": "sha256:abc123",
                "service_name": "checkout-api",
            },
            "tags": ["reverse-shell", "runtime", "lateral-movement"],
            "stack_ref": "http://localhost:3000/explore?schemaVersion=1&panes={\"loki\":{\"queries\":[{\"refId\":\"A\",\"expr\":\"{service=\\\"checkout-api\\\"} |= \\\"reverse shell\\\"\"}]}}",
        },
        "telemetry": [
            {
                "signal_type": "metric",
                "severity": "high",
                "source": "mimir",
                "title": "5xx error rate spike on checkout-api",
                "details": "error_rate crossed 12% threshold over 5m window",
                "context": {
                    "cloud_account": "prod-aws",
                    "region": "eu-west-1",
                    "cluster": "eks-prod",
                    "namespace": "payments",
                    "service": "checkout-api",
                },
                "correlation": {
                    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                    "service_name": "checkout-api",
                    "pod_name": "checkout-api-7f9c8",
                },
                "metrics": {"error_rate": 0.12, "latency_p95_ms": 2800},
                "stack_ref": "http://localhost:3000/explore?left={\"datasource\":\"Mimir\",\"queries\":[{\"expr\":\"rate(http_requests_total{service=\\\"checkout-api\\\",status=~\\\"5..\\\"}[5m])\"}]}",
            },
            {
                "signal_type": "log",
                "severity": "high",
                "source": "loki",
                "title": "Error log burst on checkout-api",
                "details": "Unhandled exception in payment processor — correlation trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
                "context": {
                    "cloud_account": "prod-aws",
                    "region": "eu-west-1",
                    "cluster": "eks-prod",
                    "namespace": "payments",
                    "service": "checkout-api",
                },
                "correlation": {
                    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                    "service_name": "checkout-api",
                },
                "labels": {"level": "error", "logger": "payment.processor"},
                "stack_ref": "http://localhost:3000/explore?schemaVersion=1&panes={\"loki\":{\"queries\":[{\"refId\":\"A\",\"expr\":\"{service=\\\"checkout-api\\\"} |= \\\"Unhandled exception\\\"\"}]}}",
            },
            {
                "signal_type": "trace",
                "severity": "high",
                "source": "tempo",
                "title": "Slow/error trace on POST /checkout",
                "details": "Span checkout-api → payment-gateway returned 500 after 2.8s",
                "context": {
                    "cloud_account": "prod-aws",
                    "region": "eu-west-1",
                    "cluster": "eks-prod",
                    "namespace": "payments",
                    "service": "checkout-api",
                },
                "correlation": {
                    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                    "span_id": "00f067aa0ba902b7",
                    "service_name": "checkout-api",
                },
                "stack_ref": "http://localhost:3000/explore?schemaVersion=1&panes={\"tempo\":{\"queries\":[{\"refId\":\"A\",\"queryType\":\"traceql\",\"query\":\"{ resource.service.name = \\\"checkout-api\\\" && status = error }\"}]}}",
            },
        ],
    },
    {
        "finding": {
            "domain": "cspm",
            "severity": "high",
            "source": "cwp-simulator",
            "title": "Security group allows 0.0.0.0/0 on port 5432",
            "details": "RDS instance payments-db reachable from internet via misconfigured SG sg-0123abcd",
            "exploitability": 0.85,
            "context": {
                "cloud_account": "prod-aws",
                "region": "eu-west-1",
                "cluster": "eks-prod",
                "namespace": "payments",
                "service": "checkout-api",
                "resource_id": "sg-0123abcd",
            },
            "tags": ["internet-exposed", "attack-path", "cspm"],
        },
        "telemetry": [],
    },
    {
        "finding": {
            "domain": "vuln",
            "severity": "high",
            "source": "cwp-simulator",
            "title": "CVE-2024-3094 (xz backdoor) in active container image",
            "details": "Package xz-utils 5.6.0 loaded in memory on checkout-api workload",
            "exploitability": 0.88,
            "epss_score": 0.72,
            "context": {
                "cloud_account": "prod-aws",
                "region": "eu-west-1",
                "cluster": "eks-prod",
                "namespace": "payments",
                "service": "checkout-api",
                "resource_id": "sha256:abc123",
            },
            "correlation": {"image_digest": "sha256:abc123", "pod_name": "checkout-api-7f9c8"},
            "tags": ["cve", "runtime-validation", "active-package"],
        },
        "telemetry": [
            {
                "signal_type": "metric",
                "severity": "medium",
                "source": "mimir",
                "title": "Elevated CPU on checkout-api",
                "details": "CPU utilization at 78% — possible cryptomining or exploitation activity",
                "context": {
                    "cloud_account": "prod-aws",
                    "region": "eu-west-1",
                    "cluster": "eks-prod",
                    "namespace": "payments",
                    "service": "checkout-api",
                },
                "metrics": {"cpu_utilization": 0.78},
            }
        ],
    },
]


def push_loki(service: str, line: str) -> None:
    ts = str(int(time.time() * 1_000_000_000))
    payload = {
        "streams": [
            {
                "stream": {"service": service, "source": "cwp-simulator", "plane": "cwp"},
                "values": [[ts, line]],
            }
        ]
    }
    try:
        httpx.post(f"{LOKI}/loki/api/v1/push", json=payload, timeout=5.0)
    except httpx.HTTPError as exc:
        print(f"[cwp] loki push failed: {exc}")


def push_unified(scenario: dict) -> None:
    payload = {
        "events": scenario.get("telemetry", []),
        "findings": [scenario["finding"]],
    }
    try:
        response = httpx.post(f"{API}/ingest/unified", json=payload, timeout=10.0)
        response.raise_for_status()
        print(f"[cwp] unified ingest ok: {response.json()}")
    except httpx.HTTPError as exc:
        print(f"[cwp] unified ingest failed: {exc}")

    finding = scenario["finding"]
    service = finding["context"].get("service", "unknown")
    line = json.dumps(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "domain": finding["domain"],
            "title": finding["title"],
            "severity": finding["severity"],
        }
    )
    push_loki(service, line)


def main() -> None:
    print(f"[cwp] simulator starting — api={API} loki={LOKI} interval={INTERVAL}s")
    index = 0
    while True:
        scenario = SCENARIOS[index % len(SCENARIOS)]
        push_unified(scenario)
        index += 1
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
