from __future__ import annotations

import os
from typing import Iterable

import httpx

from .models import (
    MasterStackStatus,
    SecurityDomain,
    SignalInventory,
    SignalType,
    StackBackendStatus,
)
from .storage import SqliteStore

DEFAULT_BACKENDS = {
    "mimir": ("http://127.0.0.1:9009/prometheus/api/v1/status/buildinfo", "metrics"),
    "loki": ("http://127.0.0.1:3100/ready", "logs"),
    "tempo": ("http://127.0.0.1:3200/ready", "traces"),
    "grafana": ("http://127.0.0.1:3000/api/health", "visualization"),
    "observaagent": ("http://127.0.0.1:12345/-/ready", "collector"),
}


def _env_url(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _backend_targets() -> dict[str, tuple[str, str]]:
    return {
        "mimir": (
            _env_url("OBSERVASHIELD_MIMIR_URL", DEFAULT_BACKENDS["mimir"][0]),
            DEFAULT_BACKENDS["mimir"][1],
        ),
        "loki": (
            _env_url("OBSERVASHIELD_LOKI_URL", DEFAULT_BACKENDS["loki"][0]),
            DEFAULT_BACKENDS["loki"][1],
        ),
        "tempo": (
            _env_url("OBSERVASHIELD_TEMPO_URL", DEFAULT_BACKENDS["tempo"][0]),
            DEFAULT_BACKENDS["tempo"][1],
        ),
        "grafana": (
            _env_url("OBSERVASHIELD_GRAFANA_URL", DEFAULT_BACKENDS["grafana"][0]),
            DEFAULT_BACKENDS["grafana"][1],
        ),
        "observaagent": (
            _env_url("OBSERVASHIELD_AGENT_URL", DEFAULT_BACKENDS["observaagent"][0]),
            DEFAULT_BACKENDS["observaagent"][1],
        ),
    }


async def _probe(name: str, url: str, role: str) -> StackBackendStatus:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(url)
            healthy = response.status_code < 400
            detail = "ready" if healthy else f"HTTP {response.status_code}"
    except httpx.HTTPError as exc:
        healthy = False
        detail = str(exc)
    return StackBackendStatus(name=name, role=role, url=url, healthy=healthy, detail=detail)


def _count_inventory(store: SqliteStore) -> SignalInventory:
    inventory = SignalInventory()
    for event in store.telemetry:
        inventory.total_telemetry += 1
        if event.signal_type == SignalType.METRIC:
            inventory.metrics += 1
        elif event.signal_type == SignalType.LOG:
            inventory.logs += 1
        elif event.signal_type == SignalType.TRACE:
            inventory.traces += 1
        elif event.signal_type == SignalType.PROFILE:
            inventory.profiles += 1
        elif event.signal_type == SignalType.EVENT:
            inventory.events += 1

    for finding in store.findings:
        inventory.total_security += 1
        if finding.domain in (SecurityDomain.CWP_RUNTIME, SecurityDomain.CWPM):
            inventory.cwp_runtime += 1
        elif finding.domain == SecurityDomain.CSPM:
            inventory.cspm += 1
        elif finding.domain == SecurityDomain.VULN:
            inventory.vuln += 1
        elif finding.domain == SecurityDomain.AI_SPM:
            inventory.ai_spm += 1

    return inventory


async def get_master_stack_status(store: SqliteStore) -> MasterStackStatus:
    targets = _backend_targets()
    agent_url, agent_role = targets.pop("observaagent")
    agent = await _probe("observaagent", agent_url, agent_role)

    backends: list[StackBackendStatus] = []
    for name, (url, role) in targets.items():
        backends.append(await _probe(name, url, role))

    return MasterStackStatus(
        observaagent=agent,
        backends=backends,
        inventory=_count_inventory(store),
    )


def cwp_domains() -> Iterable[SecurityDomain]:
    return (SecurityDomain.CWP_RUNTIME, SecurityDomain.CWPM)
