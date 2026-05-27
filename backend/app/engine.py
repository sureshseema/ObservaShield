from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .models import (
    Priority,
    SecurityFinding,
    Severity,
    TelemetryEvent,
    UnifiedIncident,
)
from .storage import SqliteStore


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
}


def _value_or_default(value: str | None, default: str) -> str:
    return value if value else default


def _correlation_key_parts(key: tuple[str, str, str, str]) -> str:
    return f"{key[0]}:{key[1]}:{key[2]}:{key[3]}"


def stable_incident_id(key: tuple[str, str, str, str]) -> str:
    raw = _correlation_key_parts(key)
    digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"inc-{digest}"


def _service_criticality(service_name: str | None) -> float:
    critical = {"auth", "payment", "checkout", "gateway", "identity"}
    if service_name and any(name in service_name.lower() for name in critical):
        return 1.0
    return 0.6


def _active_incident_severity(telemetry: list[TelemetryEvent]) -> float:
    if not telemetry:
        return 0.4
    max_weight = max(SEVERITY_WEIGHT[event.severity] for event in telemetry)
    return max(0.4, max_weight)


def _user_impact(telemetry: list[TelemetryEvent]) -> float:
    for event in telemetry:
        error_rate = event.metrics.get("error_rate", 0.0)
        latency_p95 = event.metrics.get("latency_p95_ms", 0.0)
        if error_rate >= 0.1 or latency_p95 >= 2000:
            return 1.0
    return 0.6


def _security_risk(findings: list[SecurityFinding]) -> float:
    if not findings:
        return 0.2
    score = 0.0
    for finding in findings:
        score += (SEVERITY_WEIGHT[finding.severity] + finding.exploitability) / 2
    return min(1.0, score / len(findings))


def _priority(score: float) -> Priority:
    if score >= 0.75:
        return Priority.P0
    if score >= 0.45:
        return Priority.P1
    return Priority.P2


def _actions(findings: list[SecurityFinding], telemetry: list[TelemetryEvent]) -> list[str]:
    actions = [
        "Run service-level rollback check and verify latest deployment diff.",
        "Validate IAM/service-account permissions against least-privilege baseline.",
        "Correlate logs + traces for the impacted service over last 30 minutes.",
    ]
    if any(f.domain.value == "cspm" for f in findings):
        actions.append("Review cloud posture drift and patch exposed network/IAM misconfigurations.")
    if any(f.domain.value == "cwpm" for f in findings):
        actions.append("Isolate suspicious workload and run container/image integrity checks.")
    if any(t.signal_type.value == "metric" for t in telemetry):
        actions.append("Confirm error budget impact and enforce temporary alert threshold guardrails.")
    return actions


def rebuild_incidents(store: SqliteStore) -> dict[str, UnifiedIncident]:
    grouped: dict[tuple[str, str, str, str], dict[str, list]] = {}

    for event in store.telemetry:
        c = event.context
        key = store.context_tuple(
            c.cloud_account,
            _value_or_default(c.cluster, "unknown-cluster"),
            _value_or_default(c.namespace, "default"),
            _value_or_default(c.service, "unknown-service"),
        )
        grouped.setdefault(key, {"telemetry": [], "findings": []})["telemetry"].append(event)

    for finding in store.findings:
        c = finding.context
        key = store.context_tuple(
            c.cloud_account,
            _value_or_default(c.cluster, "unknown-cluster"),
            _value_or_default(c.namespace, "default"),
            _value_or_default(c.service, "unknown-service"),
        )
        grouped.setdefault(key, {"telemetry": [], "findings": []})["findings"].append(finding)

    incidents: dict[str, UnifiedIncident] = {}
    now = datetime.now(timezone.utc)

    for key, group in grouped.items():
        telemetry = group["telemetry"]
        findings = group["findings"]

        risk = _security_risk(findings)
        crit = _service_criticality(key[3])
        impact = _user_impact(telemetry)
        active = _active_incident_severity(telemetry)
        score = round(risk * crit * impact * active, 3)
        priority = _priority(score)

        first_context = (telemetry[0].context if telemetry else findings[0].context)
        correlation_key = _correlation_key_parts(key)
        incident_id = stable_incident_id(key)

        created_at, updated_at, status = store.upsert_incident_meta(
            incident_id, correlation_key, now
        )

        incidents[incident_id] = UnifiedIncident(
            id=incident_id,
            correlation_key=correlation_key,
            status=status,
            created_at=created_at,
            updated_at=updated_at,
            priority=priority,
            score=score,
            summary=(
                f"{priority.value} incident on {key[3]}: "
                f"{len(telemetry)} telemetry signals and {len(findings)} security findings correlated."
            ),
            context=first_context,
            telemetry_events=telemetry,
            security_findings=findings,
            recommended_actions=_actions(findings, telemetry),
        )

    store.incidents = incidents
    return incidents
