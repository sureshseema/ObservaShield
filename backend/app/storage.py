from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import List, Tuple

from .db import connect, default_db_path, init_schema
from .models import AgentHeartbeat, AssetRecord, IncidentStatus, SecurityFinding, TelemetryEvent


class SqliteStore:
    """Append-only signals + incident lifecycle metadata (SQLite)."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or default_db_path()
        self._lock = threading.Lock()
        self._conn = connect(self._db_path)
        init_schema(self._conn)
        self.telemetry: List[TelemetryEvent] = []
        self.findings: List[SecurityFinding] = []
        self.agents: dict[str, AgentHeartbeat] = {}
        self.assets: dict[str, AssetRecord] = {}
        self.incidents: dict[str, "UnifiedIncident"] = {}
        self._load()

    def group_key(self, cloud_account: str, cluster: str, namespace: str, service: str) -> str:
        return f"{cloud_account}:{cluster}:{namespace}:{service}"

    def _load(self) -> None:
        self.telemetry.clear()
        self.findings.clear()
        self.agents.clear()
        self.assets.clear()
        cur = self._conn.cursor()
        for (payload,) in cur.execute("SELECT payload FROM telemetry ORDER BY id"):
            self.telemetry.append(TelemetryEvent.model_validate_json(payload))
        for (payload,) in cur.execute("SELECT payload FROM findings ORDER BY id"):
            self.findings.append(SecurityFinding.model_validate_json(payload))
        for (payload,) in cur.execute("SELECT payload FROM agents ORDER BY agent_id"):
            agent = AgentHeartbeat.model_validate_json(payload)
            self.agents[agent.agent_id] = agent
        for (payload,) in cur.execute("SELECT payload FROM assets ORDER BY asset_type, name"):
            asset = AssetRecord.model_validate_json(payload)
            self.assets[asset.asset_id] = asset

    def add_telemetry(self, events: List[TelemetryEvent]) -> None:
        if not events:
            return
        with self._lock:
            cur = self._conn.cursor()
            for event in events:
                cur.execute(
                    "INSERT INTO telemetry (payload) VALUES (?)",
                    (event.model_dump_json(),),
                )
            self._conn.commit()
            self.telemetry.extend(events)

    def add_findings(self, items: List[SecurityFinding]) -> None:
        if not items:
            return
        with self._lock:
            cur = self._conn.cursor()
            for finding in items:
                cur.execute(
                    "INSERT INTO findings (payload) VALUES (?)",
                    (finding.model_dump_json(),),
                )
            self._conn.commit()
            self.findings.extend(items)

    def upsert_agent(self, agent: AgentHeartbeat | None) -> None:
        if agent is None:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agents (agent_id, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (agent.agent_id, agent.model_dump_json(), agent.observed_at.isoformat()),
            )
            self._conn.commit()
            self.agents[agent.agent_id] = agent

    def upsert_assets(self, assets: List[AssetRecord]) -> None:
        if not assets:
            return
        with self._lock:
            cur = self._conn.cursor()
            for asset in assets:
                existing = self.assets.get(asset.asset_id)
                if existing is not None:
                    asset.first_seen = existing.first_seen
                cur.execute(
                    """
                    INSERT INTO assets (asset_id, asset_type, name, payload, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_id) DO UPDATE SET
                        asset_type = excluded.asset_type,
                        name = excluded.name,
                        payload = excluded.payload,
                        last_seen = excluded.last_seen
                    """,
                    (
                        asset.asset_id,
                        asset.asset_type.value,
                        asset.name,
                        asset.model_dump_json(),
                        asset.first_seen.isoformat(),
                        asset.last_seen.isoformat(),
                    ),
                )
                self.assets[asset.asset_id] = asset
            self._conn.commit()

    def context_tuple(
        self,
        cloud_account: str,
        cluster: str,
        namespace: str,
        service: str,
    ) -> Tuple[str, str, str, str]:
        return cloud_account, cluster, namespace, service

    def upsert_incident_meta(
        self,
        incident_id: str,
        correlation_key: str,
        updated_at: datetime,
    ) -> Tuple[datetime, datetime, IncidentStatus]:
        """Create row on first sight; refresh updated_at on subsequent rebuilds."""
        now_iso = updated_at.isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT created_at, updated_at, status FROM incident_meta WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO incident_meta (incident_id, correlation_key, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        correlation_key,
                        IncidentStatus.OPEN.value,
                        now_iso,
                        now_iso,
                    ),
                )
                self._conn.commit()
                return updated_at, updated_at, IncidentStatus.OPEN
            self._conn.execute(
                "UPDATE incident_meta SET updated_at = ? WHERE incident_id = ?",
                (now_iso, incident_id),
            )
            self._conn.commit()
            created = datetime.fromisoformat(row["created_at"])
            status = IncidentStatus(row["status"])
            return created, updated_at, status

    def set_incident_status(self, incident_id: str, status: IncidentStatus) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE incident_meta SET status = ?, updated_at = ? WHERE incident_id = ?",
                (status.value, datetime.now(timezone.utc).isoformat(), incident_id),
            )
            self._conn.commit()
            return cur.rowcount > 0
