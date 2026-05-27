from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .engine import rebuild_incidents
from .models import (
    AgentHeartbeat,
    AgentStatus,
    AssetRecord,
    AssetType,
    IncidentStatus,
    MasterStackStatus,
    OverviewResponse,
    SecurityFinding,
    SignalInventory,
    SignalType,
    TelemetryEvent,
    UnifiedIncident,
)
from .stack import get_master_stack_status
from .storage import SqliteStore

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

app = FastAPI(
    title="ObservaShield API",
    description="ObservaShield — correlate observability and security signals into prioritized incidents (MVP).",
    version="0.2.0",
)
store = SqliteStore()
rebuild_incidents(store)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TelemetryIngestRequest(BaseModel):
    events: list[TelemetryEvent] = Field(default_factory=list)


class SecurityIngestRequest(BaseModel):
    findings: list[SecurityFinding] = Field(default_factory=list)


class UnifiedIngestRequest(BaseModel):
    """ObservaAgent batch ingest — metrics, logs, traces, and CWP in one call."""

    agent: AgentHeartbeat | None = None
    assets: list[AssetRecord] = Field(default_factory=list)
    events: list[TelemetryEvent] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)


class IncidentPatchRequest(BaseModel):
    status: IncidentStatus


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "product": "ObservaShield"}


def _learn_assets_from_contexts(
    events: list[TelemetryEvent],
    findings: list[SecurityFinding],
    agent: AgentHeartbeat | None,
) -> list[AssetRecord]:
    learned: dict[str, AssetRecord] = {}
    source_agent_id = agent.agent_id if agent else None
    for signal in [*events, *findings]:
        context = signal.context
        if context.cluster:
            asset_id = f"cluster:{context.cloud_account}:{context.cluster}"
            learned[asset_id] = AssetRecord(
                asset_id=asset_id,
                asset_type=AssetType.CLUSTER,
                name=context.cluster,
                context=context,
                source_agent_id=source_agent_id,
            )
        if context.service:
            service_scope = context.cluster or context.region or context.cloud_account
            namespace = context.namespace or "default"
            asset_id = f"service:{context.cloud_account}:{service_scope}:{namespace}:{context.service}"
            learned[asset_id] = AssetRecord(
                asset_id=asset_id,
                asset_type=AssetType.SERVICE,
                name=context.service,
                context=context,
                source_agent_id=source_agent_id,
            )
        if context.resource_id:
            asset_id = f"resource:{context.cloud_account}:{context.resource_id}"
            learned[asset_id] = AssetRecord(
                asset_id=asset_id,
                asset_type=AssetType.CLOUD_RESOURCE,
                name=context.resource_id,
                context=context,
                source_agent_id=source_agent_id,
            )
    return list(learned.values())


def _signal_inventory() -> SignalInventory:
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
        key = finding.domain.value
        if key in ("cwp_runtime", "cwpm"):
            inventory.cwp_runtime += 1
        elif key == "cspm":
            inventory.cspm += 1
        elif key == "vuln":
            inventory.vuln += 1
        elif key == "ai_spm":
            inventory.ai_spm += 1
    return inventory


@app.post("/ingest/telemetry")
def ingest_telemetry(payload: TelemetryIngestRequest) -> dict[str, int]:
    store.add_telemetry(payload.events)
    store.upsert_assets(_learn_assets_from_contexts(payload.events, [], None))
    rebuild_incidents(store)
    return {"accepted": len(payload.events), "incidents": len(store.incidents)}


@app.post("/ingest/security")
def ingest_security(payload: SecurityIngestRequest) -> dict[str, int]:
    store.add_findings(payload.findings)
    store.upsert_assets(_learn_assets_from_contexts([], payload.findings, None))
    rebuild_incidents(store)
    return {"accepted": len(payload.findings), "incidents": len(store.incidents)}


@app.post("/ingest/unified")
def ingest_unified(payload: UnifiedIngestRequest) -> dict[str, int | dict[str, int]]:
    """Primary ObservaAgent → ObservaShield ingest for all signal planes."""
    store.upsert_agent(payload.agent)
    learned_assets = _learn_assets_from_contexts(payload.events, payload.findings, payload.agent)
    store.upsert_assets([*payload.assets, *learned_assets])
    store.add_telemetry(payload.events)
    store.add_findings(payload.findings)
    rebuild_incidents(store)
    return {
        "accepted": {
            "telemetry": len(payload.events),
            "security": len(payload.findings),
            "assets": len(payload.assets) + len(learned_assets),
            "agents": 1 if payload.agent else 0,
        },
        "incidents": len(store.incidents),
    }


@app.post("/agents/heartbeat", response_model=AgentHeartbeat)
def agent_heartbeat(payload: AgentHeartbeat) -> AgentHeartbeat:
    store.upsert_agent(payload)
    return payload


@app.get("/agents", response_model=list[AgentHeartbeat])
def list_agents() -> list[AgentHeartbeat]:
    return sorted(store.agents.values(), key=lambda agent: agent.agent_id)


@app.get("/assets", response_model=list[AssetRecord])
def list_assets() -> list[AssetRecord]:
    return sorted(store.assets.values(), key=lambda asset: (asset.asset_type.value, asset.name))


@app.get("/overview", response_model=OverviewResponse)
def overview() -> OverviewResponse:
    agent_counts = {"total": len(store.agents), "healthy": 0, "degraded": 0, "offline": 0}
    for agent in store.agents.values():
        if agent.status == AgentStatus.HEALTHY:
            agent_counts["healthy"] += 1
        elif agent.status == AgentStatus.DEGRADED:
            agent_counts["degraded"] += 1
        elif agent.status == AgentStatus.OFFLINE:
            agent_counts["offline"] += 1

    asset_counts = {"total": len(store.assets)}
    for asset in store.assets.values():
        asset_counts[asset.asset_type.value] = asset_counts.get(asset.asset_type.value, 0) + 1

    incident_counts = {"total": len(store.incidents), "open": 0, "acknowledged": 0, "resolved": 0}
    for incident in store.incidents.values():
        incident_counts[incident.status.value] += 1

    return OverviewResponse(
        agents=agent_counts,
        assets=asset_counts,
        signals=_signal_inventory(),
        incidents=incident_counts,
    )


@app.get("/stack/status", response_model=MasterStackStatus)
async def stack_status() -> MasterStackStatus:
    return await get_master_stack_status(store)


@app.get("/incidents", response_model=list[UnifiedIncident])
def list_incidents() -> list[UnifiedIncident]:
    incidents = list(store.incidents.values())
    return sorted(
        incidents,
        key=lambda incident: (incident.priority.value, -incident.score),
    )


@app.get("/incidents/{incident_id}", response_model=UnifiedIncident)
def get_incident(incident_id: str) -> UnifiedIncident:
    incident = store.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.patch("/incidents/{incident_id}", response_model=UnifiedIncident)
def patch_incident(incident_id: str, body: IncidentPatchRequest) -> UnifiedIncident:
    if incident_id not in store.incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not store.set_incident_status(incident_id, body.status):
        raise HTTPException(status_code=404, detail="Incident not found")
    rebuild_incidents(store)
    return store.incidents[incident_id]


static_dir = REPO_ROOT / "web"
if static_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=static_dir), name="assets")


@app.get("/dashboard")
def dashboard() -> FileResponse:
    path = REPO_ROOT / "dashboard.html"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="dashboard.html not found")
    return FileResponse(path)
