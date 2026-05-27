from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .engine import rebuild_incidents
from .models import (
    IncidentStatus,
    MasterStackStatus,
    SecurityFinding,
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


@app.post("/ingest/telemetry")
def ingest_telemetry(payload: TelemetryIngestRequest) -> dict[str, int]:
    store.add_telemetry(payload.events)
    rebuild_incidents(store)
    return {"accepted": len(payload.events), "incidents": len(store.incidents)}


@app.post("/ingest/security")
def ingest_security(payload: SecurityIngestRequest) -> dict[str, int]:
    store.add_findings(payload.findings)
    rebuild_incidents(store)
    return {"accepted": len(payload.findings), "incidents": len(store.incidents)}


@app.post("/ingest/unified")
def ingest_unified(payload: UnifiedIngestRequest) -> dict[str, int | dict[str, int]]:
    """Primary ObservaAgent → ObservaShield ingest for all signal planes."""
    store.add_telemetry(payload.events)
    store.add_findings(payload.findings)
    rebuild_incidents(store)
    return {
        "accepted": {
            "telemetry": len(payload.events),
            "security": len(payload.findings),
        },
        "incidents": len(store.incidents),
    }


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
