from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SignalType(str, Enum):
    METRIC = "metric"
    LOG = "log"
    TRACE = "trace"


class SecurityDomain(str, Enum):
    CWPM = "cwpm"
    CSPM = "cspm"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Priority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class IncidentStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ResourceContext(BaseModel):
    cloud_account: str
    region: Optional[str] = None
    cluster: Optional[str] = None
    namespace: Optional[str] = None
    service: Optional[str] = None
    identity: Optional[str] = None
    resource_id: Optional[str] = None


class TelemetryEvent(BaseModel):
    signal_type: SignalType
    severity: Severity
    source: str = Field(description="prometheus|loki|tempo|otel")
    title: str
    details: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: ResourceContext
    metrics: Dict[str, float] = Field(default_factory=dict)


class SecurityFinding(BaseModel):
    domain: SecurityDomain
    severity: Severity
    source: str = Field(description="wiz|cloud-scanner")
    title: str
    details: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    exploitability: float = Field(ge=0.0, le=1.0, default=0.5)
    context: ResourceContext
    tags: List[str] = Field(default_factory=list)


class UnifiedIncident(BaseModel):
    id: str
    correlation_key: str
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    priority: Priority
    score: float
    summary: str
    context: ResourceContext
    telemetry_events: List[TelemetryEvent]
    security_findings: List[SecurityFinding]
    recommended_actions: List[str]

