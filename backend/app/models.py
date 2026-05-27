from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SignalType(str, Enum):
    METRIC = "metric"
    LOG = "log"
    TRACE = "trace"
    PROFILE = "profile"
    EVENT = "event"


class SecurityDomain(str, Enum):
    CWP_RUNTIME = "cwp_runtime"
    CSPM = "cspm"
    VULN = "vuln"
    AI_SPM = "ai_spm"
    CWPM = "cwpm"  # legacy alias for CWP runtime


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


class CorrelationKeys(BaseModel):
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    host_id: Optional[str] = None
    pod_name: Optional[str] = None
    resource_id: Optional[str] = None
    image_digest: Optional[str] = None
    service_name: Optional[str] = None


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
    source: str = Field(description="prometheus|loki|tempo|pyroscope|otel|observaagent")
    title: str
    details: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: ResourceContext
    correlation: CorrelationKeys = Field(default_factory=CorrelationKeys)
    metrics: Dict[str, float] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)
    stack_ref: Optional[str] = Field(
        default=None,
        description="Query URL or backend pointer into the master stack (Mimir/Loki/Tempo)",
    )


class SecurityFinding(BaseModel):
    domain: SecurityDomain
    severity: Severity
    source: str = Field(description="wiz|falco|observaagent|cwp-simulator")
    title: str
    details: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    exploitability: float = Field(ge=0.0, le=1.0, default=0.5)
    epss_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    context: ResourceContext
    correlation: CorrelationKeys = Field(default_factory=CorrelationKeys)
    tags: List[str] = Field(default_factory=list)
    stack_ref: Optional[str] = None


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


class StackBackendStatus(BaseModel):
    name: str
    role: str
    url: str
    healthy: bool
    detail: str


class SignalInventory(BaseModel):
    metrics: int = 0
    logs: int = 0
    traces: int = 0
    profiles: int = 0
    events: int = 0
    cwp_runtime: int = 0
    cspm: int = 0
    vuln: int = 0
    ai_spm: int = 0
    total_telemetry: int = 0
    total_security: int = 0


class MasterStackStatus(BaseModel):
    observaagent: StackBackendStatus
    backends: List[StackBackendStatus]
    inventory: SignalInventory
