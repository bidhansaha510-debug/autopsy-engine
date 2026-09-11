from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field
from backend.schemas.common import ProvenanceSchema


# --- Ingestion Schemas ---

class LogIngestRequest(BaseModel):
    service: str
    message: str
    level: str = "INFO"
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: Optional[Dict[str, Any]] = None
    incident_id: Optional[str] = None


class MetricSampleIngest(BaseModel):
    timestamp: Optional[datetime] = None
    value: float
    labels: Dict[str, str] = Field(default_factory=dict)


class MetricIngestRequest(BaseModel):
    service: str
    name: str
    unit: str = "count"
    metric_type: str = "GAUGE"
    samples: List[MetricSampleIngest]
    tags: Dict[str, str] = Field(default_factory=dict)
    incident_id: Optional[str] = None


class SpanIngestRequest(BaseModel):
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    service: str
    name: str
    start_time: datetime
    duration_ms: float
    status: str = "OK"  # OK, ERROR
    attributes: Dict[str, Any] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    incident_id: Optional[str] = None


class TraceBatchIngestRequest(BaseModel):
    trace_id: str
    incident_id: Optional[str] = None
    spans: List[SpanIngestRequest]


class DeploymentIngestRequest(BaseModel):
    service: str
    version: str
    commit_sha: Optional[str] = None
    deployed_at: Optional[datetime] = None
    deployed_by: str = "automation"
    status: str = "SUCCESS"
    changelog: Optional[str] = None
    environment: str = "production"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ConfigChangeIngestRequest(BaseModel):
    service: str
    config_key: str
    old_value: Optional[str] = None
    new_value: str
    changed_at: Optional[datetime] = None
    changed_by: str = "operator"
    reason: Optional[str] = None
    environment: str = "production"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertIngestRequest(BaseModel):
    incident_id: Optional[str] = None
    name: str
    severity: str = "CRITICAL"
    service: str
    triggered_at: Optional[datetime] = None
    query: Optional[str] = None
    threshold: Optional[str] = None
    condition: Optional[str] = None


# --- Response Schemas ---

class LogEntryResponse(BaseModel):
    id: str
    incident_id: Optional[str]
    event_id: Optional[str]
    timestamp: datetime
    level: str
    service: str
    host: Optional[str]
    message: str
    request_id: Optional[str]
    trace_id: Optional[str]
    span_id: Optional[str]
    attributes_json: Dict[str, Any]

    model_config = {"from_attributes": True}


class MetricSampleResponse(BaseModel):
    id: str
    metric_id: str
    timestamp: datetime
    value: float
    labels_json: Dict[str, Any]

    model_config = {"from_attributes": True}


class SpanResponse(BaseModel):
    id: str
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    service: str
    name: str
    start_time: datetime
    duration_ms: float
    status: str
    attributes_json: Dict[str, Any]
    events_json: List[Dict[str, Any]]

    model_config = {"from_attributes": True}


class TraceDetailResponse(BaseModel):
    trace_id: str
    root_service: str
    start_time: datetime
    duration_ms: float
    status_code: int
    has_error: bool
    spans: List[SpanResponse]
    critical_path: List[str] = Field(default_factory=list)
    latency_breakdown: Dict[str, float] = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class EventResponse(BaseModel):
    id: str
    incident_id: Optional[str]
    timestamp: datetime
    ingested_at: datetime
    source: str
    source_type: str
    environment: str
    service: str
    host: Optional[str]
    raw_data: Dict[str, Any]
    normalized_data: Dict[str, Any]
    provenance: Dict[str, Any]
    is_simulated: bool

    model_config = {"from_attributes": True}
