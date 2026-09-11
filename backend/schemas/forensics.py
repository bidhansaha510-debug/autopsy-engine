from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class AnomalyResponse(BaseModel):
    id: str
    incident_id: Optional[str]
    metric_name: str
    service: str
    detected_at: datetime
    actual: float
    expected: float
    deviation: float
    severity: str
    anomaly_score: float
    baseline_window: str

    model_config = {"from_attributes": True}


class EvidenceResponse(BaseModel):
    id: str
    incident_id: str
    timestamp: datetime
    evidence_type: str
    source: str
    entity: str
    content: Dict[str, Any]
    confidence: float
    provenance: Dict[str, Any]

    model_config = {"from_attributes": True}


class HypothesisEvidenceLinkResponse(BaseModel):
    evidence_id: str
    relationship_type: str  # SUPPORTS, CONTRADICTS, NEUTRAL
    weight: float
    explanation: str
    evidence_detail: Optional[EvidenceResponse] = None


class HypothesisResponse(BaseModel):
    id: str
    incident_id: str
    statement: str
    claim: Optional[str] = None
    causal_mechanism: Optional[str] = None
    score: float
    status: str
    affected_services: List[str]
    expected_observations: List[str] = Field(default_factory=list)
    predicted_observations: List[Dict[str, Any]] = Field(default_factory=list)
    required_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    supporting_rules: List[Dict[str, Any]] = Field(default_factory=list)
    contradiction_rules: List[Dict[str, Any]] = Field(default_factory=list)
    actual_observations: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    rank: int
    supporting_evidence_count: int = 0
    contradicting_evidence_count: int = 0
    evidence_links: List[HypothesisEvidenceLinkResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ServiceNode(BaseModel):
    id: str
    name: str
    tier: str
    environment: str
    status: str  # HEALTHY, DEGRADED, FAILED
    is_directly_affected: bool = False
    is_indirectly_affected: bool = False
    is_customer_facing: bool = False


class ServiceEdge(BaseModel):
    source: str
    target: str
    dependency_type: str
    is_critical: bool
    status: str = "NORMAL"  # NORMAL, DEGRADED, FAILING


class BlastRadiusResponse(BaseModel):
    incident_id: str
    root_cause_service: Optional[str]
    directly_affected: List[str]
    indirectly_affected: List[str]
    customer_facing_endpoints: List[str]
    unaffected_services: List[str]
    nodes: List[ServiceNode]
    edges: List[ServiceEdge]
    propagation_path: List[str]


class IncidentCreate(BaseModel):
    title: str
    severity: str = "SEV1"
    summary: Optional[str] = None
    started_at: Optional[datetime] = None
    is_simulated: bool = False


class IncidentResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    started_at: datetime
    detected_at: Optional[datetime]
    mitigated_at: Optional[datetime]
    resolved_at: Optional[datetime]
    summary: Optional[str]
    is_simulated: bool
    event_count: int = 0
    evidence_count: int = 0
    hypothesis_count: int = 0
    anomaly_count: int = 0

    model_config = {"from_attributes": True}
