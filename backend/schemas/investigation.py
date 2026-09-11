from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class InterventionCreate(BaseModel):
    action_type: str  # ROLLBACK, SCALE_UP, POOL_EXPANSION, RESTART
    description: str
    target_service: str
    executed_by: str = "operator"
    parameters: Dict[str, Any] = Field(default_factory=dict)


class InterventionResponse(BaseModel):
    id: str
    incident_id: str
    action_type: str
    description: str
    executed_at: datetime
    executed_by: str
    status: str
    target_service: str
    parameters_json: Dict[str, Any]

    model_config = {"from_attributes": True}


class RecoveryEventResponse(BaseModel):
    id: str
    incident_id: str
    timestamp: datetime
    service: str
    metric_id: Optional[str]
    observed_recovery: str
    latency_to_recovery_sec: float
    verified_by_evidence_id: Optional[str]

    model_config = {"from_attributes": True}


class InvestigationStepResponse(BaseModel):
    id: str
    step_number: int
    question: str
    tool_called: str
    tool_parameters_json: Dict[str, Any]
    tool_result_json: Dict[str, Any]
    findings: str
    evidence_generated_ids: List[str]

    model_config = {"from_attributes": True}


class InvestigationResponse(BaseModel):
    id: str
    incident_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    trigger: str
    current_focus: Optional[str]
    steps: List[InvestigationStepResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ReportResponse(BaseModel):
    id: str
    incident_id: str
    generated_at: datetime
    title: str
    content_markdown: str
    content_json: Dict[str, Any]
    executive_summary: str
    blast_radius: Dict[str, Any]
    rca_statement: str
    recommendations: List[Dict[str, Any]]
    preventive_actions: List[Dict[str, Any]]
    unknowns: List[str]

    model_config = {"from_attributes": True}


class ToolExecutionRequest(BaseModel):
    tool_name: str
    incident_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResponse(BaseModel):
    tool_name: str
    success: bool
    data: Any
    evidence_created: List[str] = Field(default_factory=list)
    error: Optional[str] = None
