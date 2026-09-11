from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class GetAnomaliesParams(BaseModel):
    incident_id: str = Field(description="UUID of the incident to fetch metric anomalies for")


class InspectConfigParams(BaseModel):
    service: Optional[str] = Field(default=None, description="Target service name to filter configuration modifications")
    start_time: Optional[str] = Field(default=None, description="ISO timestamp for start of inspection window")
    end_time: Optional[str] = Field(default=None, description="ISO timestamp for end of inspection window")
    lookback_entries: int = Field(default=10, ge=1, le=50, description="Max entries to return if time window not specified")


class InspectDeploymentParams(BaseModel):
    service: Optional[str] = Field(default=None, description="Target service name to filter deployment events")
    start_time: Optional[str] = Field(default=None, description="ISO timestamp for start of inspection window")
    end_time: Optional[str] = Field(default=None, description="ISO timestamp for end of inspection window")
    lookback_entries: int = Field(default=10, ge=1, le=50, description="Max entries to return if time window not specified")


class GetLogsParams(BaseModel):
    incident_id: Optional[str] = Field(default=None, description="Incident UUID")
    service: Optional[str] = Field(default=None, description="Target service name")
    query: Optional[str] = Field(default=None, description="Subtext query to filter log message")
    level: str = Field(default="ERROR", description="Log level filter, e.g. ERROR, WARN, INFO")
    limit: int = Field(default=10, ge=1, le=50, description="Max log records to fetch")
    start_time: Optional[str] = Field(default=None, description="ISO timestamp for start of log query")
    end_time: Optional[str] = Field(default=None, description="ISO timestamp for end of log query")


class GetDependenciesParams(BaseModel):
    service_name: str = Field(description="Service name whose topology callers/callees should be inspected")


class CompareBaselineParams(BaseModel):
    metric_name: str = Field(description="Exact metric name, e.g. db_connection_pool_utilization_pct")
    service: str = Field(description="Service owning the metric")
    incident_id: Optional[str] = Field(default=None, description="Incident UUID to define pre-incident baseline")


class GenerateHypothesesParams(BaseModel):
    incident_id: str = Field(description="Incident UUID to build and test hypotheses for")


class GetRecoveryEventsParams(BaseModel):
    incident_id: str = Field(description="Incident UUID to fetch interventions and recovery milestones for")


# Schema dictionary mapping tool names to their Pydantic validator models
TOOL_PARAM_MODELS = {
    "get_anomalies": GetAnomaliesParams,
    "inspect_config_change": InspectConfigParams,
    "inspect_deployment": InspectDeploymentParams,
    "get_logs": GetLogsParams,
    "get_dependencies": GetDependenciesParams,
    "compare_baseline": CompareBaselineParams,
    "generate_competing_hypotheses": GenerateHypothesesParams,
    "get_recovery_events": GetRecoveryEventsParams,
}
