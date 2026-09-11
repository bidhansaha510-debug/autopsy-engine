from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.ingestion.base import BaseIngestionAdapter, IngestionResult
from backend.ingestion.log_adapter import LogIngestionAdapter
from backend.ingestion.metric_adapter import MetricIngestionAdapter
from backend.ingestion.trace_adapter import TraceIngestionAdapter
from backend.ingestion.config_adapter import ConfigChangeIngestionAdapter, DeploymentIngestionAdapter
from backend.ingestion.k8s_alert_adapter import AlertIngestionAdapter, KubernetesEventAdapter

ADAPTER_REGISTRY: Dict[str, BaseIngestionAdapter] = {
    "LOG": LogIngestionAdapter(),
    "METRIC": MetricIngestionAdapter(),
    "TRACE": TraceIngestionAdapter(),
    "CONFIG": ConfigChangeIngestionAdapter(),
    "DEPLOYMENT": DeploymentIngestionAdapter(),
    "ALERT": AlertIngestionAdapter(),
    "KUBERNETES_EVENT": KubernetesEventAdapter(),
    "GIT_CHANGE": DeploymentIngestionAdapter(),
}


def get_adapter(source_type: str) -> BaseIngestionAdapter:
    adapter = ADAPTER_REGISTRY.get(source_type.upper())
    if not adapter:
        # Default fallback to LogIngestionAdapter
        return ADAPTER_REGISTRY["LOG"]
    return adapter


def ingest_telemetry(
    db: Session,
    source_type: str,
    payload: Dict[str, Any],
    incident_id: Optional[str] = None,
    source: Optional[str] = None,
    environment: str = "production",
    is_simulated: bool = False,
) -> IngestionResult:
    adapter = get_adapter(source_type)
    resolved_source = source or f"{source_type.lower()}-adapter"
    return adapter.process(
        db=db,
        raw_payload=payload,
        incident_id=incident_id,
        source=resolved_source,
        environment=environment,
        is_simulated=is_simulated,
    )
