from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.connectors.manager import StackPullManager

router = APIRouter(prefix="/connectors", tags=["Stack Connectors"])


class StackPullRequest(BaseModel):
    lookback_hours: float = Field(default=2.0, ge=0.25, le=72.0, description="Hours of telemetry lookback to query")
    incident_id: Optional[str] = Field(default=None, description="Existing incident to ingest into, or None to create fresh")
    case_title: Optional[str] = Field(default=None, description="Human-readable title for the reconstructed incident case")
    providers: List[str] = Field(default=["prometheus", "kubernetes", "git"], description="List of providers to query")
    prometheus_url: str = Field(default="http://localhost:9090", description="Prometheus or VictoriaMetrics base URL")
    kubernetes_api: str = Field(default="http://localhost:8001", description="Kubernetes API server URL")
    kubernetes_namespace: str = Field(default="production", description="Kubernetes namespace to pull events for")
    git_repo: str = Field(default="corp/payment-service", description="Git repository name or URL")
    services: Optional[List[str]] = Field(default=None, description="Target services to filter or query")


@router.post("/pull")
def pull_stack_telemetry(req: StackPullRequest, db: Session = Depends(get_db)):
    """Pulls telemetry directly from your live or simulated infrastructure stack

    (Prometheus metrics, Kubernetes events, Git deployments) across the incident window,
    constructs the case file, and runs deterministic forensic reconstruction.
    """
    try:
        manager = StackPullManager(db)
        result = manager.pull_stack_telemetry(
            lookback_hours=req.lookback_hours,
            incident_id=req.incident_id,
            case_title=req.case_title,
            providers=req.providers,
            prometheus_url=req.prometheus_url,
            kubernetes_api=req.kubernetes_api,
            kubernetes_namespace=req.kubernetes_namespace,
            git_repo=req.git_repo,
            services=req.services,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stack pull failed: {str(e)}")


@router.get("/status")
def get_connectors_status():
    """Returns available telemetry pull providers and capabilities."""
    return {
        "status": "ready",
        "supported_providers": [
            {
                "id": "prometheus",
                "name": "Prometheus / VictoriaMetrics",
                "types": ["METRIC"],
                "default_url": "http://localhost:9090",
                "description": "Pulls Golden Signals (p99 latency, 5xx rate, pool capacity, CPU) over incident interval",
            },
            {
                "id": "kubernetes",
                "name": "Kubernetes Cluster Events",
                "types": ["KUBERNETES_EVENT", "ALERT"],
                "default_url": "http://localhost:8001",
                "description": "Pulls OOMKilled, CrashLoopBackOff, and Eviction events from target namespaces",
            },
            {
                "id": "git",
                "name": "Git / CI Deployments",
                "types": ["DEPLOYMENT", "CONFIG"],
                "default_repo": "corp/payment-service",
                "description": "Pulls recent commits, release tags, and configuration pushes leading up to failure onset",
            },
        ],
    }
