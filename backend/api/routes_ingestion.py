from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.ingestion import ingest_telemetry
from backend.schemas.telemetry import (
    LogIngestRequest,
    MetricIngestRequest,
    TraceBatchIngestRequest,
    DeploymentIngestRequest,
    ConfigChangeIngestRequest,
    AlertIngestRequest,
)

router = APIRouter(prefix="/ingest", tags=["Ingestion"])


@router.post("/log")
def ingest_log(req: LogIngestRequest, db: Session = Depends(get_db)):
    res = ingest_telemetry(
        db=db,
        source_type="LOG",
        payload=req.model_dump(),
        incident_id=req.incident_id,
        source="api-log-stream",
    )
    db.commit()
    return {
        "status": "success",
        "event_id": res.event.id,
        "evidence_id": res.evidence.id if res.evidence else None,
    }


@router.post("/metric")
def ingest_metric(req: MetricIngestRequest, db: Session = Depends(get_db)):
    res = ingest_telemetry(
        db=db,
        source_type="METRIC",
        payload=req.model_dump(),
        incident_id=req.incident_id,
        source="prometheus-adapter",
    )
    db.commit()
    return {
        "status": "success",
        "event_id": res.event.id,
        "evidence_id": res.evidence.id if res.evidence else None,
    }


@router.post("/trace")
def ingest_trace(req: TraceBatchIngestRequest, db: Session = Depends(get_db)):
    res = ingest_telemetry(
        db=db,
        source_type="TRACE",
        payload=req.model_dump(),
        incident_id=req.incident_id,
        source="otel-collector",
    )
    db.commit()
    return {
        "status": "success",
        "event_id": res.event.id,
        "evidence_id": res.evidence.id if res.evidence else None,
    }


@router.post("/deployment")
def ingest_deployment(req: DeploymentIngestRequest, db: Session = Depends(get_db)):
    res = ingest_telemetry(
        db=db,
        source_type="DEPLOYMENT",
        payload=req.model_dump(),
        source="ci-cd",
    )
    db.commit()
    return {
        "status": "success",
        "event_id": res.event.id,
        "evidence_id": res.evidence.id if res.evidence else None,
    }


@router.post("/config")
def ingest_config(req: ConfigChangeIngestRequest, db: Session = Depends(get_db)):
    res = ingest_telemetry(
        db=db,
        source_type="CONFIG",
        payload=req.model_dump(),
        source="k8s-configmap",
    )
    db.commit()
    return {
        "status": "success",
        "event_id": res.event.id,
        "evidence_id": res.evidence.id if res.evidence else None,
    }


@router.post("/alert")
def ingest_alert(req: AlertIngestRequest, db: Session = Depends(get_db)):
    res = ingest_telemetry(
        db=db,
        source_type="ALERT",
        payload=req.model_dump(),
        incident_id=req.incident_id,
        source="alertmanager",
    )
    db.commit()
    return {
        "status": "success",
        "event_id": res.event.id,
        "evidence_id": res.evidence.id if res.evidence else None,
    }
