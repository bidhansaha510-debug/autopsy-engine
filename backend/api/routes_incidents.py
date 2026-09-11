from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import Incident, Event, Evidence, Hypothesis, Anomaly
from backend.schemas.forensics import IncidentResponse, IncidentCreate
from backend.replay.engine import IncidentReplayEngine

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentResponse])
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.started_at.desc()).all()
    results = []
    for inc in incidents:
        event_count = db.query(Event).filter(Event.incident_id == inc.id).count()
        evid_count = db.query(Evidence).filter(Evidence.incident_id == inc.id).count()
        hyp_count = db.query(Hypothesis).filter(Hypothesis.incident_id == inc.id).count()
        anom_count = db.query(Anomaly).filter(Anomaly.incident_id == inc.id).count()

        results.append(
            IncidentResponse(
                id=inc.id,
                title=inc.title,
                severity=inc.severity,
                status=inc.status,
                started_at=inc.started_at,
                detected_at=inc.detected_at,
                mitigated_at=inc.mitigated_at,
                resolved_at=inc.resolved_at,
                summary=inc.summary,
                is_simulated=inc.is_simulated,
                event_count=event_count,
                evidence_count=evid_count,
                hypothesis_count=hyp_count,
                anomaly_count=anom_count,
            )
        )
    return results


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    event_count = db.query(Event).filter(Event.incident_id == inc.id).count()
    evid_count = db.query(Evidence).filter(Evidence.incident_id == inc.id).count()
    hyp_count = db.query(Hypothesis).filter(Hypothesis.incident_id == inc.id).count()
    anom_count = db.query(Anomaly).filter(Anomaly.incident_id == inc.id).count()

    return IncidentResponse(
        id=inc.id,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        started_at=inc.started_at,
        detected_at=inc.detected_at,
        mitigated_at=inc.mitigated_at,
        resolved_at=inc.resolved_at,
        summary=inc.summary,
        is_simulated=inc.is_simulated,
        event_count=event_count,
        evidence_count=evid_count,
        hypothesis_count=hyp_count,
        anomaly_count=anom_count,
    )


@router.post("", response_model=IncidentResponse)
def create_incident(req: IncidentCreate, db: Session = Depends(get_db)):
    inc = Incident(
        title=req.title,
        severity=req.severity,
        summary=req.summary,
        started_at=req.started_at,
        is_simulated=req.is_simulated,
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return IncidentResponse(
        id=inc.id,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        started_at=inc.started_at,
        detected_at=inc.detected_at,
        mitigated_at=inc.mitigated_at,
        resolved_at=inc.resolved_at,
        summary=inc.summary,
        is_simulated=inc.is_simulated,
        event_count=0,
        evidence_count=0,
        hypothesis_count=0,
        anomaly_count=0,
    )


@router.post("/bootstrap-canonical", response_model=IncidentResponse)
def bootstrap_canonical(db: Session = Depends(get_db)):
    replay = IncidentReplayEngine(db)
    inc = replay.bootstrap_canonical_incident()
    return get_incident(inc.id, db)
