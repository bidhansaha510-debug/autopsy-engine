from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import Service, ServiceDependency
from backend.schemas.forensics import BlastRadiusResponse
from backend.topology.blast_radius import BlastRadiusCalculator

router = APIRouter(prefix="/topology", tags=["Topology"])


@router.get("/services")
def list_services(db: Session = Depends(get_db)):
    services = db.query(Service).all()
    deps = db.query(ServiceDependency).all()
    svc_map = {s.id: s.name for s in services}
    return {
        "services": [
            {
                "id": s.id,
                "name": s.name,
                "tier": s.tier,
                "environment": s.environment,
                "oncall_team": s.oncall_team,
                "is_active": s.is_active,
            }
            for s in services
        ],
        "dependencies": [
            {
                "id": d.id,
                "source": svc_map.get(d.source_service_id),
                "target": svc_map.get(d.target_service_id),
                "type": d.dependency_type,
                "critical": d.is_critical,
                "avg_latency_ms": d.avg_latency_ms,
            }
            for d in deps
        ],
    }


@router.get("/blast-radius/{incident_id}", response_model=BlastRadiusResponse)
def get_blast_radius(incident_id: str, db: Session = Depends(get_db)):
    calc = BlastRadiusCalculator(db)
    return calc.calculate_blast_radius(incident_id)
