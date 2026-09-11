from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import Anomaly, Evidence, Hypothesis, HypothesisEvidence
from backend.schemas.forensics import (
    AnomalyResponse,
    EvidenceResponse,
    HypothesisResponse,
    HypothesisEvidenceLinkResponse,
)
from backend.hypotheses.engine import HypothesisEngine

router = APIRouter(prefix="/forensics", tags=["Forensics"])


@router.get("/anomalies/{incident_id}", response_model=List[AnomalyResponse])
def get_incident_anomalies(incident_id: str, db: Session = Depends(get_db)):
    anomalies = (
        db.query(Anomaly)
        .filter(Anomaly.incident_id == incident_id)
        .order_by(Anomaly.detected_at.asc())
        .all()
    )
    return anomalies


@router.get("/evidence/{incident_id}", response_model=List[EvidenceResponse])
def get_incident_evidence(incident_id: str, db: Session = Depends(get_db)):
    evidence = (
        db.query(Evidence)
        .filter(Evidence.incident_id == incident_id)
        .order_by(Evidence.timestamp.asc())
        .all()
    )
    return evidence


@router.get("/hypotheses/{incident_id}", response_model=List[HypothesisResponse])
def get_incident_hypotheses(incident_id: str, db: Session = Depends(get_db)):
    hypotheses = (
        db.query(Hypothesis)
        .filter(Hypothesis.incident_id == incident_id)
        .order_by(Hypothesis.rank.asc())
        .all()
    )
    results = []
    for h in hypotheses:
        links = (
            db.query(HypothesisEvidence)
            .filter(HypothesisEvidence.hypothesis_id == h.id)
            .all()
        )
        sup_count = sum(1 for l in links if l.relationship_type == "SUPPORTS")
        contra_count = sum(1 for l in links if l.relationship_type == "CONTRADICTS")

        link_responses = []
        for l in links:
            ev_detail = None
            if l.evidence:
                ev_detail = EvidenceResponse(
                    id=l.evidence.id,
                    incident_id=l.evidence.incident_id,
                    timestamp=l.evidence.timestamp,
                    evidence_type=l.evidence.evidence_type,
                    source=l.evidence.source,
                    entity=l.evidence.entity,
                    content=l.evidence.content,
                    confidence=l.evidence.confidence,
                    provenance=l.evidence.provenance,
                )
            link_responses.append(
                HypothesisEvidenceLinkResponse(
                    evidence_id=l.evidence_id,
                    relationship_type=l.relationship_type,
                    weight=l.weight,
                    explanation=l.explanation,
                    evidence_detail=ev_detail,
                )
            )

        results.append(
            HypothesisResponse(
                id=h.id,
                incident_id=h.incident_id,
                statement=h.statement,
                score=h.score,
                status=h.status,
                affected_services=h.affected_services,
                expected_observations=h.expected_observations,
                actual_observations=h.actual_observations,
                missing_evidence=h.missing_evidence,
                rank=h.rank,
                supporting_evidence_count=sup_count,
                contradicting_evidence_count=contra_count,
                evidence_links=link_responses,
            )
        )
    return results


@router.post("/hypotheses/recalculate/{incident_id}", response_model=List[HypothesisResponse])
def recalculate_hypotheses(incident_id: str, db: Session = Depends(get_db)):
    engine = HypothesisEngine(db)
    engine.generate_competing_hypotheses(incident_id)
    return get_incident_hypotheses(incident_id, db)
