from typing import List, Dict, Any
from sqlalchemy.orm import Session
from backend.models import Hypothesis, Incident, Evidence, Event
from backend.models.base import generate_uuid
from backend.hypotheses.prove_me_wrong import ProveMeWrongEvaluator


class HypothesisEngine:
    def __init__(self, db: Session):
        self.db = db
        self.evaluator = ProveMeWrongEvaluator(db)

    def generate_competing_hypotheses(self, incident_id: str) -> List[Hypothesis]:
        """Generates competing, rival root-cause hypotheses for the incident."""
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return []

        # Remove existing hypotheses to re-synthesize cleanly
        self.db.query(Hypothesis).filter(Hypothesis.incident_id == incident_id).delete()

        # Archetype Candidate 1: Resource starvation / DB pool configuration
        h1 = Hypothesis(
            id=generate_uuid(),
            incident_id=incident_id,
            statement="Database connection-pool exhaustion caused by configuration parameter reduction",
            score=0.10,
            status="CANDIDATE",
            affected_services=["payment-service", "checkout-service", "api-gateway"],
            expected_observations=[
                "Configuration change reducing connection pool size",
                "Database connection pool utilization reaching capacity",
                "Downstream latency and timeout cascade on caller services",
                "Mitigation/rollback followed by immediate symptom resolution",
            ],
            actual_observations=[],
            missing_evidence=[],
            rank=1,
        )

        # Archetype Candidate 2: Upstream / External network latency
        h2 = Hypothesis(
            id=generate_uuid(),
            incident_id=incident_id,
            statement="External network partition or upstream third-party gateway latency",
            score=0.10,
            status="CANDIDATE",
            affected_services=["api-gateway", "checkout-service"],
            expected_observations=[
                "Network packet loss or interface drop metrics elevated",
                "TCP handshake timeouts to external endpoints",
                "No correlation with internal deployment or config changes",
            ],
            actual_observations=[],
            missing_evidence=[],
            rank=2,
        )

        # Archetype Candidate 3: Application code regression
        h3 = Hypothesis(
            id=generate_uuid(),
            incident_id=incident_id,
            statement="Application regression or memory leak introduced via recent code deployment",
            score=0.10,
            status="CANDIDATE",
            affected_services=["payment-service"],
            expected_observations=[
                "Recent deployment or Git commit timestamped prior to incident onset",
                "Gradual heap memory growth or CPU saturation",
                "Stack traces showing unhandled application exceptions",
            ],
            actual_observations=[],
            missing_evidence=[],
            rank=3,
        )

        candidates = [h1, h2, h3]
        for c in candidates:
            self.db.add(c)
        self.db.flush()

        # Run "Prove Me Wrong" evaluation on each
        for c in candidates:
            self.evaluator.evaluate_hypothesis(c)

        # Re-rank by score descending
        candidates.sort(key=lambda x: x.score, reverse=True)
        for idx, c in enumerate(candidates):
            c.rank = idx + 1

        self.db.commit()
        return candidates
