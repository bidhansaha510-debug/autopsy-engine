import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.database import Base
from backend.models import Incident, Evidence, Hypothesis
from backend.replay.engine import IncidentReplayEngine
from backend.hypotheses.prove_me_wrong import ProveMeWrongEvaluator


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_canonical_incident_forensics(test_db):
    replay = IncidentReplayEngine(test_db)
    incident = replay.bootstrap_canonical_incident()

    assert incident.id is not None
    assert incident.is_simulated is True

    # Verify evidence was generated
    evidence_count = test_db.query(Evidence).filter(Evidence.incident_id == incident.id).count()
    assert evidence_count >= 5

    # Verify hypotheses exist
    hypotheses = test_db.query(Hypothesis).filter(Hypothesis.incident_id == incident.id).all()
    assert len(hypotheses) >= 3

    # The leading hypothesis must be Database connection-pool exhaustion
    top_hyp = max(hypotheses, key=lambda h: h.score)
    assert "pool" in top_hyp.statement.lower() or "database" in top_hyp.statement.lower()
    assert top_hyp.score >= 0.70
    assert top_hyp.status == "SUPPORTED"

    # Counterevidence: network and deployment hypotheses should have lower scores
    other_hyps = [h for h in hypotheses if h.id != top_hyp.id]
    for oh in other_hyps:
        assert oh.score < top_hyp.score
