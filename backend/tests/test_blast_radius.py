import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.database import Base
from backend.replay.engine import IncidentReplayEngine
from backend.topology.blast_radius import BlastRadiusCalculator


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


def test_blast_radius_calculation(test_db):
    replay = IncidentReplayEngine(test_db)
    incident = replay.bootstrap_canonical_incident()

    calc = BlastRadiusCalculator(test_db)
    blast = calc.calculate_blast_radius(incident.id)

    assert blast.incident_id == incident.id
    assert len(blast.nodes) >= 5
    assert len(blast.edges) >= 4
    # Directly affected or root cause should identify payment-service / db
    assert any("payment" in s for s in blast.directly_affected) or (blast.root_cause_service and "payment" in blast.root_cause_service)
    # Customer facing endpoint should include api-gateway or checkout-service
    assert any("gateway" in s or "checkout" in s for s in blast.customer_facing_endpoints)
