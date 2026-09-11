import pytest
from datetime import datetime, timezone, timedelta
import networkx as nx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.database import Base
from backend.models import (
    Incident,
    Event,
    EventRelationship,
    Metric,
    MetricSample,
    Evidence,
    Hypothesis,
)
from backend.correlation.engine import CorrelationEngine
from backend.anomaly.detector import AnomalyDetector, calculate_calibrated_confidence
from backend.hypotheses.prove_me_wrong import ProveMeWrongEvaluator
from backend.ai.investigator import AIInvestigator
from backend.ai.schemas import TOOL_PARAM_MODELS, InspectConfigParams


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def test_causal_dag_acyclicity(test_db):
    """Verifies that cyclical event relationships are broken via feedback arc cycle elimination
    and the resulting causal graph is guaranteed to be a strict DAG."""
    inc = Incident(id="inc-cycle-1", title="Cycle Test Incident")
    test_db.add(inc)

    t0 = datetime.now(timezone.utc)
    e1 = Event(id="ev-1", incident_id=inc.id, service="auth-svc", source="auth", source_type="LOG", timestamp=t0, raw_data={}, normalized_data={}, provenance={})
    e2 = Event(id="ev-2", incident_id=inc.id, service="user-svc", source="user", source_type="LOG", timestamp=t0 + timedelta(seconds=1), raw_data={}, normalized_data={}, provenance={})
    e3 = Event(id="ev-3", incident_id=inc.id, service="db-svc", source="db", source_type="LOG", timestamp=t0 + timedelta(seconds=2), raw_data={}, normalized_data={}, provenance={})
    test_db.add_all([e1, e2, e3])

    # Construct a cycle: e1 -> e2 (0.90) -> e3 (0.80) -> e1 (0.40 - back-edge)
    r1 = EventRelationship(id="r-1", incident_id=inc.id, source_event_id=e1.id, target_event_id=e2.id, relationship_type="AFFECTED", score=0.90, reason="Forward call", provenance={})
    r2 = EventRelationship(id="r-2", incident_id=inc.id, source_event_id=e2.id, target_event_id=e3.id, relationship_type="AFFECTED", score=0.80, reason="Forward call", provenance={})
    r3 = EventRelationship(id="r-3", incident_id=inc.id, source_event_id=e3.id, target_event_id=e1.id, relationship_type="AFFECTED", score=0.40, reason="Cycle back-edge", provenance={})
    test_db.add_all([r1, r2, r3])
    test_db.commit()

    engine = CorrelationEngine(test_db)
    dag = engine.build_causal_dag(inc.id)

    # Must be strictly acyclic
    assert nx.is_directed_acyclic_graph(dag) is True
    # The lowest scoring back-edge (0.40) must have been eliminated
    assert not dag.has_edge("ev-3", "ev-1")
    assert dag.has_edge("ev-1", "ev-2")
    assert dag.has_edge("ev-2", "ev-3")


def test_anomaly_episode_grouping_and_calibrated_confidence(test_db):
    """Verifies that 6 contiguous anomalous samples collapse into 1 Anomaly Episode
    with a single Evidence record and calibrated statistical confidence."""
    t0 = datetime.now(timezone.utc)
    t_inc = t0 - timedelta(minutes=30)
    inc = Incident(id="inc-ep-1", title="Episode Test", started_at=t_inc)
    test_db.add(inc)

    m = Metric(id="m-ep-1", name="cpu_utilization", service="cart-service", unit="percent")
    test_db.add(m)

    # Pre-incident baseline (5 normal samples)
    for i in range(5):
        s = MetricSample(
            id=f"base-{i}",
            metric_id=m.id,
            incident_id=inc.id,
            timestamp=t_inc - timedelta(minutes=20 - i * 2),
            value=15.0 + (i % 2),
        )
        test_db.add(s)

    # 6 contiguous anomalous samples (within 60s of each other)
    for i in range(6):
        s = MetricSample(
            id=f"anom-{i}",
            metric_id=m.id,
            incident_id=inc.id,
            timestamp=t_inc + timedelta(minutes=2, seconds=i * 30),
            value=95.0 + (i * 1.5),
        )
        test_db.add(s)
    test_db.commit()

    detector = AnomalyDetector(test_db)
    anomalies = detector.analyze_incident_metrics(inc.id)

    # Must produce exactly 1 grouped anomaly episode, NOT 6 separate anomalies
    assert len(anomalies) == 1
    anom = anomalies[0]
    assert anom.service == "cart-service"
    assert anom.actual >= 95.0

    # Must produce exactly 1 Evidence item
    evidence_items = test_db.query(Evidence).filter(Evidence.incident_id == inc.id).all()
    assert len(evidence_items) == 1
    ev = evidence_items[0]
    assert ev.content["episode_sample_count"] == 6
    assert ev.confidence >= 0.85
    assert ev.confidence <= 0.99


def test_pydantic_tool_parameter_validation():
    """Verifies that Pydantic enforces parameter validation and catches malformed arguments."""
    # Valid parameters
    valid_params, err = AIInvestigator._validate_tool_params(
        "inspect_config_change",
        {"service": "payment-service", "lookback_entries": 5}
    )
    assert err is None
    assert valid_params["service"] == "payment-service"
    assert valid_params["lookback_entries"] == 5

    # Invalid parameter range (lookback_entries > 50)
    _, err_range = AIInvestigator._validate_tool_params(
        "inspect_config_change",
        {"service": "payment-service", "lookback_entries": 999}
    )
    assert err_range is not None

    # Unknown tool
    _, err_tool = AIInvestigator._validate_tool_params("hallucinated_tool", {})
    assert "Unknown tool" in err_tool


def test_evidence_reservation_1_to_1(test_db):
    """Verifies that one evidence item cannot satisfy multiple predicted observations."""
    inc = Incident(id="inc-res-1", title="Reservation Test")
    test_db.add(inc)

    # Only ONE evidence item exists
    ev1 = Evidence(
        id="EVID-TEST-001",
        incident_id=inc.id,
        timestamp=datetime.now(timezone.utc),
        evidence_type="METRIC",
        source="test",
        entity="order-service:cpu",
        content={"metric": "cpu", "service": "order-service"},
        confidence=0.90,
        provenance={},
    )
    test_db.add(ev1)
    test_db.commit()

    # Hypothesis with TWO predicted observations for the same service metric
    hyp = Hypothesis(
        id="hyp-res-1",
        incident_id=inc.id,
        statement="Test reservation",
        claim="Test reservation",
        predicted_observations=[
            {"type": "METRIC", "service": "order-service", "description": "High CPU utilization", "mandatory": True, "weight": 1.0},
            {"type": "METRIC", "service": "order-service", "description": "Secondary CPU metric anomaly", "mandatory": True, "weight": 1.0},
        ],
        expected_observations=["High CPU utilization", "Secondary CPU metric anomaly"],
        required_evidence=[],
        contradiction_rules=[],
    )
    test_db.add(hyp)
    test_db.commit()

    evaluator = ProveMeWrongEvaluator(test_db)
    result = evaluator.evaluate_hypothesis(hyp)

    # Exactly 1 prediction matched; the 2nd mandatory prediction must be marked MISSING (no double counting!)
    assert result["supporting_count"] == 1
    assert len(result["missing_evidence"]) == 1


def test_post_generation_citation_verification(test_db):
    """Verifies that the citation verifier validates all [EVID-...] tags against actual DB records."""
    inc = Incident(id="inc-cit-1", title="Citation Test")
    test_db.add(inc)

    ev_valid = Evidence(
        id="EVID-VALID-001",
        incident_id=inc.id,
        timestamp=datetime.now(timezone.utc),
        evidence_type="LOG",
        source="test",
        entity="auth-service",
        content={"message": "ok"},
        confidence=1.0,
        provenance={},
    )
    test_db.add(ev_valid)
    test_db.commit()

    investigator = AIInvestigator(test_db)

    # Text containing a real citation and a hallucinated citation
    text_with_fake = "Outage confirmed by [EVID-VALID-001] and hallucinated [EVID-FAKE-999]."
    cleaned = investigator._verify_and_calibrate_synthesis(text_with_fake, inc.id)

    # Fake citation must not remain as [EVID-FAKE-999]
    assert "[EVID-FAKE-999]" not in cleaned
    assert "[EVID-VALID-001]" in cleaned
