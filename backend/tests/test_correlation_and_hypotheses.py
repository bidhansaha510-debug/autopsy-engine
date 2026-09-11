import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.database import Base
from backend.models import (
    Incident,
    Evidence,
    Hypothesis,
    Event,
    Metric,
    MetricSample,
    LogEntry,
    Service,
    ServiceDependency,
)
from backend.models.base import generate_uuid
from backend.replay.engine import IncidentReplayEngine
from backend.hypotheses.engine import HypothesisEngine
from backend.correlation.engine import CorrelationEngine
from backend.anomaly.detector import AnomalyDetector


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
    assert top_hyp.status in ("SUPPORTED", "STRONGLY_SUPPORTED")

    # Counterevidence: network and deployment hypotheses should have lower scores
    rival_hyps = [h for h in hypotheses if "network" in h.statement.lower() or "deployment" in h.statement.lower() or "code" in h.statement.lower()]
    assert len(rival_hyps) >= 2
    for rh in rival_hyps:
        assert rh.score < top_hyp.score
        assert rh.status == "REFUTED"


def test_dynamic_kafka_lag_hypotheses(test_db):
    """Verifies that the hypothesis engine naturally discovers novel failure modes (e.g. Kafka lag/worker starvation)
    without hardcoding DB or network archetypes."""
    now = datetime.now(timezone.utc)
    t0 = now - timedelta(minutes=15)
    t1 = t0 + timedelta(minutes=2)
    t2 = t0 + timedelta(minutes=4)

    # 1. Create Services & Dependencies
    s_kafka = Service(id="svc-kafka", name="kafka-cluster", tier="messaging")
    s_worker = Service(id="svc-worker", name="order-worker", tier="backend")
    s_api = Service(id="svc-api", name="checkout-service", tier="gateway")
    test_db.add_all([s_kafka, s_worker, s_api])
    test_db.flush()

    dep1 = ServiceDependency(id=generate_uuid(), source_service_id="svc-worker", target_service_id="svc-kafka", dependency_type="MESSAGING", is_critical=True)
    dep2 = ServiceDependency(id=generate_uuid(), source_service_id="svc-api", target_service_id="svc-worker", dependency_type="GRPC", is_critical=True)
    test_db.add_all([dep1, dep2])

    inc = Incident(
        id=generate_uuid(),
        title="Order Processing Outage",
        severity="SEV1",
        status="ACTIVE",
        started_at=t0,
        summary="Queue backlog and worker timeouts",
    )
    test_db.add(inc)
    test_db.flush()

    # 2. Add Baseline and Anomaly Metrics for Kafka and Worker
    m_lag = Metric(id="m-lag", name="consumer_partition_lag", service="kafka-cluster", unit="messages")
    m_q = Metric(id="m-q", name="queue_depth", service="order-worker", unit="messages")
    test_db.add_all([m_lag, m_q])
    test_db.flush()

    # Ingest baseline samples
    for i in range(10):
        ts = t0 - timedelta(minutes=20 - i)
        test_db.add(MetricSample(id=generate_uuid(), metric_id="m-lag", timestamp=ts, value=12.0))
        test_db.add(MetricSample(id=generate_uuid(), metric_id="m-q", timestamp=ts, value=45.0))

    # Ingest incident spike samples
    test_db.add(MetricSample(id=generate_uuid(), metric_id="m-lag", timestamp=t0, value=45000.0))
    test_db.add(MetricSample(id=generate_uuid(), metric_id="m-q", timestamp=t1, value=25000.0))

    # Add Events & Error Logs
    ev_lag = Event(
        id=generate_uuid(),
        incident_id=inc.id,
        timestamp=t0,
        source="kafka-monitor",
        source_type="METRIC",
        service="kafka-cluster",
        raw_data={"name": "consumer_partition_lag", "value": 45000.0},
        normalized_data={"metric": "consumer_partition_lag", "actual": 45000.0},
        provenance={"ingested_at": t0.isoformat()},
    )
    ev_worker = Event(
        id=generate_uuid(),
        incident_id=inc.id,
        timestamp=t1,
        source="order-worker-app",
        source_type="LOG",
        service="order-worker",
        raw_data={"message": "Worker thread pool starvation: lag exceeding buffer capacity"},
        normalized_data={"message": "Worker thread pool starvation"},
        provenance={"ingested_at": t1.isoformat()},
    )
    ev_api = Event(
        id=generate_uuid(),
        incident_id=inc.id,
        timestamp=t2,
        source="k8s-alerts",
        source_type="ALERT",
        service="checkout-service",
        raw_data={"alert_name": "API_Timeout_Spike", "severity": "CRITICAL"},
        normalized_data={"alert": "API_Timeout_Spike"},
        provenance={"ingested_at": t2.isoformat()},
    )
    evid_worker = Evidence(
        id=f"EVID-LOG-{generate_uuid()[:6].upper()}",
        incident_id=inc.id,
        timestamp=t1,
        source="order-worker-app",
        evidence_type="LOG",
        entity="order-worker",
        content={"message": "Worker thread pool starvation: lag exceeding buffer capacity", "level": "ERROR", "service": "order-worker"},
        confidence=1.0,
        provenance={"ingested_at": t1.isoformat()},
    )
    evid_api = Evidence(
        id=f"EVID-ALERT-{generate_uuid()[:6].upper()}",
        incident_id=inc.id,
        timestamp=t2,
        source="k8s-alerts",
        evidence_type="ALERT",
        entity="checkout-service",
        content={"alert": "API_Timeout_Spike", "service": "checkout-service"},
        confidence=1.0,
        provenance={"ingested_at": t2.isoformat()},
    )
    test_db.add_all([ev_lag, ev_worker, ev_api, evid_worker, evid_api])
    test_db.flush()

    # Detect anomalies & build correlations
    detector = AnomalyDetector(test_db)
    detector.analyze_incident_metrics(inc.id)

    correlator = CorrelationEngine(test_db)
    correlator.correlate_incident_events(inc.id)

    # 3. Dynamically Generate Hypotheses
    hyp_engine = HypothesisEngine(test_db)
    hyps = hyp_engine.generate_competing_hypotheses(inc.id)

    assert len(hyps) >= 2
    top = hyps[0]

    # The top hypothesis must naturally describe the kafka or worker degradation without any mention of database pool!
    assert "database" not in top.statement.lower()
    assert "pool" not in top.statement.lower()
    assert ("kafka" in top.statement.lower() or "worker" in top.statement.lower() or "order" in top.statement.lower())
    assert top.score >= 0.60
    assert top.status in ("SUPPORTED", "STRONGLY_SUPPORTED", "VALIDATING")
