import pytest
from backend.baselines.stats import compute_baseline_stats, calculate_anomaly_score


def test_baseline_stats_calculation():
    data = [10.0, 10.2, 9.8, 10.1, 10.3, 9.9, 10.0, 10.1]
    stats = compute_baseline_stats(data)

    assert stats.count == 8
    assert abs(stats.mean - 10.05) < 0.1
    assert abs(stats.median - 10.05) < 0.1
    assert stats.p50 == stats.median
    assert stats.mad >= 0.0
    assert stats.robust_scale >= 0.0


def test_anomaly_scoring_normal():
    data = [10.0, 10.2, 9.8, 10.1, 10.3, 9.9, 10.0, 10.1]
    stats = compute_baseline_stats(data)

    # Value within normal band
    res = calculate_anomaly_score(10.1, stats)
    assert not res["is_anomaly"]
    assert res["severity"] == "NORMAL"


def test_anomaly_scoring_critical_deviation():
    data = [10.0, 10.2, 9.8, 10.1, 10.3, 9.9, 10.0, 10.1]
    stats = compute_baseline_stats(data)

    # Value drastically deviating (pool utilization 100 vs baseline 10)
    res = calculate_anomaly_score(100.0, stats)
    assert res["is_anomaly"]
    assert res["severity"] in ("CRITICAL", "HIGH")
    assert res["anomaly_score"] > 5.0


def test_uncontaminated_baseline_rejection_in_production():
    """Verifies that in production, the engine strictly refuses to carve up failure-period
    telemetry into an artificial baseline and explicitly reports INSUFFICIENT_HISTORICAL_BASELINE."""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.core.database import Base
    from backend.models import Incident, Metric, MetricSample
    from backend.ai.tools import ForensicsToolRegistry

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    t_now = datetime.now(timezone.utc)
    t_incident = t_now - timedelta(minutes=10)

    # Production (non-simulated) incident
    incident = Incident(
        id="inc-prod-001",
        title="Production API Outage",
        severity="CRITICAL",
        status="ACTIVE",
        started_at=t_incident,
        is_simulated=False,
    )
    db.add(incident)

    metric = Metric(
        id="met-1",
        name="cpu_utilization_pct",
        service="order-service",
        unit="percent",
    )
    db.add(metric)

    # Telemetry only collected AFTER the incident started (failure period samples)
    for i in range(10):
        s = MetricSample(
            id=f"m-{i}",
            metric_id=metric.id,
            incident_id="inc-prod-001",
            timestamp=t_incident + timedelta(minutes=i),
            value=95.0 + (i % 3),
        )
        db.add(s)
    db.commit()

    registry = ForensicsToolRegistry(db)
    result = registry.compare_baseline(
        incident_id="inc-prod-001",
        service="order-service",
        metric_name="cpu_utilization_pct",
    )

    # Must reject baseline synthesis from failure data
    assert result["status"] == "INSUFFICIENT_HISTORICAL_BASELINE"
    assert "Refusing to contaminate" in result["error"]
    assert result["pre_incident_samples"] == 0
