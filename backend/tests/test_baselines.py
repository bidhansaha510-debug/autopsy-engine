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
