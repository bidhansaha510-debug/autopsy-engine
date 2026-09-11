import numpy as np
from typing import List, Dict, Any
from pydantic import BaseModel


class BaselineStats(BaseModel):
    count: int
    mean: float
    median: float
    stddev: float
    p25: float = 0.0
    p50: float = 0.0
    p75: float = 0.0
    p90: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    mad: float = 0.0
    robust_scale: float = 0.0
    iqr: float = 0.0
    min_samples_met: bool = False
    min_required_samples: int = 5


def compute_baseline_stats(values: List[float], min_required_samples: int = 5) -> BaselineStats:
    """Calculates rigorous statistical baseline metrics over real historical sample values."""
    if not values:
        return BaselineStats(
            count=0,
            mean=0.0,
            median=0.0,
            stddev=0.0,
            p25=0.0,
            p50=0.0,
            p75=0.0,
            p90=0.0,
            p95=0.0,
            p99=0.0,
            mad=0.0,
            robust_scale=0.0,
            iqr=0.0,
            min_samples_met=False,
            min_required_samples=min_required_samples,
        )

    arr = np.array(values, dtype=np.float64)
    n = len(arr)
    mean_val = float(np.mean(arr))
    median_val = float(np.median(arr))
    std_val = float(np.std(arr)) if n > 1 else 0.0

    # Percentiles
    p25 = float(np.percentile(arr, 25))
    p50 = float(np.percentile(arr, 50))
    p75 = float(np.percentile(arr, 75))
    p90 = float(np.percentile(arr, 90))
    p95 = float(np.percentile(arr, 95))
    p99 = float(np.percentile(arr, 99))
    iqr_val = float(p75 - p25)

    # Median Absolute Deviation (MAD)
    abs_deviations = np.abs(arr - median_val)
    mad_val = float(np.median(abs_deviations))
    # Normal distribution scale factor for MAD is ~1.4826
    robust_scale = 1.4826 * mad_val

    min_met = n >= min_required_samples

    return BaselineStats(
        count=n,
        mean=round(mean_val, 4),
        median=round(median_val, 4),
        stddev=round(std_val, 4),
        p25=round(p25, 4),
        p50=round(p50, 4),
        p75=round(p75, 4),
        p90=round(p90, 4),
        p95=round(p95, 4),
        p99=round(p99, 4),
        mad=round(mad_val, 4),
        robust_scale=round(robust_scale, 4),
        iqr=round(iqr_val, 4),
        min_samples_met=min_met,
        min_required_samples=min_required_samples,
    )


def calculate_anomaly_score(actual: float, baseline: BaselineStats) -> Dict[str, Any]:
    """Calculates deterministic deviation and anomaly severity against baseline."""
    expected = baseline.median if baseline.min_samples_met else baseline.mean
    deviation = actual - expected

    # Robust scale hierarchy: MAD -> IQR * 0.7413 -> StdDev
    if baseline.robust_scale > 0.0001:
        scale = baseline.robust_scale
    elif baseline.iqr > 0.0001:
        scale = baseline.iqr * 0.7413
    elif baseline.stddev > 0.0001:
        scale = baseline.stddev
    else:
        scale = 0.0

    if scale < 0.0001:
        # If historical variance was virtually zero, any significant absolute delta is anomalous
        score = abs(deviation) if abs(deviation) > 1.0 else 0.0
    else:
        score = abs(deviation) / scale

    # If baseline sample requirements weren't met, temper anomaly confidence
    if not baseline.min_samples_met and baseline.count < 3:
        score = min(score, 1.5)

    score = round(float(score), 2)

    # Classify severity deterministically based on robust sigma deviation
    if score >= 6.0:
        severity = "CRITICAL"
    elif score >= 4.5:
        severity = "HIGH"
    elif score >= 3.0:
        severity = "MEDIUM"
    elif score >= 2.0:
        severity = "LOW"
    else:
        severity = "NORMAL"

    return {
        "actual": round(actual, 4),
        "expected": round(expected, 4),
        "deviation": round(deviation, 4),
        "anomaly_score": score,
        "severity": severity,
        "is_anomaly": score >= 2.5,
        "min_samples_met": baseline.min_samples_met,
    }
