import math
from datetime import timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import Incident, Metric, MetricSample, Anomaly, Evidence
from backend.models.base import generate_uuid, utc_now
from backend.baselines.stats import compute_baseline_stats, calculate_anomaly_score


def calculate_calibrated_confidence(anomaly_score: float) -> float:
    """Computes a statistically calibrated confidence score from robust z-score via logistic sigmoid.
    
    Anchors:
    - z = 2.5 -> 0.50 (marginal anomaly)
    - z = 3.5 -> 0.73 (statistically significant)
    - z = 5.0 -> 0.92 (critical deviation)
    - z >= 7.0 -> 0.99 (indisputable outlier)
    """
    z = max(0.0, float(anomaly_score))
    prob = 1.0 / (1.0 + math.exp(-(z - 2.5)))
    return round(max(0.50, min(0.99, prob)), 2)


class AnomalyDetector:
    def __init__(self, db: Session):
        self.db = db

    def analyze_incident_metrics(
        self,
        incident_id: str,
        baseline_window_minutes: int = 120,
    ) -> List[Anomaly]:
        """Detects metric anomalies by comparing incident-window telemetry to historical pre-incident baseline.
        
        Enforces strict pre-incident baseline windowing (no failure period contamination),
        groups contiguous anomalous samples into discrete Anomaly Episodes, and computes
        calibrated statistical confidence.
        """
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return []

        incident_start = incident.started_at
        baseline_start = incident_start - timedelta(minutes=baseline_window_minutes)

        metrics = self.db.query(Metric).all()
        detected_anomalies: List[Anomaly] = []

        anomaly_evidence_counter = self.db.query(Evidence).filter(Evidence.incident_id == incident_id).count()

        for metric in metrics:
            # 1. Fetch strict pre-incident baseline samples
            baseline_samples = (
                self.db.query(MetricSample)
                .filter(
                    MetricSample.metric_id == metric.id,
                    MetricSample.timestamp >= baseline_start,
                    MetricSample.timestamp < incident_start,
                )
                .order_by(MetricSample.timestamp.asc())
                .all()
            )
            baseline_vals = [s.value for s in baseline_samples]

            # In production: strictly refuse to contaminate reference baseline with failure-period data
            if len(baseline_vals) < 3:
                continue

            stats = compute_baseline_stats(baseline_vals)

            # 2. Fetch incident-period evaluation samples
            eval_samples = (
                self.db.query(MetricSample)
                .filter(
                    MetricSample.metric_id == metric.id,
                    MetricSample.timestamp >= incident_start,
                )
                .order_by(MetricSample.timestamp.asc())
                .all()
            )
            if not eval_samples:
                continue

            # 3. Identify all anomalous samples
            anomalous_samples = []
            for sample in eval_samples:
                eval_res = calculate_anomaly_score(sample.value, stats)
                if eval_res["is_anomaly"]:
                    anomalous_samples.append((sample, eval_res))

            if not anomalous_samples:
                continue

            # 4. Group adjacent anomalous samples into discrete Anomaly Episodes (window <= 5 minutes)
            episodes: List[List[Tuple[MetricSample, Dict[str, Any]]]] = []
            current_episode: List[Tuple[MetricSample, Dict[str, Any]]] = []

            for s_item in anomalous_samples:
                sample, res = s_item
                if not current_episode:
                    current_episode.append(s_item)
                else:
                    prev_sample, _ = current_episode[-1]
                    delta_sec = (sample.timestamp - prev_sample.timestamp).total_seconds()
                    if delta_sec <= 300.0:
                        current_episode.append(s_item)
                    else:
                        episodes.append(current_episode)
                        current_episode = [s_item]

            if current_episode:
                episodes.append(current_episode)

            # 5. Create 1 Anomaly and 1 authoritative Evidence record per Episode
            for episode in episodes:
                # Find peak deviation in this episode
                peak_sample, peak_res = max(episode, key=lambda x: x[1]["anomaly_score"])
                start_time = episode[0][0].timestamp
                end_time = episode[-1][0].timestamp
                sample_count = len(episode)

                anomaly_rec = Anomaly(
                    id=generate_uuid(),
                    incident_id=incident_id,
                    metric_id=metric.id,
                    metric_name=metric.name,
                    service=metric.service,
                    detected_at=peak_sample.timestamp,
                    actual=peak_res["actual"],
                    expected=peak_res["expected"],
                    deviation=peak_res["deviation"],
                    severity=peak_res["severity"],
                    anomaly_score=peak_res["anomaly_score"],
                    baseline_window=f"{baseline_window_minutes}m_pre_incident",
                )
                self.db.add(anomaly_rec)
                detected_anomalies.append(anomaly_rec)

                anomaly_evidence_counter += 1
                import uuid
                evid_id = f"EVID-ANOM-{anomaly_evidence_counter:04d}-{uuid.uuid4().hex[:6].upper()}"
                
                calibrated_conf = calculate_calibrated_confidence(peak_res["anomaly_score"])

                evidence = Evidence(
                    id=evid_id,
                    incident_id=incident_id,
                    timestamp=peak_sample.timestamp,
                    evidence_type="METRIC",
                    source=f"anomaly-detector:{metric.service}",
                    entity=f"{metric.service}:{metric.name}",
                    entity_id=metric.id,
                    entity_type="METRIC",
                    content={
                        "metric": metric.name,
                        "service": metric.service,
                        "actual": peak_res["actual"],
                        "expected": peak_res["expected"],
                        "deviation": peak_res["deviation"],
                        "anomaly_score": peak_res["anomaly_score"],
                        "severity": peak_res["severity"],
                        "unit": metric.unit,
                        "episode_sample_count": sample_count,
                        "episode_start": start_time.isoformat(),
                        "episode_end": end_time.isoformat(),
                    },
                    confidence=calibrated_conf,
                    provenance={
                        "baseline_samples_count": stats.count,
                        "baseline_median": stats.median,
                        "baseline_mad": stats.mad,
                        "baseline_p95": stats.p95,
                        "calibrated_confidence_formula": "logistic_sigmoid(z - 2.5)",
                    },
                )
                self.db.add(evidence)

        self.db.flush()
        return detected_anomalies
