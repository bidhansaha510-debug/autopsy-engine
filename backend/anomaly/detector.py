from datetime import timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import Incident, Metric, MetricSample, Anomaly, Evidence
from backend.models.base import generate_uuid, utc_now
from backend.baselines.stats import compute_baseline_stats, calculate_anomaly_score


class AnomalyDetector:
    def __init__(self, db: Session):
        self.db = db

    def analyze_incident_metrics(
        self,
        incident_id: str,
        baseline_window_minutes: int = 120,
    ) -> List[Anomaly]:
        """Detects metric anomalies by comparing incident-window telemetry to historical baseline."""
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return []

        incident_start = incident.started_at
        baseline_start = incident_start - timedelta(minutes=baseline_window_minutes)

        # Find all metrics with samples during or leading up to incident
        metrics = self.db.query(Metric).all()
        detected_anomalies: List[Anomaly] = []

        anomaly_evidence_counter = self.db.query(Evidence).filter(Evidence.incident_id == incident_id).count()

        for metric in metrics:
            # Fetch baseline samples (prior to incident start)
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

            # If no explicit pre-incident samples exist, use the earliest 30% of incident samples as baseline
            incident_samples = (
                self.db.query(MetricSample)
                .filter(
                    MetricSample.metric_id == metric.id,
                    MetricSample.timestamp >= incident_start,
                )
                .order_by(MetricSample.timestamp.asc())
                .all()
            )
            if not incident_samples:
                continue

            if len(baseline_vals) < 3 and len(incident_samples) >= 5:
                # Use first samples as reference baseline
                split_idx = max(2, len(incident_samples) // 3)
                baseline_vals = [s.value for s in incident_samples[:split_idx]]
                eval_samples = incident_samples[split_idx:]
            else:
                eval_samples = incident_samples

            if not baseline_vals:
                continue

            stats = compute_baseline_stats(baseline_vals)

            for sample in eval_samples:
                eval_res = calculate_anomaly_score(sample.value, stats)
                if eval_res["is_anomaly"]:
                    # Create Anomaly record
                    anomaly_rec = Anomaly(
                        id=generate_uuid(),
                        incident_id=incident_id,
                        metric_id=metric.id,
                        metric_name=metric.name,
                        service=metric.service,
                        detected_at=sample.timestamp,
                        actual=eval_res["actual"],
                        expected=eval_res["expected"],
                        deviation=eval_res["deviation"],
                        severity=eval_res["severity"],
                        anomaly_score=eval_res["anomaly_score"],
                        baseline_window=f"{baseline_window_minutes}m_pre_incident",
                    )
                    self.db.add(anomaly_rec)
                    detected_anomalies.append(anomaly_rec)

                    # Create referenceable Evidence
                    import uuid
                    anomaly_evidence_counter += 1
                    evid_id = f"EVID-ANOM-{anomaly_evidence_counter:04d}-{uuid.uuid4().hex[:6].upper()}"
                    evidence = Evidence(
                        id=evid_id,
                        incident_id=incident_id,
                        timestamp=sample.timestamp,
                        evidence_type="METRIC",
                        source=f"anomaly-detector:{metric.service}",
                        entity=f"{metric.service}:{metric.name}",
                        content={
                            "metric": metric.name,
                            "service": metric.service,
                            "actual": eval_res["actual"],
                            "expected": eval_res["expected"],
                            "deviation": eval_res["deviation"],
                            "anomaly_score": eval_res["anomaly_score"],
                            "severity": eval_res["severity"],
                            "unit": metric.unit,
                        },
                        confidence=min(1.0, 0.6 + (eval_res["anomaly_score"] * 0.05)),
                        provenance={
                            "baseline_samples_count": stats.count,
                            "baseline_median": stats.median,
                            "baseline_mad": stats.mad,
                            "baseline_p95": stats.p95,
                        },
                    )
                    self.db.add(evidence)

        self.db.flush()
        return detected_anomalies
