from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import (
    Incident,
    LogEntry,
    Metric,
    MetricSample,
    Trace,
    Span,
    Deployment,
    ConfigChange,
    Anomaly,
    Event,
    EventRelationship,
    Service,
    ServiceDependency,
    Hypothesis,
    RecoveryEvent,
    Evidence,
)
from backend.baselines.stats import compute_baseline_stats, calculate_anomaly_score
from backend.tracing.analyzer import TraceAnalyzer


class ForensicsToolRegistry:
    def __init__(self, db: Session):
        self.db = db

    def get_logs(
        self,
        incident_id: Optional[str] = None,
        service: Optional[str] = None,
        query: Optional[str] = None,
        level: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Queries application and infrastructure logs for forensic inspection."""
        q = self.db.query(LogEntry)
        if incident_id:
            q = q.filter(LogEntry.incident_id == incident_id)
        if service:
            q = q.filter(LogEntry.service.ilike(f"%{service}%"))
        if level:
            q = q.filter(LogEntry.level == level.upper())
        if query:
            q = q.filter(LogEntry.message.ilike(f"%{query}%"))

        entries = q.order_by(LogEntry.timestamp.asc()).limit(limit).all()
        results = []
        for e in entries:
            results.append({
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "service": e.service,
                "level": e.level,
                "message": e.message,
                "request_id": e.request_id,
                "trace_id": e.trace_id,
            })
        return {"count": len(results), "logs": results}

    def query_metrics(
        self,
        service: Optional[str] = None,
        metric_name: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries timeseries metric samples."""
        q = self.db.query(MetricSample).join(Metric, MetricSample.metric_id == Metric.id)
        if incident_id:
            q = q.filter(MetricSample.incident_id == incident_id)
        if service:
            q = q.filter(Metric.service == service)
        if metric_name:
            q = q.filter(Metric.name.ilike(f"%{metric_name}%"))

        samples = q.order_by(MetricSample.timestamp.asc()).limit(100).all()
        sample_list = [{"timestamp": s.timestamp.isoformat(), "value": s.value} for s in samples]
        return {"count": len(sample_list), "samples": sample_list}

    def inspect_trace(self, trace_id: str) -> Dict[str, Any]:
        """Inspects distributed trace waterfall, latency contribution, and critical path."""
        trace = self.db.query(Trace).filter(Trace.trace_id == trace_id).first()
        if not trace:
            return {"error": f"Trace {trace_id} not found"}
        spans = self.db.query(Span).filter(Span.trace_id == trace_id).all()
        result = TraceAnalyzer.analyze_trace(trace, spans)
        return result.model_dump()

    def inspect_deployment(self, service: Optional[str] = None, lookback_entries: int = 10) -> Dict[str, Any]:
        """Inspects recent deployments and commit SHAs."""
        q = self.db.query(Deployment)
        if service:
            q = q.filter(Deployment.service == service)
        deps = q.order_by(Deployment.deployed_at.desc()).limit(lookback_entries).all()
        return {
            "deployments": [
                {
                    "service": d.service,
                    "version": d.version,
                    "commit_sha": d.commit_sha,
                    "deployed_at": d.deployed_at.isoformat(),
                    "status": d.status,
                    "changelog": d.changelog,
                }
                for d in deps
            ]
        }

    def inspect_config_change(self, service: Optional[str] = None, lookback_entries: int = 10) -> Dict[str, Any]:
        """Inspects configuration changes, old values, new values, and operators."""
        q = self.db.query(ConfigChange)
        if service:
            q = q.filter(ConfigChange.service == service)
        cfgs = q.order_by(ConfigChange.changed_at.desc()).limit(lookback_entries).all()
        return {
            "config_changes": [
                {
                    "id": c.id,
                    "service": c.service,
                    "config_key": c.config_key,
                    "old_value": c.old_value,
                    "new_value": c.new_value,
                    "changed_at": c.changed_at.isoformat(),
                    "changed_by": c.changed_by,
                    "reason": c.reason,
                }
                for c in cfgs
            ]
        }

    def compare_baseline(self, metric_name: str, service: str, incident_id: Optional[str] = None) -> Dict[str, Any]:
        """Compares incident metric samples against historical baseline samples."""
        metric = self.db.query(Metric).filter(Metric.name == metric_name, Metric.service == service).first()
        if not metric:
            return {"error": f"Metric {metric_name} on {service} not found"}

        samples = self.db.query(MetricSample).filter(MetricSample.metric_id == metric.id).order_by(MetricSample.timestamp.asc()).all()
        if len(samples) < 3:
            return {"error": "Insufficient samples for baseline calculation"}

        incident = None
        if incident_id:
            incident = self.db.query(Incident).filter(Incident.id == incident_id).first()

        if incident and incident.started_at:
            baseline_samples = [s for s in samples if s.timestamp < incident.started_at]
            recent_samples = [s for s in samples if s.timestamp >= incident.started_at]
            if len(baseline_samples) < 3:
                if incident.is_simulated:
                    split = max(2, int(len(samples) * 0.3))
                    baseline_samples = samples[:split]
                    recent_samples = samples[split:]
                else:
                    return {
                        "status": "INSUFFICIENT_HISTORICAL_BASELINE",
                        "error": "Insufficient pre-incident baseline telemetry. Refusing to contaminate reference population with incident failure data.",
                        "metric": metric_name,
                        "service": service,
                        "pre_incident_samples": len(baseline_samples),
                    }
        else:
            # Operational baseline: earliest 35% of samples
            split = max(2, int(len(samples) * 0.35))
            baseline_samples = samples[:split]
            recent_samples = samples[split:]

        baseline_vals = [s.value for s in baseline_samples]
        recent_vals = [s.value for s in recent_samples]

        base_stats = compute_baseline_stats(baseline_vals)
        recent_avg = sum(recent_vals) / len(recent_vals) if recent_vals else base_stats.median
        eval_res = calculate_anomaly_score(recent_avg, base_stats)

        return {
            "metric": metric_name,
            "service": service,
            "baseline": base_stats.model_dump(),
            "recent_actual": round(recent_avg, 4),
            "deviation": eval_res["deviation"],
            "anomaly_score": eval_res["anomaly_score"],
            "severity": eval_res["severity"],
            "min_samples_met": eval_res["min_samples_met"],
        }

    def get_anomalies(self, incident_id: str) -> Dict[str, Any]:
        """Retrieves all detected statistical anomalies for an incident."""
        anomalies = self.db.query(Anomaly).filter(Anomaly.incident_id == incident_id).order_by(Anomaly.anomaly_score.desc()).all()
        return {
            "incident_id": incident_id,
            "anomalies_count": len(anomalies),
            "anomalies": [
                {
                    "id": a.id,
                    "service": a.service,
                    "metric_name": a.metric_name,
                    "detected_at": a.detected_at.isoformat(),
                    "actual": a.actual,
                    "expected": a.expected,
                    "deviation": a.deviation,
                    "severity": a.severity,
                    "anomaly_score": a.anomaly_score,
                }
                for a in anomalies
            ]
        }

    def find_related_events(self, incident_id: str, event_id: str) -> Dict[str, Any]:
        """Finds events correlated to a specific event via the correlation engine."""
        rels = (
            self.db.query(EventRelationship)
            .filter(
                (EventRelationship.source_event_id == event_id) | (EventRelationship.target_event_id == event_id)
            )
            .all()
        )
        return {
            "correlations": [
                {
                    "relationship_type": r.relationship_type,
                    "score": r.score,
                    "reason": r.reason,
                    "source_event_id": r.source_event_id,
                    "target_event_id": r.target_event_id,
                }
                for r in rels
            ]
        }

    def get_dependencies(self, service_name: str) -> Dict[str, Any]:
        """Returns direct inbound and outbound dependencies of a service."""
        svc = self.db.query(Service).filter(Service.name == service_name).first()
        if not svc:
            return {"error": f"Service {service_name} not found"}

        outbound = [
            {"target": d.target_service.name, "type": d.dependency_type, "critical": d.is_critical}
            for d in svc.outbound_dependencies
        ]
        inbound = [
            {"source": d.source_service.name, "type": d.dependency_type, "critical": d.is_critical}
            for d in svc.inbound_dependencies
        ]
        return {"service": service_name, "dependencies": outbound, "dependents": inbound}

    def test_hypothesis(self, hypothesis_id: str) -> Dict[str, Any]:
        """Executes Prove Me Wrong evaluation against a hypothesis."""
        h = self.db.query(Hypothesis).filter(Hypothesis.id == hypothesis_id).first()
        if not h:
            return {"error": f"Hypothesis {hypothesis_id} not found"}
        from backend.hypotheses.prove_me_wrong import ProveMeWrongEvaluator
        evaluator = ProveMeWrongEvaluator(self.db)
        return evaluator.evaluate_hypothesis(h)

    def get_recovery_events(self, incident_id: str) -> Dict[str, Any]:
        """Retrieves recovery markers and stabilization evidence."""
        events = self.db.query(RecoveryEvent).filter(RecoveryEvent.incident_id == incident_id).all()
        return {
            "recovery_events": [
                {
                    "timestamp": r.timestamp.isoformat(),
                    "service": r.service,
                    "observed_recovery": r.observed_recovery,
                    "latency_to_recovery_sec": r.latency_to_recovery_sec,
                }
                for r in events
            ]
        }
