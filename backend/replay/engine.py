from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import (
    Incident,
    Service,
    ServiceDependency,
    Event,
    Evidence,
    LogEntry,
    Metric,
    MetricSample,
    Trace,
    Span,
    ConfigChange,
    Intervention,
    RecoveryEvent,
)
from backend.models.base import generate_uuid, utc_now
from backend.ingestion import ingest_telemetry
from backend.anomaly.detector import AnomalyDetector
from backend.correlation.engine import CorrelationEngine
from backend.hypotheses.engine import HypothesisEngine
from backend.topology.blast_radius import BlastRadiusCalculator


class IncidentReplayEngine:
    def __init__(self, db: Session):
        self.db = db

    def seed_canonical_services(self):
        """Seeds the standard production service topology if not present."""
        services_def = [
            ("api-gateway", "tier-1", "production"),
            ("checkout-service", "tier-1", "production"),
            ("payment-service", "tier-1", "production"),
            ("payment-db", "tier-2", "production"),
            ("bank-gateway", "tier-2", "production"),
        ]
        svc_map = {}
        for name, tier, env in services_def:
            s = self.db.query(Service).filter(Service.name == name).first()
            if not s:
                s = Service(
                    id=generate_uuid(),
                    name=name,
                    tier=tier,
                    environment=env,
                    repo_url=f"git://github.com/corp/{name}.git",
                    oncall_team=f"team-{tier}",
                )
                self.db.add(s)
                self.db.flush()
            svc_map[name] = s

        # Dependencies: api-gateway -> checkout-service -> payment-service -> payment-db
        #                                               \-> bank-gateway
        dependencies_def = [
            ("api-gateway", "checkout-service", "RPC", True, 12.0),
            ("checkout-service", "payment-service", "RPC", True, 25.0),
            ("payment-service", "payment-db", "DB", True, 4.0),
            ("payment-service", "bank-gateway", "RPC", True, 65.0),
        ]
        for src_name, tgt_name, dtype, crit, lat in dependencies_def:
            src = svc_map[src_name]
            tgt = svc_map[tgt_name]
            dep = (
                self.db.query(ServiceDependency)
                .filter(
                    ServiceDependency.source_service_id == src.id,
                    ServiceDependency.target_service_id == tgt.id,
                )
                .first()
            )
            if not dep:
                dep = ServiceDependency(
                    id=generate_uuid(),
                    source_service_id=src.id,
                    target_service_id=tgt.id,
                    dependency_type=dtype,
                    is_critical=crit,
                    avg_latency_ms=lat,
                )
                self.db.add(dep)

        self.db.commit()

    def bootstrap_canonical_incident(self) -> Incident:
        """Constructs the canonical 02:47 DB pool degradation incident deterministically."""
        self.seed_canonical_services()

        # Check if canonical incident already exists
        existing = self.db.query(Incident).filter(Incident.title.ilike("%Connection Pool Exhaustion%")).first()
        if existing:
            return existing

        t_base = datetime.now(timezone.utc).replace(hour=2, minute=45, second=0, microsecond=0)

        incident = Incident(
            id=generate_uuid(),
            title="SEV1: Payment DB Connection Pool Exhaustion & API Gateway Outage",
            severity="SEV1",
            status="RESOLVED",
            started_at=t_base + timedelta(minutes=2),  # 02:47
            detected_at=t_base + timedelta(minutes=4), # 02:49
            mitigated_at=t_base + timedelta(minutes=7), # 02:52
            resolved_at=t_base + timedelta(minutes=8),  # 02:53
            summary=(
                "At 02:47 UTC a configuration change to payment-service reduced max_db_pool from 50 to 5. "
                "At 02:48 DB pool utilization saturated to 100%. "
                "Cascading latency propagated from payment-service to checkout-service and api-gateway. "
                "Rollback executed at 02:52 restored connection pool capacity and returned error rate to baseline."
            ),
            is_simulated=True,
        )
        self.db.add(incident)
        self.db.flush()

        inc_id = incident.id

        # 1. Historical pre-incident metric baseline samples (02:00 - 02:46)
        # DB pool utilization normal: 15% - 25%
        # API gateway latency normal: 20ms - 45ms
        pre_times = [t_base - timedelta(minutes=m) for m in range(45, 0, -3)]
        for pt in pre_times:
            ingest_telemetry(
                db=self.db,
                source_type="METRIC",
                payload={
                    "service": "payment-service",
                    "name": "db_connection_pool_utilization_pct",
                    "unit": "percent",
                    "timestamp": pt.isoformat(),
                    "value": 18.5,
                },
                incident_id=inc_id,
                is_simulated=True,
            )
            ingest_telemetry(
                db=self.db,
                source_type="METRIC",
                payload={
                    "service": "api-gateway",
                    "name": "http_request_latency_p99_ms",
                    "unit": "milliseconds",
                    "timestamp": pt.isoformat(),
                    "value": 32.0,
                },
                incident_id=inc_id,
                is_simulated=True,
            )

        # 2. 02:47 UTC - Config Changed: DB pool 50 -> 5
        t_0247 = t_base + timedelta(minutes=2)
        ingest_telemetry(
            db=self.db,
            source_type="CONFIG",
            payload={
                "service": "payment-service",
                "config_key": "database.pool.max_connections",
                "old_value": "50",
                "new_value": "5",
                "changed_by": "infra-ops-script",
                "changed_at": t_0247.isoformat(),
                "reason": "tuning database concurrency",
            },
            incident_id=inc_id,
            is_simulated=True,
        )

        # 3. 02:48 UTC - DB connection pool utilization spiked to 100%
        t_0248 = t_base + timedelta(minutes=3)
        ingest_telemetry(
            db=self.db,
            source_type="METRIC",
            payload={
                "service": "payment-service",
                "name": "db_connection_pool_utilization_pct",
                "unit": "percent",
                "timestamp": t_0248.isoformat(),
                "value": 100.0,
            },
            incident_id=inc_id,
            is_simulated=True,
        )
        ingest_telemetry(
            db=self.db,
            source_type="LOG",
            payload={
                "service": "payment-service",
                "level": "WARN",
                "timestamp": t_0248.isoformat(),
                "message": "ConnectionPool exhausted. 5/5 connections in use, 14 callers waiting in queue.",
            },
            incident_id=inc_id,
            is_simulated=True,
        )

        # 4. 02:49 UTC - API latency increased (45ms -> 1250ms)
        t_0249 = t_base + timedelta(minutes=4)
        ingest_telemetry(
            db=self.db,
            source_type="METRIC",
            payload={
                "service": "api-gateway",
                "name": "http_request_latency_p99_ms",
                "unit": "milliseconds",
                "timestamp": t_0249.isoformat(),
                "value": 1280.0,
            },
            incident_id=inc_id,
            is_simulated=True,
        )

        # 5. 02:50 UTC - Checkout timeouts increased
        t_0250 = t_base + timedelta(minutes=5)
        trace_id_sample = "trace-e71a-49bf"
        ingest_telemetry(
            db=self.db,
            source_type="TRACE",
            payload={
                "trace_id": trace_id_sample,
                "root_service": "api-gateway",
                "spans": [
                    {
                        "span_id": "span-gw-1",
                        "parent_span_id": None,
                        "service": "api-gateway",
                        "name": "POST /checkout",
                        "start_time": t_0250.isoformat(),
                        "duration_ms": 3050.0,
                        "status": "ERROR",
                        "attributes": {"http.status_code": 503},
                    },
                    {
                        "span_id": "span-co-1",
                        "parent_span_id": "span-gw-1",
                        "service": "checkout-service",
                        "name": "ExecuteCheckout",
                        "start_time": (t_0250 + timedelta(milliseconds=20)).isoformat(),
                        "duration_ms": 3020.0,
                        "status": "ERROR",
                    },
                    {
                        "span_id": "span-pay-1",
                        "parent_span_id": "span-co-1",
                        "service": "payment-service",
                        "name": "AuthorizePayment",
                        "start_time": (t_0250 + timedelta(milliseconds=45)).isoformat(),
                        "duration_ms": 2960.0,
                        "status": "ERROR",
                        "attributes": {"error.message": "Timeout waiting for DB connection pool"},
                    },
                ],
            },
            incident_id=inc_id,
            is_simulated=True,
        )
        ingest_telemetry(
            db=self.db,
            source_type="LOG",
            payload={
                "service": "checkout-service",
                "level": "ERROR",
                "timestamp": t_0250.isoformat(),
                "trace_id": trace_id_sample,
                "message": "Payment RPC timed out after 3000ms calling payment-service:AuthorizePayment",
            },
            incident_id=inc_id,
            is_simulated=True,
        )

        # 6. 02:51 UTC - Payment 503s increased + Alert triggered
        t_0251 = t_base + timedelta(minutes=6)
        ingest_telemetry(
            db=self.db,
            source_type="ALERT",
            payload={
                "name": "HighHTTP5xxErrorRate",
                "severity": "CRITICAL",
                "service": "api-gateway",
                "triggered_at": t_0251.isoformat(),
                "query": "sum(rate(http_requests_total{status=~'5..'}[1m])) > 0.05",
                "threshold": "5%",
                "condition": "Current 5xx rate: 42.8%",
            },
            incident_id=inc_id,
            is_simulated=True,
        )

        # 7. 02:52 UTC - Rollback occurred (Intervention)
        t_0252 = t_base + timedelta(minutes=7)
        intervention = Intervention(
            id=generate_uuid(),
            incident_id=inc_id,
            action_type="ROLLBACK",
            description="Rollback payment-service config: database.pool.max_connections restored 5 -> 50",
            executed_at=t_0252,
            executed_by="incident-commander",
            status="COMPLETED",
            target_service="payment-service",
            parameters_json={"restored_value": "50"},
        )
        self.db.add(intervention)
        ingest_telemetry(
            db=self.db,
            source_type="CONFIG",
            payload={
                "service": "payment-service",
                "config_key": "database.pool.max_connections",
                "old_value": "5",
                "new_value": "50",
                "changed_by": "incident-commander",
                "changed_at": t_0252.isoformat(),
                "reason": "Emergency mitigation rollback",
            },
            incident_id=inc_id,
            is_simulated=True,
        )

        # 8. 02:53 UTC - Error rate and latency returned to baseline
        t_0253 = t_base + timedelta(minutes=8)
        ingest_telemetry(
            db=self.db,
            source_type="METRIC",
            payload={
                "service": "payment-service",
                "name": "db_connection_pool_utilization_pct",
                "unit": "percent",
                "timestamp": t_0253.isoformat(),
                "value": 22.0,
            },
            incident_id=inc_id,
            is_simulated=True,
        )
        ingest_telemetry(
            db=self.db,
            source_type="METRIC",
            payload={
                "service": "api-gateway",
                "name": "http_request_latency_p99_ms",
                "unit": "milliseconds",
                "timestamp": t_0253.isoformat(),
                "value": 35.0,
            },
            incident_id=inc_id,
            is_simulated=True,
        )
        rec_event = RecoveryEvent(
            id=generate_uuid(),
            incident_id=inc_id,
            timestamp=t_0253,
            service="payment-service",
            observed_recovery="DB connection pool utilization normalized to 22%. Latency returned to baseline 35ms.",
            latency_to_recovery_sec=60.0,
        )
        self.db.add(rec_event)

        self.db.commit()

        # Run forensic processors on the ingested data
        detector = AnomalyDetector(self.db)
        detector.analyze_incident_metrics(inc_id)

        correlator = CorrelationEngine(self.db)
        correlator.correlate_incident_events(inc_id)

        hyp_engine = HypothesisEngine(self.db)
        hyp_engine.generate_competing_hypotheses(inc_id)

        return incident

    def get_timeline_slice(
        self,
        incident_id: str,
        cursor_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Returns forensic state up to the given cursor time for step-by-step incident replay."""
        q = self.db.query(Event).filter(Event.incident_id == incident_id)
        if cursor_time:
            q = q.filter(Event.timestamp <= cursor_time)
        events = q.order_by(Event.timestamp.asc()).all()

        evid_q = self.db.query(Evidence).filter(Evidence.incident_id == incident_id)
        if cursor_time:
            evid_q = evid_q.filter(Evidence.timestamp <= cursor_time)
        evidence_items = evid_q.order_by(Evidence.timestamp.asc()).all()

        return {
            "incident_id": incident_id,
            "cursor_time": cursor_time.isoformat() if cursor_time else None,
            "event_count": len(events),
            "evidence_count": len(evidence_items),
            "events": [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "source_type": e.source_type,
                    "service": e.service,
                    "summary": str(e.raw_data.get("message") or e.raw_data.get("name") or e.raw_data.get("config_key") or e.source_type),
                    "is_simulated": e.is_simulated,
                }
                for e in events
            ],
            "evidence": [
                {
                    "id": ev.id,
                    "timestamp": ev.timestamp.isoformat(),
                    "type": ev.evidence_type,
                    "entity": ev.entity,
                    "confidence": ev.confidence,
                }
                for ev in evidence_items
            ],
        }
