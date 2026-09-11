from datetime import timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import Event, EventRelationship, Incident, ServiceDependency, Service
from backend.models.base import generate_uuid, utc_now


class CorrelationEngine:
    def __init__(self, db: Session):
        self.db = db

    def correlate_incident_events(
        self,
        incident_id: str,
        time_window_seconds: int = 600,
    ) -> List[EventRelationship]:
        """Discovers deterministic causal and temporal correlations across incident events."""
        events = (
            self.db.query(Event)
            .filter(Event.incident_id == incident_id)
            .order_by(Event.timestamp.asc())
            .all()
        )
        if len(events) < 2:
            return []

        # Load dependency graph edges as a set of (source_name, target_name)
        deps = self.db.query(ServiceDependency).all()
        service_map = {s.id: s.name for s in self.db.query(Service).all()}
        dependency_pairs = {
            (service_map.get(d.source_service_id), service_map.get(d.target_service_id))
            for d in deps
            if d.source_service_id in service_map and d.target_service_id in service_map
        }

        created_relationships: List[EventRelationship] = []

        # Pairwise correlation analysis with strict criteria
        for i in range(len(events)):
            e1 = events[i]
            for j in range(i + 1, min(len(events), i + 25)):
                e2 = events[j]
                time_delta = (e2.timestamp - e1.timestamp).total_seconds()
                if time_delta > time_window_seconds:
                    break

                rel_type = None
                score = 0.0
                reason = ""

                # Criterion 1: Shared Trace ID or Request ID (Exact causal propagation)
                e1_trace = e1.normalized_data.get("trace_id") or e1.raw_data.get("trace_id")
                e2_trace = e2.normalized_data.get("trace_id") or e2.raw_data.get("trace_id")
                e1_req = e1.normalized_data.get("request_id") or e1.raw_data.get("request_id")
                e2_req = e2.normalized_data.get("request_id") or e2.raw_data.get("request_id")

                if e1_trace and e2_trace and e1_trace == e2_trace:
                    rel_type = "AFFECTED"
                    score = 0.98
                    reason = f"Shared distributed trace_id {e1_trace} across {e1.service} and {e2.service}"
                elif e1_req and e2_req and e1_req == e2_req:
                    rel_type = "AFFECTED"
                    score = 0.95
                    reason = f"Shared request_id {e1_req} between {e1.service} and {e2.service}"

                # Criterion 2: Change Event (Config/Deploy) followed by Anomaly/Error on same or caller service
                elif e1.source_type in ("CONFIG", "DEPLOYMENT", "GIT_CHANGE") and e2.source_type in ("METRIC", "LOG", "ALERT"):
                    is_same_service = e1.service == e2.service
                    is_dependent_caller = (e2.service, e1.service) in dependency_pairs

                    if is_same_service:
                        rel_type = "PRECEDED"
                        score = 0.92
                        reason = (
                            f"{e1.source_type} change on {e1.service} preceded {e2.source_type} symptom by "
                            f"{int(time_delta)}s with exact service match"
                        )
                    elif is_dependent_caller:
                        rel_type = "AFFECTED"
                        score = 0.88
                        reason = (
                            f"{e1.source_type} on {e1.service} preceded failure in upstream caller {e2.service} "
                            f"({e2.service} depends on {e1.service}) by {int(time_delta)}s"
                        )

                # Criterion 3: Metric anomaly propagation across topological dependencies
                elif (e1.service, e2.service) in dependency_pairs or (e2.service, e1.service) in dependency_pairs:
                    caller, callee = (e1.service, e2.service) if (e1.service, e2.service) in dependency_pairs else (e2.service, e1.service)
                    # Downstream dependency failure propagating upstream
                    if e1.service == callee and e2.service == caller:
                        rel_type = "AFFECTED"
                        score = 0.84
                        reason = f"Failure propagated from downstream dependency {callee} to caller {caller} within {int(time_delta)}s"
                    else:
                        rel_type = "DEPENDS_ON"
                        score = 0.75
                        reason = f"Topological dependency between {e1.service} and {e2.service} active during failure window"

                # Criterion 4: Recovery timing (Rollback or mitigation followed by symptom clearance)
                elif "rollback" in str(e1.raw_data).lower() or "mitigate" in str(e1.raw_data).lower():
                    if e2.source_type in ("METRIC", "LOG") and ("normal" in str(e2.raw_data).lower() or "baseline" in str(e2.raw_data).lower()):
                        rel_type = "RECOVERED_AFTER"
                        score = 0.94
                        reason = f"System recovery observed {int(time_delta)}s following rollback/mitigation event"

                # Criterion 5: Same host error proximity
                elif e1.host and e2.host and e1.host == e2.host and e1.service == e2.service:
                    rel_type = "CORRELATED_WITH"
                    score = 0.70
                    reason = f"Sequential events on host {e1.host} within {int(time_delta)}s"

                if rel_type and score >= 0.70:
                    # Check if relationship already exists
                    existing = (
                        self.db.query(EventRelationship)
                        .filter(
                            EventRelationship.source_event_id == e1.id,
                            EventRelationship.target_event_id == e2.id,
                        )
                        .first()
                    )
                    if not existing:
                        rel = EventRelationship(
                            id=generate_uuid(),
                            incident_id=incident_id,
                            source_event_id=e1.id,
                            target_event_id=e2.id,
                            relationship_type=rel_type,
                            score=round(score, 2),
                            reason=reason,
                            provenance={
                                "e1_timestamp": e1.timestamp.isoformat(),
                                "e2_timestamp": e2.timestamp.isoformat(),
                                "delta_seconds": time_delta,
                                "source_types": [e1.source_type, e2.source_type],
                            },
                        )
                        self.db.add(rel)
                        created_relationships.append(rel)

        self.db.flush()
        return created_relationships
