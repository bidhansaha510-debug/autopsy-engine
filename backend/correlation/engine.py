from datetime import timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
import networkx as nx
from sqlalchemy.orm import Session
from backend.models import Event, EventRelationship, Incident, ServiceDependency, Service
from backend.models.base import generate_uuid, utc_now


class CorrelationEngine:
    def __init__(self, db: Session):
        self.db = db

    def correlate_incident_events(
        self,
        incident_id: str,
        time_window_seconds: int = 900,
    ) -> List[EventRelationship]:
        """Discovers deterministic causal and temporal correlations across incident events.
        
        Uses temporal-window sweeps (without arbitrary slice limits) and exact trace/request indices.
        Correlation scores represent calibrated heuristic weights (0.0 to 1.0).
        """
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
        dependency_pairs: Set[Tuple[str, str]] = {
            (service_map.get(d.source_service_id, ""), service_map.get(d.target_service_id, ""))
            for d in deps
            if d.source_service_id in service_map and d.target_service_id in service_map
        }

        # Clear older relationships for this incident for clean idempotency
        self.db.query(EventRelationship).filter(
            EventRelationship.incident_id == incident_id
        ).delete()

        created_relationships: List[EventRelationship] = []
        linked_pairs: Set[Tuple[str, str]] = set()

        # 1. Exact Trace ID and Request ID Indexing (Global across incident window)
        trace_index: Dict[str, List[Event]] = defaultdict(list)
        req_index: Dict[str, List[Event]] = defaultdict(list)

        for ev in events:
            norm = ev.normalized_data or {}
            raw = ev.raw_data or {}
            trace_id = norm.get("trace_id") or raw.get("trace_id")
            req_id = norm.get("request_id") or raw.get("request_id")
            if trace_id:
                trace_index[str(trace_id)].append(ev)
            if req_id:
                req_index[str(req_id)].append(ev)

        for trace_id, indexed_events in trace_index.items():
            if len(indexed_events) > 1:
                # Link sequentially along trace execution
                for k in range(len(indexed_events) - 1):
                    e1 = indexed_events[k]
                    e2 = indexed_events[k + 1]
                    if (e1.id, e2.id) not in linked_pairs and e1.id != e2.id:
                        linked_pairs.add((e1.id, e2.id))
                        rel = EventRelationship(
                            id=generate_uuid(),
                            incident_id=incident_id,
                            source_event_id=e1.id,
                            target_event_id=e2.id,
                            relationship_type="AFFECTED",
                            score=0.98,
                            reason=f"Shared distributed trace_id {trace_id} across {e1.service} and {e2.service}",
                            provenance={
                                "trace_id": trace_id,
                                "correlation_type": "EXACT_TRACE_PROPAGATION",
                                "source_types": [e1.source_type, e2.source_type],
                            },
                        )
                        self.db.add(rel)
                        created_relationships.append(rel)

        for req_id, indexed_events in req_index.items():
            if len(indexed_events) > 1:
                for k in range(len(indexed_events) - 1):
                    e1 = indexed_events[k]
                    e2 = indexed_events[k + 1]
                    if (e1.id, e2.id) not in linked_pairs and e1.id != e2.id:
                        linked_pairs.add((e1.id, e2.id))
                        rel = EventRelationship(
                            id=generate_uuid(),
                            incident_id=incident_id,
                            source_event_id=e1.id,
                            target_event_id=e2.id,
                            relationship_type="AFFECTED",
                            score=0.95,
                            reason=f"Shared request_id {req_id} across {e1.service} and {e2.service}",
                            provenance={
                                "request_id": req_id,
                                "correlation_type": "EXACT_REQUEST_PROPAGATION",
                                "source_types": [e1.source_type, e2.source_type],
                            },
                        )
                        self.db.add(rel)
                        created_relationships.append(rel)

        # 2. Temporal Window Sweep (No arbitrary 25-event slice limit)
        n_events = len(events)
        for i in range(n_events):
            e1 = events[i]
            for j in range(i + 1, n_events):
                e2 = events[j]
                time_delta = (e2.timestamp - e1.timestamp).total_seconds()
                if time_delta > time_window_seconds:
                    # Since events are sorted chronologically, no further event can be within window
                    break

                if (e1.id, e2.id) in linked_pairs or e1.id == e2.id:
                    continue

                rel_type: Optional[str] = None
                score: float = 0.0
                reason: str = ""

                # Criterion A: Change Event (Config/Deploy) followed by Anomaly/Error
                if e1.source_type in ("CONFIG", "DEPLOYMENT", "GIT_CHANGE") and e2.source_type in ("METRIC", "LOG", "ALERT"):
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
                            f"{e1.source_type} on {e1.service} preceded failure in caller {e2.service} "
                            f"({e2.service} -> {e1.service}) by {int(time_delta)}s"
                        )

                # Criterion B: Metric anomaly propagation across topological dependencies
                elif (e1.service, e2.service) in dependency_pairs or (e2.service, e1.service) in dependency_pairs:
                    caller, callee = (e1.service, e2.service) if (e1.service, e2.service) in dependency_pairs else (e2.service, e1.service)
                    if e1.service == callee and e2.service == caller:
                        rel_type = "AFFECTED"
                        score = 0.84
                        reason = f"Failure propagated from downstream dependency {callee} to caller {caller} within {int(time_delta)}s"
                    else:
                        rel_type = "DEPENDS_ON"
                        score = 0.75
                        reason = f"Topological dependency between {e1.service} and {e2.service} active during failure window"

                # Criterion C: Recovery timing (Rollback or mitigation followed by symptom clearance)
                elif "rollback" in str(e1.raw_data).lower() or "mitigate" in str(e1.raw_data).lower():
                    if e2.source_type in ("METRIC", "LOG") and ("normal" in str(e2.raw_data).lower() or "baseline" in str(e2.raw_data).lower()):
                        rel_type = "RECOVERED_AFTER"
                        score = 0.94
                        reason = f"System recovery observed {int(time_delta)}s following rollback/mitigation event"

                # Criterion D: Same host error proximity
                elif e1.host and e2.host and e1.host == e2.host and e1.service == e2.service:
                    rel_type = "CORRELATED_WITH"
                    score = 0.70
                    reason = f"Sequential events on host {e1.host} within {int(time_delta)}s"

                if rel_type and score >= 0.70:
                    linked_pairs.add((e1.id, e2.id))
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
                            "correlation_weight": score,
                        },
                    )
                    self.db.add(rel)
                    created_relationships.append(rel)

        self.db.flush()
        return created_relationships

    def build_causal_dag(self, incident_id: str) -> nx.DiGraph:
        """Constructs a directed causal DAG of incident events and their relationships."""
        dag = nx.DiGraph()

        events = self.db.query(Event).filter(Event.incident_id == incident_id).all()
        for ev in events:
            dag.add_node(
                ev.id,
                service=ev.service,
                source_type=ev.source_type,
                timestamp=ev.timestamp,
                host=ev.host,
                raw=ev.raw_data or {},
                normalized=ev.normalized_data or {},
            )

        rels = self.db.query(EventRelationship).filter(EventRelationship.incident_id == incident_id).all()
        for rel in rels:
            if dag.has_node(rel.source_event_id) and dag.has_node(rel.target_event_id):
                dag.add_edge(
                    rel.source_event_id,
                    rel.target_event_id,
                    relationship_type=rel.relationship_type,
                    score=rel.score,
                    reason=rel.reason,
                )

        return dag

    def extract_causal_chains(self, incident_id: str) -> List[Dict[str, Any]]:
        """Extracts candidate causal chains from the DAG to dynamically synthesize hypotheses."""
        dag = self.build_causal_dag(incident_id)
        if dag.number_of_nodes() == 0:
            return []

        # Candidate roots: in-degree 0 nodes or change events with outgoing edges
        candidate_root_ids = [
            n for n in dag.nodes
            if dag.out_degree(n) > 0 and (dag.in_degree(n) == 0 or dag.nodes[n].get("source_type") in ("CONFIG", "DEPLOYMENT", "GIT_CHANGE"))
        ]

        # If no strict in-degree 0 nodes, take earliest events with outgoing edges
        if not candidate_root_ids:
            sorted_nodes = sorted(dag.nodes, key=lambda n: dag.nodes[n].get("timestamp"))
            candidate_root_ids = [n for n in sorted_nodes if dag.out_degree(n) > 0][:5]

        chains: List[Dict[str, Any]] = []

        for root_id in candidate_root_ids:
            root_data = dag.nodes[root_id]
            descendants = nx.descendants(dag, root_id)
            if not descendants:
                continue

            subgraph_nodes = {root_id} | descendants
            sub = dag.subgraph(subgraph_nodes)

            path: List[str] = [root_id]
            curr = root_id
            visited = {curr}
            while True:
                successors = [s for s in sub.successors(curr) if s not in visited]
                if not successors:
                    break
                best_next = max(successors, key=lambda s: sub[curr][s].get("score", 0))
                path.append(best_next)
                visited.add(best_next)
                curr = best_next

            path_nodes_data = [dag.nodes[nid] for nid in path]
            services_in_path = []
            for nd in path_nodes_data:
                svc = nd.get("service")
                if svc and svc not in services_in_path:
                    services_in_path.append(svc)

            path_descriptions = []
            for nd in path_nodes_data:
                st = nd.get("source_type")
                svc = nd.get("service")
                raw = nd.get("raw") or {}
                if st == "CONFIG":
                    cfg_key = raw.get("config_key", "param")
                    path_descriptions.append(f"ConfigChange({svc}.{cfg_key})")
                elif st == "DEPLOYMENT":
                    ver = raw.get("version", "release")
                    path_descriptions.append(f"Deployment({svc}@{ver})")
                elif st == "METRIC":
                    m_name = raw.get("name", "metric")
                    path_descriptions.append(f"MetricAnomaly({svc}.{m_name})")
                elif st == "LOG":
                    path_descriptions.append(f"ErrorLog({svc})")
                elif st == "ALERT":
                    path_descriptions.append(f"Alert({svc})")
                else:
                    path_descriptions.append(f"{st}({svc})")

            summary = " -> ".join(path_descriptions)
            chain_scores = [
                dag[path[k]][path[k+1]].get("score", 0.7)
                for k in range(len(path) - 1)
            ]
            avg_score = sum(chain_scores) / len(chain_scores) if chain_scores else 0.75

            chains.append({
                "root_event_id": root_id,
                "root_service": root_data.get("service"),
                "trigger_type": root_data.get("source_type"),
                "trigger_raw": root_data.get("raw"),
                "path_event_ids": path,
                "affected_services": services_in_path,
                "causal_mechanism": summary,
                "chain_weight": round(avg_score, 2),
            })

        chains.sort(key=lambda c: c["chain_weight"], reverse=True)
        return chains
