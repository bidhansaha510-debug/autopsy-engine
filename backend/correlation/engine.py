import math
from datetime import timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
import networkx as nx
from sqlalchemy.orm import Session
from backend.models import (
    Event,
    EventRelationship,
    Incident,
    ServiceDependency,
    Service,
    Intervention,
    Span,
)
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
        
        Uses temporal-window sweeps, span parent-child hierarchies, multi-criteria evaluation
        (without mutually-exclusive if/elif dropping), and calibrated correlation decay.
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
        linked_type_pairs: Set[Tuple[str, str, str]] = set()

        # Load structured interventions for recovery correlation
        interventions = (
            self.db.query(Intervention)
            .filter(Intervention.incident_id == incident_id)
            .all()
        )
        rollback_services = {
            itv.target_service: itv
            for itv in interventions
            if itv.action_type == "ROLLBACK"
        }

        # 1. Trace Span Hierarchy & Exact Request Correlation
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

        # Index known spans by trace_id to correlate by parent/child rather than naive timestamp sort
        all_spans = self.db.query(Span).filter(Span.trace_id.in_(list(trace_index.keys()))).all() if trace_index else []
        span_by_id = {s.span_id: s for s in all_spans}
        spans_by_trace: Dict[str, List[Span]] = defaultdict(list)
        for s in all_spans:
            spans_by_trace[s.trace_id].append(s)

        for trace_id, indexed_events in trace_index.items():
            trace_spans = spans_by_trace.get(trace_id, [])
            span_event_map: Dict[str, Event] = {}
            for ev in indexed_events:
                norm = ev.normalized_data or {}
                raw = ev.raw_data or {}
                sid = norm.get("span_id") or raw.get("span_id")
                if sid:
                    span_event_map[str(sid)] = ev

            # Link along span hierarchy if available
            hierarchy_linked = False
            for s in trace_spans:
                parent_ev = span_event_map.get(s.parent_span_id or "")
                child_ev = span_event_map.get(s.span_id)
                if parent_ev and child_ev and parent_ev.id != child_ev.id:
                    key = (parent_ev.id, child_ev.id, "AFFECTED")
                    if key not in linked_type_pairs:
                        linked_type_pairs.add(key)
                        rel = EventRelationship(
                            id=generate_uuid(),
                            incident_id=incident_id,
                            source_event_id=parent_ev.id,
                            target_event_id=child_ev.id,
                            relationship_type="AFFECTED",
                            score=0.95,
                            reason=f"Direct parent-child span invocation in trace {trace_id} ({parent_ev.service} -> {child_ev.service})",
                            provenance={
                                "trace_id": trace_id,
                                "parent_span_id": s.parent_span_id,
                                "child_span_id": s.span_id,
                                "correlation_type": "SPAN_HIERARCHY_PROPAGATION",
                            },
                        )
                        self.db.add(rel)
                        created_relationships.append(rel)
                        hierarchy_linked = True

            # If no explicit span objects existed, link chronologically with interval check
            if not hierarchy_linked and len(indexed_events) > 1:
                for k in range(len(indexed_events) - 1):
                    e1 = indexed_events[k]
                    e2 = indexed_events[k + 1]
                    key = (e1.id, e2.id, "AFFECTED")
                    if key not in linked_type_pairs and e1.id != e2.id:
                        linked_type_pairs.add(key)
                        rel = EventRelationship(
                            id=generate_uuid(),
                            incident_id=incident_id,
                            source_event_id=e1.id,
                            target_event_id=e2.id,
                            relationship_type="AFFECTED",
                            score=0.90,
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
                    key = (e1.id, e2.id, "AFFECTED")
                    if key not in linked_type_pairs and e1.id != e2.id:
                        linked_type_pairs.add(key)
                        rel = EventRelationship(
                            id=generate_uuid(),
                            incident_id=incident_id,
                            source_event_id=e1.id,
                            target_event_id=e2.id,
                            relationship_type="AFFECTED",
                            score=0.88,
                            reason=f"Shared request_id {req_id} across {e1.service} and {e2.service}",
                            provenance={
                                "request_id": req_id,
                                "correlation_type": "EXACT_REQUEST_PROPAGATION",
                                "source_types": [e1.source_type, e2.source_type],
                            },
                        )
                        self.db.add(rel)
                        created_relationships.append(rel)

        # 2. Multi-Criteria Temporal Window Sweep (Independent Evaluation)
        n_events = len(events)
        for i in range(n_events):
            e1 = events[i]
            for j in range(i + 1, n_events):
                e2 = events[j]
                time_delta = (e2.timestamp - e1.timestamp).total_seconds()
                if time_delta > time_window_seconds:
                    break

                if e1.id == e2.id:
                    continue

                # Calibrated time decay factor: tau = 300 seconds
                decay = math.exp(-time_delta / 300.0)

                # Criterion A: Change Event Preceding Anomaly/Error
                if e1.source_type in ("CONFIG", "DEPLOYMENT", "GIT_CHANGE") and e2.source_type in ("METRIC", "LOG", "ALERT"):
                    is_same_service = e1.service == e2.service
                    is_dependent_caller = (e2.service, e1.service) in dependency_pairs

                    if is_same_service:
                        score = round(max(0.70, 0.92 * decay), 2)
                        key = (e1.id, e2.id, "PRECEDED")
                        if key not in linked_type_pairs:
                            linked_type_pairs.add(key)
                            created_relationships.append(
                                self._create_rel(
                                    incident_id, e1.id, e2.id, "PRECEDED", score,
                                    f"{e1.source_type} change on {e1.service} preceded {e2.source_type} symptom by {int(time_delta)}s with exact service match",
                                    {"criterion": "CHANGE_PRECEDENCE", "delta_seconds": time_delta, "decay": round(decay, 3)}
                                )
                            )
                    elif is_dependent_caller:
                        score = round(max(0.65, 0.88 * decay), 2)
                        key = (e1.id, e2.id, "AFFECTED")
                        if key not in linked_type_pairs:
                            linked_type_pairs.add(key)
                            created_relationships.append(
                                self._create_rel(
                                    incident_id, e1.id, e2.id, "AFFECTED", score,
                                    f"{e1.source_type} on {e1.service} preceded failure in caller {e2.service} ({e2.service} -> {e1.service}) by {int(time_delta)}s",
                                    {"criterion": "CHANGE_DEPENDENCY_CASCADE", "delta_seconds": time_delta, "decay": round(decay, 3)}
                                )
                            )

                # Criterion B: Metric / Symptom Propagation Across Topological Dependencies
                is_downstream_to_upstream = (e2.service, e1.service) in dependency_pairs
                is_upstream_to_downstream = (e1.service, e2.service) in dependency_pairs

                if is_downstream_to_upstream:
                    score = round(max(0.65, 0.85 * decay), 2)
                    key = (e1.id, e2.id, "AFFECTED")
                    if key not in linked_type_pairs:
                        linked_type_pairs.add(key)
                        created_relationships.append(
                            self._create_rel(
                                incident_id, e1.id, e2.id, "AFFECTED", score,
                                f"Failure propagated from downstream callee {e1.service} to caller {e2.service} within {int(time_delta)}s",
                                {"criterion": "TOPOLOGICAL_PROPAGATION", "delta_seconds": time_delta}
                            )
                        )
                elif is_upstream_to_downstream:
                    score = round(max(0.60, 0.75 * decay), 2)
                    key = (e1.id, e2.id, "DEPENDS_ON")
                    if key not in linked_type_pairs:
                        linked_type_pairs.add(key)
                        created_relationships.append(
                            self._create_rel(
                                incident_id, e1.id, e2.id, "DEPENDS_ON", score,
                                f"Topological dependency call from {e1.service} to {e2.service} recorded during incident window",
                                {"criterion": "TOPOLOGICAL_DEPENDENCY", "delta_seconds": time_delta}
                            )
                        )

                # Criterion C: Structured Recovery Correlation
                is_recovery_trigger = (
                    e1.source_type == "RECOVERY"
                    or (e1.service in rollback_services and (e1.source_type == "CONFIG" or "rollback" in str(e1.raw_data).lower()))
                    or e1.normalized_data.get("action") == "ROLLBACK"
                )
                if is_recovery_trigger:
                    is_normalized_symptom = (
                        e2.source_type in ("METRIC", "LOG")
                        and (e2.normalized_data.get("status") == "OK" or "normal" in str(e2.raw_data).lower() or "baseline" in str(e2.raw_data).lower())
                    )
                    if is_normalized_symptom:
                        score = round(max(0.70, 0.94 * decay), 2)
                        key = (e1.id, e2.id, "RECOVERED_AFTER")
                        if key not in linked_type_pairs:
                            linked_type_pairs.add(key)
                            created_relationships.append(
                                self._create_rel(
                                    incident_id, e1.id, e2.id, "RECOVERED_AFTER", score,
                                    f"System recovery observed {int(time_delta)}s following verified intervention/rollback on {e1.service}",
                                    {"criterion": "STRUCTURED_RECOVERY", "delta_seconds": time_delta}
                                )
                            )

                # Criterion D: Same Host Co-location (Immediate temporal proximity, not dense N^2 clique)
                if e1.host and e2.host and e1.host == e2.host and e1.service == e2.service and e1.id != e2.id:
                    if j == i + 1 or time_delta <= 15.0:
                        score = round(max(0.50, 0.65 * decay), 2)
                        key = (e1.id, e2.id, "CORRELATED_WITH")
                        if key not in linked_type_pairs:
                            linked_type_pairs.add(key)
                            created_relationships.append(
                                self._create_rel(
                                    incident_id, e1.id, e2.id, "CORRELATED_WITH", score,
                                    f"Sequential events on host {e1.host} within {int(time_delta)}s",
                                    {"criterion": "HOST_PROXIMITY", "delta_seconds": time_delta}
                                )
                            )

        self.db.flush()
        return created_relationships

    def _create_rel(
        self,
        incident_id: str,
        src_id: str,
        tgt_id: str,
        rel_type: str,
        score: float,
        reason: str,
        prov: Dict[str, Any],
    ) -> EventRelationship:
        rel = EventRelationship(
            id=generate_uuid(),
            incident_id=incident_id,
            source_event_id=src_id,
            target_event_id=tgt_id,
            relationship_type=rel_type,
            score=score,
            reason=reason,
            provenance=prov,
        )
        self.db.add(rel)
        return rel

    def build_causal_dag(self, incident_id: str) -> nx.DiGraph:
        """Constructs a directed graph and enforces strict DAG acyclicity via feedback arc cycle breaking."""
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

        # Enforce DAG acyclicity: break cycles by eliminating lowest-scoring back-edges
        self._ensure_acyclic(dag)
        return dag

    @staticmethod
    def _ensure_acyclic(dag: nx.DiGraph) -> None:
        """Guarantees the graph is a strict DAG by iteratively breaking cycles on the lowest-confidence edge."""
        max_iterations = 200
        iteration = 0
        while not nx.is_directed_acyclic_graph(dag) and iteration < max_iterations:
            iteration += 1
            try:
                cycle = nx.find_cycle(dag, orientation="original")
            except Exception:
                break

            # Find the edge in the cycle with the lowest score
            weakest_edge = None
            min_score = float("inf")
            for u, v, _ in cycle:
                score = dag[u][v].get("score", 0.5)
                if score < min_score:
                    min_score = score
                    weakest_edge = (u, v)

            if weakest_edge:
                dag.remove_edge(*weakest_edge)
            else:
                break

    def extract_causal_chains(self, incident_id: str) -> List[Dict[str, Any]]:
        """Extracts candidate causal chains using DAG topological dynamic programming in O(V + E) time."""
        dag = self.build_causal_dag(incident_id)
        if dag.number_of_nodes() == 0:
            return []

        # Candidate roots: in-degree 0 nodes or change events with outgoing edges
        candidate_root_ids = [
            n for n in dag.nodes
            if dag.out_degree(n) > 0 and (dag.in_degree(n) == 0 or dag.nodes[n].get("source_type") in ("CONFIG", "DEPLOYMENT", "GIT_CHANGE"))
        ]

        if not candidate_root_ids:
            sorted_nodes = sorted(dag.nodes, key=lambda n: dag.nodes[n].get("timestamp"))
            candidate_root_ids = [n for n in sorted_nodes if dag.out_degree(n) > 0][:5]

        chains: List[Dict[str, Any]] = []
        seen_paths: Set[Tuple[str, ...]] = set()

        for root_id in candidate_root_ids:
            root_data = dag.nodes[root_id]
            descendants = nx.descendants(dag, root_id)
            if not descendants:
                continue

            sub_nodes = {root_id} | descendants
            sub = dag.subgraph(sub_nodes)

            # Global optimal path via DAG topological dynamic programming (O(V + E))
            topo_order = list(nx.topological_sort(sub))
            dist: Dict[str, float] = {n: -float("inf") for n in topo_order}
            parent: Dict[str, Optional[str]] = {n: None for n in topo_order}
            hops: Dict[str, int] = {n: 0 for n in topo_order}
            dist[root_id] = 0.0

            for u in topo_order:
                if dist[u] == -float("inf"):
                    continue
                for v in sub.successors(u):
                    w = sub[u][v].get("score", 0.7)
                    if dist[u] + w > dist[v]:
                        dist[v] = dist[u] + w
                        parent[v] = u
                        hops[v] = hops[u] + 1

            valid_targets = [n for n in sub_nodes if hops[n] >= 1]
            if not valid_targets:
                continue

            best_target = max(valid_targets, key=lambda n: dist[n] / max(1, hops[n]))
            best_path_score = dist[best_target] / max(1, hops[best_target])

            path = []
            curr: Optional[str] = best_target
            while curr is not None:
                path.append(curr)
                curr = parent[curr]
            best_path = list(reversed(path))

            path_tuple = tuple(best_path)
            if path_tuple in seen_paths:
                continue
            seen_paths.add(path_tuple)

            path_nodes_data = [dag.nodes[nid] for nid in best_path]
            services_in_path: List[str] = []
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

            chains.append({
                "root_event_id": root_id,
                "root_service": root_data.get("service"),
                "trigger_type": root_data.get("source_type"),
                "trigger_raw": root_data.get("raw"),
                "path_event_ids": best_path,
                "affected_services": services_in_path,
                "causal_mechanism": summary,
                "chain_weight": round(best_path_score, 2),
                "chain_status": "TOPOLOGICALLY_CORROBORATED" if len(services_in_path) > 1 else "CANDIDATE_CORRELATION",
            })

        chains.sort(key=lambda c: c["chain_weight"], reverse=True)
        return chains
