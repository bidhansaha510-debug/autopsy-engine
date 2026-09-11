import networkx as nx
from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from backend.models import Service, ServiceDependency, Incident, Anomaly, LogEntry, Span
from backend.schemas.forensics import BlastRadiusResponse, ServiceNode, ServiceEdge


class BlastRadiusCalculator:
    def __init__(self, db: Session):
        self.db = db

    def build_graph(self) -> nx.DiGraph:
        """Constructs a directed graph of services where edges point from caller to callee."""
        G = nx.DiGraph()
        services = self.db.query(Service).all()
        for svc in services:
            G.add_node(
                svc.name,
                id=svc.id,
                tier=svc.tier,
                environment=svc.environment,
                oncall=svc.oncall_team,
            )

        deps = self.db.query(ServiceDependency).all()
        for d in deps:
            src = self.db.query(Service).filter(Service.id == d.source_service_id).first()
            tgt = self.db.query(Service).filter(Service.id == d.target_service_id).first()
            if src and tgt:
                G.add_edge(
                    src.name,
                    tgt.name,
                    id=d.id,
                    dependency_type=d.dependency_type,
                    is_critical=d.is_critical,
                    avg_latency_ms=d.avg_latency_ms,
                )
        return G

    def calculate_blast_radius(
        self,
        incident_id: str,
        root_service_hint: Optional[str] = None,
    ) -> BlastRadiusResponse:
        G = self.build_graph()

        # Identify services with detected anomalies
        anomalies = self.db.query(Anomaly).filter(Anomaly.incident_id == incident_id).all()
        anomalous_services = {a.service for a in anomalies}

        # Identify services with error logs
        error_logs = (
            self.db.query(LogEntry.service)
            .filter(
                LogEntry.incident_id == incident_id,
                LogEntry.level.in_(["ERROR", "FATAL", "CRITICAL"]),
            )
            .distinct()
            .all()
        )
        error_services = {r[0] for r in error_logs}

        # Identify failing spans
        failed_spans = (
            self.db.query(Span.service)
            .filter(Span.status == "ERROR")
            .distinct()
            .all()
        )
        failing_span_services = {r[0] for r in failed_spans}

        active_symptom_services = anomalous_services | error_services | failing_span_services

        # Determine patient zero / root service
        root_service = root_service_hint
        if not root_service and active_symptom_services:
            # If no root hint, find deepest callee among active symptom services
            # (i.e. service with no downstream failing services or deepest in DAG)
            candidates = list(active_symptom_services)
            # Pick one with lowest out-degree to other failing services
            def failing_outdegree(s):
                if s not in G:
                    return 0
                return sum(1 for neighbor in G.successors(s) if neighbor in active_symptom_services)
            candidates.sort(key=failing_outdegree)
            root_service = candidates[0] if candidates else None

        directly_affected: Set[str] = set()
        indirectly_affected: Set[str] = set()
        customer_facing: Set[str] = set()
        propagation_path: List[str] = []

        if root_service and root_service in G:
            directly_affected.add(root_service)
            # Traverse upstream (predecessors: callers that depend on this service)
            # In DiGraph, callers are G.predecessors(service)
            upstream_callers = nx.ancestors(G, root_service)
            for caller in upstream_callers:
                if caller in active_symptom_services:
                    indirectly_affected.add(caller)
                else:
                    # Potential risk / degraded
                    pass

            # Any service with tier-1 or no predecessors is customer-facing
            for node_name in (directly_affected | indirectly_affected):
                node_data = G.nodes.get(node_name, {})
                tier = node_data.get("tier", "")
                in_degree = G.in_degree(node_name) if node_name in G else 0
                if tier == "tier-1" or in_degree == 0 or "gateway" in node_name.lower() or "api" in node_name.lower():
                    customer_facing.add(node_name)

            # Reconstruct propagation path from root service up to customer facing endpoints
            for cf in customer_facing:
                if nx.has_path(G, cf, root_service):
                    path = nx.shortest_path(G, cf, root_service)
                    # Reverse path so it represents root cause -> callers -> customer facing
                    propagation_path = list(reversed(path))
                    break
        else:
            directly_affected = active_symptom_services

        all_graph_nodes = set(G.nodes())
        all_affected = directly_affected | indirectly_affected
        unaffected = list(all_graph_nodes - all_affected)

        nodes_list: List[ServiceNode] = []
        for n in all_graph_nodes:
            node_data = G.nodes.get(n, {})
            status = "HEALTHY"
            if n in directly_affected:
                status = "FAILED"
            elif n in indirectly_affected:
                status = "DEGRADED"

            nodes_list.append(
                ServiceNode(
                    id=node_data.get("id", n),
                    name=n,
                    tier=node_data.get("tier", "tier-2"),
                    environment=node_data.get("environment", "production"),
                    status=status,
                    is_directly_affected=n in directly_affected,
                    is_indirectly_affected=n in indirectly_affected,
                    is_customer_facing=n in customer_facing,
                )
            )

        edges_list: List[ServiceEdge] = []
        for u, v, data in G.edges(data=True):
            edge_status = "NORMAL"
            if v in directly_affected or (u in all_affected and v in all_affected):
                edge_status = "FAILING"
            elif u in indirectly_affected or v in indirectly_affected:
                edge_status = "DEGRADED"

            edges_list.append(
                ServiceEdge(
                    source=u,
                    target=v,
                    dependency_type=data.get("dependency_type", "RPC"),
                    is_critical=data.get("is_critical", True),
                    status=edge_status,
                )
            )

        return BlastRadiusResponse(
            incident_id=incident_id,
            root_cause_service=root_service,
            directly_affected=sorted(list(directly_affected)),
            indirectly_affected=sorted(list(indirectly_affected)),
            customer_facing_endpoints=sorted(list(customer_facing)),
            unaffected_services=sorted(unaffected),
            nodes=nodes_list,
            edges=edges_list,
            propagation_path=propagation_path,
        )
