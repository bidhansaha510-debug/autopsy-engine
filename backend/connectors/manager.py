from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.models import Incident, Service, ServiceDependency
from backend.models.base import generate_uuid, utc_now
from backend.connectors.prometheus import PrometheusConnector
from backend.connectors.kubernetes import KubernetesConnector
from backend.connectors.git_deployments import GitDeploymentConnector
from backend.anomaly.detector import AnomalyDetector
from backend.correlation.engine import CorrelationEngine
from backend.hypotheses.engine import HypothesisEngine
from backend.reports.generator import ForensicReportGenerator


class StackPullManager:
    """Unified manager to orchestrate pulling telemetry directly from your live or simulated

    infrastructure stack (Prometheus, Kubernetes, Git) after an incident occurs.
    """

    def __init__(self, db: Session):
        self.db = db

    def pull_stack_telemetry(
        self,
        lookback_hours: float = 2.0,
        incident_id: Optional[str] = None,
        case_title: Optional[str] = None,
        providers: Optional[List[str]] = None,
        prometheus_url: str = "http://localhost:9090",
        kubernetes_api: str = "http://localhost:8001",
        kubernetes_namespace: str = "production",
        git_repo: str = "corp/payment-service",
        services: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Pulls telemetry from selected stack providers over the lookback window,

        seeds the incident case file, and triggers deterministic forensic analysis.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=lookback_hours)
        end_time = now

        target_providers = [p.lower() for p in (providers or ["prometheus", "kubernetes", "git"])]
        target_services = services or ["payment-service", "checkout-service", "api-gateway"]

        # 1. Create or attach to Incident
        if not incident_id:
            incident = Incident(
                id=generate_uuid(),
                title=case_title or f"Live Incident Autopsy: {now.strftime('%Y-%m-%d %H:%M')} UTC",
                severity="SEV1",
                status="ACTIVE",
                started_at=start_time + timedelta(minutes=15),
                summary=f"Incident case file reconstructed by pulling live stack telemetry across the preceding {lookback_hours} hours.",
                is_simulated=False,
            )
            self.db.add(incident)
            self.db.flush()
            incident_id = incident.id
        else:
            incident = self.db.query(Incident).filter(Incident.id == incident_id).first()

        # Ensure basic services and topology dependencies exist
        self._ensure_topology(target_services)

        provider_results: Dict[str, Any] = {}

        # 2. Pull from Prometheus
        if "prometheus" in target_providers:
            prom = PrometheusConnector(self.db, base_url=prometheus_url)
            provider_results["prometheus"] = prom.pull_metrics(
                incident_id=incident_id,
                start_time=start_time,
                end_time=end_time,
                services=target_services,
                allow_mock_fallback=True,
            )

        # 3. Pull from Kubernetes
        if "kubernetes" in target_providers or "k8s" in target_providers:
            k8s = KubernetesConnector(self.db, api_server=kubernetes_api, namespace=kubernetes_namespace)
            provider_results["kubernetes"] = k8s.pull_events(
                incident_id=incident_id,
                start_time=start_time,
                end_time=end_time,
                services=target_services,
                allow_mock_fallback=True,
            )

        # 4. Pull from Git / Deployments
        if "git" in target_providers or "github" in target_providers:
            git = GitDeploymentConnector(self.db, repo=git_repo)
            provider_results["git"] = git.pull_deployments(
                incident_id=incident_id,
                start_time=start_time,
                end_time=end_time,
                services=target_services,
                allow_mock_fallback=True,
            )

        self.db.commit()

        # 5. Run full forensic analytical pipeline
        detector = AnomalyDetector(self.db)
        anomalies = detector.analyze_incident_metrics(incident_id)

        correlator = CorrelationEngine(self.db)
        relationships = correlator.correlate_incident_events(incident_id)

        hyp_engine = HypothesisEngine(self.db)
        hypotheses = hyp_engine.generate_competing_hypotheses(incident_id)

        # Generate initial post-mortem draft
        report_gen = ForensicReportGenerator(self.db)
        report = report_gen.generate_incident_report(incident_id)

        top_hyp = hypotheses[0] if hypotheses else None

        return {
            "incident_id": incident_id,
            "incident_title": incident.title,
            "lookback_hours": lookback_hours,
            "providers_queried": list(provider_results.keys()),
            "provider_details": provider_results,
            "anomalies_detected": len(anomalies),
            "correlations_linked": len(relationships),
            "hypotheses_count": len(hypotheses),
            "leading_hypothesis": {
                "statement": top_hyp.statement if top_hyp else "Analyzing telemetry",
                "score": top_hyp.score if top_hyp else 0.0,
                "status": top_hyp.status if top_hyp else "ANALYZING",
            } if top_hyp else None,
            "report_id": report.id if report else None,
        }

    def _ensure_topology(self, services: List[str]):
        """Ensures services and directed dependencies exist in the graph."""
        svc_objs = {}
        for sname in services:
            s = self.db.query(Service).filter(Service.name == sname).first()
            if not s:
                tier = "tier-1" if any(w in sname for w in ("api", "gateway", "checkout")) else "tier-2"
                s = Service(
                    id=generate_uuid(),
                    name=sname,
                    tier=tier,
                    environment="production",
                    repo_url=f"git://github.com/corp/{sname}.git",
                    oncall_team=f"team-{tier}",
                )
                self.db.add(s)
                self.db.flush()
            svc_objs[sname] = s

        # Connect caller to callee if applicable (api-gateway -> checkout-service -> payment-service)
        chain = [s for s in ["api-gateway", "checkout-service", "payment-service"] if s in svc_objs]
        for i in range(len(chain) - 1):
            src = svc_objs[chain[i]]
            tgt = svc_objs[chain[i + 1]]
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
                    dependency_type="RPC",
                    is_critical=True,
                    avg_latency_ms=25.0,
                )
                self.db.add(dep)
        self.db.flush()
