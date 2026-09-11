from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.models import Hypothesis, Evidence, HypothesisEvidence, MetricSample, Metric, ConfigChange, Deployment
from backend.models.base import generate_uuid


class ProveMeWrongEvaluator:
    def __init__(self, db: Session):
        self.db = db

    def evaluate_hypothesis(
        self,
        hypothesis: Hypothesis,
    ) -> Dict[str, Any]:
        """Evaluates hypothesis against all real evidence, searching specifically for counterevidence."""
        incident_id = hypothesis.incident_id
        all_evidence = (
            self.db.query(Evidence)
            .filter(Evidence.incident_id == incident_id)
            .all()
        )

        statement_lower = hypothesis.statement.lower()

        # Clear existing links to recalculate deterministically
        self.db.query(HypothesisEvidence).filter(
            HypothesisEvidence.hypothesis_id == hypothesis.id
        ).delete()

        supporting_evidence: List[Tuple[Evidence, float, str]] = []
        contradicting_evidence: List[Tuple[Evidence, float, str]] = []
        actual_observations: List[str] = []
        missing_evidence: List[str] = []

        # Archetype 1: Database Connection Pool Exhaustion / Config Reduction
        if "pool" in statement_lower or "database" in statement_lower or "db" in statement_lower:
            # Positive checks
            cfg_evid = [e for e in all_evidence if e.evidence_type == "CONFIG" and ("pool" in str(e.content).lower() or "db" in str(e.content).lower())]
            for ce in cfg_evid:
                supporting_evidence.append((ce, 1.2, f"Configuration change reduced pool size or DB parameters: {ce.content.get('config_key')}"))
                actual_observations.append(f"Recorded config reduction {ce.content.get('old_value')} -> {ce.content.get('new_value')}")

            db_metrics = [e for e in all_evidence if e.evidence_type == "METRIC" and ("pool" in e.entity.lower() or "connection" in e.entity.lower())]
            for me in db_metrics:
                actual_val = me.content.get("actual") or me.content.get("latest_value", 0)
                expected_val = me.content.get("expected", 0)
                if actual_val > expected_val or actual_val > 80:
                    supporting_evidence.append((me, 1.0, f"Observed elevated DB connection metric on {me.entity}: {actual_val}"))
                    actual_observations.append(f"DB connection utilization reached {actual_val}")
                elif actual_val < 20:
                    # COUNTEREVIDENCE: Connection pool utilization stayed low
                    contradicting_evidence.append((me, 1.5, f"Counterevidence: DB connection metric remained low ({actual_val}) on {me.entity}"))

            timeout_logs = [e for e in all_evidence if e.evidence_type == "LOG" and ("timeout" in str(e.content).lower() or "pool" in str(e.content).lower() or "connection" in str(e.content).lower())]
            for le in timeout_logs:
                supporting_evidence.append((le, 0.8, f"Service log confirms timeouts waiting for resources: {le.content.get('message')}"))
                actual_observations.append(f"Timeouts recorded on {le.entity}")

            recovery_evid = [e for e in all_evidence if e.evidence_type in ("CONFIG", "RECOVERY", "DEPLOYMENT") and "rollback" in str(e.content).lower()]
            for re in recovery_evid:
                supporting_evidence.append((re, 1.0, f"Recovery immediately followed rollback of config change: {re.id}"))
                actual_observations.append("Rollback directly restored healthy metric baseline")

            if not cfg_evid:
                missing_evidence.append("No recorded database configuration change in audit log")
            if not db_metrics:
                missing_evidence.append("No active database connection pool timeseries telemetry available")

        # Archetype 2: External / Upstream Network Degradation
        elif "network" in statement_lower or "upstream" in statement_lower or "gateway" in statement_lower:
            net_logs = [e for e in all_evidence if e.evidence_type == "LOG" and ("packet loss" in str(e.content).lower() or "network" in str(e.content).lower() or "unreachable" in str(e.content).lower())]
            for ne in net_logs:
                supporting_evidence.append((ne, 1.0, f"Network error log observed: {ne.content.get('message')}"))
                actual_observations.append(f"Network error on {ne.entity}")

            # Check if internal config change exists (COUNTEREVIDENCE against pure external network failure)
            cfg_evid = [e for e in all_evidence if e.evidence_type == "CONFIG"]
            if cfg_evid:
                contradicting_evidence.append((cfg_evid[0], 1.2, "Counterevidence: Internal configuration change directly preceded symptoms, weakening pure network failure hypothesis"))

            if not net_logs:
                missing_evidence.append("No network packet loss, interface drops, or ICMP latency telemetry recorded")

        # Archetype 3: Application Code Regression / Deployment Bug
        elif "code" in statement_lower or "regression" in statement_lower or "deployment" in statement_lower or "release" in statement_lower:
            dep_evid = [e for e in all_evidence if e.evidence_type == "DEPLOYMENT"]
            for de in dep_evid:
                supporting_evidence.append((de, 1.0, f"Deployment {de.content.get('version')} occurred prior to failure"))
                actual_observations.append(f"Deployment of version {de.content.get('version')} to {de.entity}")

            if not dep_evid:
                missing_evidence.append("No software deployments occurred prior to incident onset")
                # Counterevidence: claim of deployment bug when no deployment occurred
                contradicting_evidence.append((all_evidence[0] if all_evidence else None, 0.9, "Counterevidence: Zero code deployments detected within incident window"))

        # General evidence linkage
        for ev, weight, expl in supporting_evidence:
            if ev:
                link = HypothesisEvidence(
                    id=generate_uuid(),
                    hypothesis_id=hypothesis.id,
                    evidence_id=ev.id,
                    relationship_type="SUPPORTS",
                    weight=weight,
                    explanation=expl,
                )
                self.db.add(link)

        for ev, weight, expl in contradicting_evidence:
            if ev:
                link = HypothesisEvidence(
                    id=generate_uuid(),
                    hypothesis_id=hypothesis.id,
                    evidence_id=ev.id,
                    relationship_type="CONTRADICTS",
                    weight=weight,
                    explanation=expl,
                )
                self.db.add(link)

        # Calculate calibrated investigation support score
        total_support_points = sum(w * ev.confidence for ev, w, _ in supporting_evidence if ev)
        total_contra_points = sum(w * (ev.confidence if ev else 1.0) for ev, w, _ in contradicting_evidence if ev)

        base_expected = max(1.0, float(len(hypothesis.expected_observations)))
        raw_score = (total_support_points - (1.5 * total_contra_points)) / (base_expected * 1.2)
        score = max(0.05, min(0.98, raw_score))

        hypothesis.score = round(score, 2)
        hypothesis.actual_observations = actual_observations
        hypothesis.missing_evidence = missing_evidence

        if hypothesis.score >= 0.70:
            hypothesis.status = "SUPPORTED"
        elif hypothesis.score <= 0.25:
            hypothesis.status = "REFUTED"
        else:
            hypothesis.status = "VALIDATING"

        self.db.flush()
        return {
            "hypothesis_id": hypothesis.id,
            "statement": hypothesis.statement,
            "score": hypothesis.score,
            "status": hypothesis.status,
            "supporting_count": len(supporting_evidence),
            "contradicting_count": len(contradicting_evidence),
            "missing_evidence": missing_evidence,
        }
