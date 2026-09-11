from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from backend.models import Hypothesis, Incident, Evidence, Event, ConfigChange, Deployment, Anomaly, ServiceDependency, Service
from backend.models.base import generate_uuid
from backend.correlation.engine import CorrelationEngine
from backend.hypotheses.prove_me_wrong import ProveMeWrongEvaluator


class HypothesisEngine:
    """Pure evidence-driven hypothesis generation engine that builds causal candidates strictly from observed telemetry."""

    def __init__(self, db: Session):
        self.db = db
        self.evaluator = ProveMeWrongEvaluator(db)
        self.correlator = CorrelationEngine(db)

    def generate_competing_hypotheses(self, incident_id: str) -> List[Hypothesis]:
        """Generates competing, rival root-cause hypotheses dynamically from observed telemetry."""
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return []

        # Remove existing hypotheses to re-synthesize cleanly
        self.db.query(Hypothesis).filter(Hypothesis.incident_id == incident_id).delete()

        # 1. Discover causal chains from the Causal DAG
        causal_chains = self.correlator.extract_causal_chains(incident_id)

        # 2. Collect context telemetry
        anomalies = self.db.query(Anomaly).filter(Anomaly.incident_id == incident_id).all()
        all_services = list({a.service for a in anomalies if a.service}) or ["service"]

        # Check if actual deployment or config changes exist
        deployments = self.db.query(Deployment).all()
        config_changes = self.db.query(ConfigChange).all()

        candidates: List[Hypothesis] = []
        seen_mechanisms: Set[str] = set()

        # 3. Dynamic Generation from Observed Causal Chains in the DAG
        for chain in causal_chains:
            root_svc = chain.get("root_service") or all_services[0]
            trigger_type = chain.get("trigger_type")
            raw_trigger = chain.get("trigger_raw") or {}
            affected = chain.get("affected_services") or [root_svc]
            mechanism = chain.get("causal_mechanism", "")

            if mechanism in seen_mechanisms:
                continue
            seen_mechanisms.add(mechanism)

            if trigger_type == "CONFIG":
                cfg_key = raw_trigger.get("config_key", "system_parameter")
                old_val = raw_trigger.get("old_value", "")
                new_val = raw_trigger.get("new_value", "")
                statement = (
                    f"Configuration parameter '{cfg_key}' reduction ({old_val} -> {new_val}) on {root_svc} "
                    f"exhausted resource capacity, propagating cascade to {', '.join(affected[:3])}"
                )
                predicted_obs = [
                    {"type": "CONFIG", "service": root_svc, "description": f"Configuration change modifying '{cfg_key}' on {root_svc}", "mandatory": True, "weight": 1.2},
                    {"type": "METRIC", "service": root_svc, "description": f"Resource utilization anomaly on {root_svc}", "mandatory": True, "weight": 1.1},
                    {"type": "PROPAGATION", "service": affected[1] if len(affected) > 1 else root_svc, "description": "Cascading downstream latency or timeouts", "mandatory": False, "weight": 0.9},
                    {"type": "RECOVERY", "service": root_svc, "description": "Mitigation or rollback coincides with symptom resolution", "mandatory": False, "weight": 1.0},
                ]
                required_evid = [
                    {"evidence_type": "CONFIG", "entity": root_svc, "mandatory": True, "description": f"Configuration audit record for {root_svc}"},
                    {"evidence_type": "METRIC", "entity": root_svc, "mandatory": True, "description": f"Metric deviation telemetry for {root_svc}"},
                ]
                contradiction_rules = [
                    {"rule_type": "METRIC_REMAINED_NORMAL", "service": root_svc, "description": f"Resource metric on {root_svc} remained within normal baseline"},
                    {"rule_type": "ABSENT_CHANGE_RECORD", "service": root_svc, "description": f"Zero configuration records detected on {root_svc}"},
                ]

            elif trigger_type == "DEPLOYMENT":
                ver = raw_trigger.get("version", "latest")
                statement = (
                    f"Software deployment of version '{ver}' to {root_svc} introduced a code defect "
                    f"or memory regression, causing failure propagation to {', '.join(affected[:3])}"
                )
                predicted_obs = [
                    {"type": "DEPLOYMENT", "service": root_svc, "description": f"Software deployment of {ver} to {root_svc}", "mandatory": True, "weight": 1.2},
                    {"type": "LOG", "service": root_svc, "description": f"Application exception or error trace on {root_svc}", "mandatory": True, "weight": 1.0},
                    {"type": "PROPAGATION", "service": affected[1] if len(affected) > 1 else root_svc, "description": "Downstream request timeouts", "mandatory": False, "weight": 0.9},
                ]
                required_evid = [
                    {"evidence_type": "DEPLOYMENT", "entity": root_svc, "mandatory": True, "description": f"Deployment audit log for {root_svc}"},
                ]
                contradiction_rules = [
                    {"rule_type": "ZERO_DEPLOYMENTS", "description": "Zero software deployments occurred within incident window"},
                ]

            else:
                # Generic symptom-driven causal chain (e.g. queue lag, worker starvation, internal saturation)
                statement = (
                    f"Service degradation on {root_svc} ({mechanism}) triggered cascade and service timeouts across {', '.join(affected[:3])}"
                )
                predicted_obs = [
                    {"type": "METRIC", "service": root_svc, "description": f"Telemetry anomaly on {root_svc}", "mandatory": True, "weight": 1.1},
                    {"type": "LOG", "service": root_svc, "description": f"Error log emitted by {root_svc}", "mandatory": False, "weight": 0.9},
                    {"type": "PROPAGATION", "service": affected[1] if len(affected) > 1 else root_svc, "description": "Downstream latency cascade", "mandatory": False, "weight": 0.8},
                ]
                required_evid = [
                    {"evidence_type": "METRIC", "entity": root_svc, "mandatory": True, "description": f"Metric telemetry on {root_svc}"},
                ]
                contradiction_rules = [
                    {"rule_type": "METRIC_REMAINED_NORMAL", "service": root_svc, "description": f"Metrics on {root_svc} remained normal"},
                ]

            hyp = Hypothesis(
                id=generate_uuid(),
                incident_id=incident_id,
                statement=statement,
                claim=statement,
                causal_mechanism=mechanism,
                score=0.10,
                status="CANDIDATE",
                affected_services=affected,
                expected_observations=[p["description"] for p in predicted_obs],
                predicted_observations=predicted_obs,
                required_evidence=required_evid,
                supporting_rules=[
                    {"rule_type": "TEMPORAL_PRECEDENCE", "description": "Observed trigger preceded symptom onset"},
                    {"rule_type": "TOPOLOGICAL_PROPAGATION", "description": "Propagation matched service dependency graph"},
                ],
                contradiction_rules=contradiction_rules,
                actual_observations=[],
                missing_evidence=[],
                rank=len(candidates) + 1,
            )
            candidates.append(hyp)

        # 4. Synthesize Rival Topological Hypotheses from Observed Inbound/Outbound Dependencies
        # For caller services in the dependency chain, synthesize rival candidates asserting that the degradation
        # was an isolated internal issue on that caller rather than a cascade from downstream dependencies
        if len(candidates) >= 1 and len(all_services) > 1:
            for caller_service in reversed(all_services):
                mech = f"{caller_service} Internal Resource Saturation -> Direct Caller Timeouts"
                if mech in seen_mechanisms:
                    continue
                seen_mechanisms.add(mech)
                rival_caller = Hypothesis(
                    id=generate_uuid(),
                    incident_id=incident_id,
                    statement=f"Isolated internal capacity exhaustion on caller service {caller_service} independent of downstream dependencies",
                    claim=f"Isolated internal capacity exhaustion on caller service {caller_service} independent of downstream dependencies",
                    causal_mechanism=mech,
                    score=0.10,
                    status="CANDIDATE",
                    affected_services=[caller_service],
                    expected_observations=[
                        f"Isolated CPU/memory saturation on {caller_service} without dependency correlation",
                        f"Normal operational response times from downstream dependencies of {caller_service}",
                    ],
                    predicted_observations=[
                        {"type": "METRIC", "service": caller_service, "description": f"Resource exhaustion on {caller_service}", "mandatory": True, "weight": 1.0},
                    ],
                    required_evidence=[
                        {"evidence_type": "METRIC", "entity": caller_service, "mandatory": True, "description": f"Metric saturation on {caller_service}"},
                    ],
                    supporting_rules=[
                        {"rule_type": "LOCAL_SATURATION", "description": f"Isolated saturation on {caller_service}"},
                    ],
                    contradiction_rules=[
                        {"rule_type": "RECOVERY_COINCIDES_WITH_ROLLBACK", "description": "Caller recovery coincided with upstream dependency mitigation/rollback"},
                    ],
                    actual_observations=[],
                    missing_evidence=[],
                    rank=len(candidates) + 1,
                )
                candidates.append(rival_caller)
                if len(candidates) >= 5:
                    break

        # Persist candidates to DB
        for c in candidates:
            self.db.add(c)
        self.db.flush()

        # Run generic "Prove Me Wrong" evaluation on each
        for c in candidates:
            self.evaluator.evaluate_hypothesis(c)

        # Re-rank by score descending, prioritizing root change triggers in ties
        candidates.sort(
            key=lambda x: (
                round(x.score, 2),
                1 if any(p.get("type") in ("CONFIG", "DEPLOYMENT") for p in (x.predicted_observations or [])) else 0
            ),
            reverse=True,
        )
        for idx, c in enumerate(candidates):
            c.rank = idx + 1

        self.db.commit()
        return candidates
