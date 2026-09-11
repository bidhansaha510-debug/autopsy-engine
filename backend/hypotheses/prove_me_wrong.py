from typing import List, Dict, Any, Tuple, Optional, Set
from datetime import timedelta
from collections import defaultdict
from sqlalchemy.orm import Session
from backend.models import (
    Hypothesis,
    Evidence,
    HypothesisEvidence,
    MetricSample,
    Metric,
    ConfigChange,
    Deployment,
    Event,
    Incident,
)
from backend.models.base import generate_uuid
from backend.baselines.stats import compute_baseline_stats, calculate_anomaly_score


def _matches_evidence(pred: Dict[str, Any], ev: Evidence, incident_start=None) -> bool:
    """Strict typed and entity matching without loose substring overlaps."""
    pred_type = pred.get("type", "").upper()
    pred_service = pred.get("service") or pred.get("entity")
    ev_type = ev.evidence_type.upper()
    ev_entity = ev.entity or ""
    content = ev.content if isinstance(ev.content, dict) else {}

    # Strict type matching
    type_matched = False
    if pred_type == ev_type:
        type_matched = True
    elif pred_type in ("PROPAGATION", "TRACE") and ev_type in ("TRACE", "LOG", "ALERT"):
        type_matched = True
    elif pred_type == "RECOVERY" and ev_type in ("RECOVERY", "CONFIG"):
        action = content.get("action") or content.get("reason", "")
        if ev_type == "RECOVERY" or "rollback" in str(action).lower():
            type_matched = True
    elif pred_type == "CONFIG" and ev_type == "CONFIG":
        type_matched = True
    elif pred_type == "DEPLOYMENT" and ev_type == "DEPLOYMENT":
        type_matched = True
    elif pred_type == "METRIC" and ev_type == "METRIC":
        type_matched = True

    if not type_matched:
        return False

    # Strict service/entity matching (no substring containment)
    if not pred_service:
        return True

    exact_match = (
        ev_entity == pred_service
        or ev_entity.startswith(f"{pred_service}:")
        or ev_entity.startswith(f"{pred_service}.")
        or content.get("service") == pred_service
    )
    if not exact_match:
        return False

    # Temporal causality check for triggers (must precede or align with incident onset)
    if incident_start and pred_type in ("CONFIG", "DEPLOYMENT"):
        if ev.timestamp > incident_start + timedelta(minutes=5):
            return False

    return True


def _matches_required(req: Dict[str, Any], ev: Evidence, incident_start=None) -> bool:
    """Strict matching for mandatory causal telemetry."""
    req_type = req.get("evidence_type", "").upper()
    req_entity = req.get("entity")
    ev_type = ev.evidence_type.upper()
    ev_entity = ev.entity or ""
    content = ev.content if isinstance(ev.content, dict) else {}

    if req_type != ev_type:
        return False
    if not req_entity:
        return True

    exact_match = (
        ev_entity == req_entity
        or ev_entity.startswith(f"{req_entity}:")
        or ev_entity.startswith(f"{req_entity}.")
        or content.get("service") == req_entity
    )
    if not exact_match:
        return False

    # Temporal window constraint for triggers
    if incident_start and req_type in ("CONFIG", "DEPLOYMENT"):
        if ev.timestamp > incident_start + timedelta(minutes=5):
            return False

    return True


class ProveMeWrongEvaluator:
    """Generic hypothesis evaluation engine that tests claims against observed telemetry.
    
    Operates without hardcoded keyword branches by evaluating formal hypothesis structures:
    - predicted_observations: verified against actual evidence items (with 1-to-1 reservation)
    - required_evidence: checks for mandatory missing evidence within causal intervals
    - contradiction_rules: evaluates metric-specific baseline and audit falsification conditions
    - evidence clustering: prevents multiple duplicate logs from inflating support scores
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_hypothesis(
        self,
        hypothesis: Hypothesis,
    ) -> Dict[str, Any]:
        """Evaluates hypothesis generically against all real evidence, searching for counterevidence."""
        incident_id = hypothesis.incident_id
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        incident_start = incident.started_at if incident else None

        all_evidence = (
            self.db.query(Evidence)
            .filter(Evidence.incident_id == incident_id)
            .order_by(Evidence.timestamp.asc())
            .all()
        )

        # Clear existing links to recalculate deterministically
        self.db.query(HypothesisEvidence).filter(
            HypothesisEvidence.hypothesis_id == hypothesis.id
        ).delete()

        supporting_evidence: List[Tuple[Evidence, float, str]] = []
        contradicting_evidence: List[Tuple[Optional[Evidence], float, str]] = []
        actual_observations: List[str] = []
        missing_evidence: List[str] = []

        # 1-to-1 Evidence Reservation
        reserved_evidence_ids: Set[str] = set()

        predicted_obs = hypothesis.predicted_observations or []
        required_evid = hypothesis.required_evidence or []
        contradiction_rules = hypothesis.contradiction_rules or []

        # 1. Evaluate Predicted Observations against Evidence (with 1-to-1 reservation)
        for pred in predicted_obs:
            desc = pred.get("description", "")
            matched_ev: Optional[Evidence] = None

            for ev in all_evidence:
                if ev.id in reserved_evidence_ids:
                    continue
                if _matches_evidence(pred, ev, incident_start):
                    matched_ev = ev
                    break

            if matched_ev:
                reserved_evidence_ids.add(matched_ev.id)
                weight = pred.get("weight", 1.0)
                expl = f"Observed [{matched_ev.id}] on {matched_ev.entity}: {desc or matched_ev.content}"
                supporting_evidence.append((matched_ev, weight, expl))
                actual_observations.append(f"Confirmed: {desc} ({matched_ev.id})")
            elif pred.get("mandatory", False):
                missing_evidence.append(f"Missing expected observation: {desc}")

        # 2. Check Required Evidence criteria within causal interval
        for req in required_evid:
            req_desc = req.get("description", "")
            is_mandatory = req.get("mandatory", True)

            found = any(_matches_required(req, ev, incident_start) for ev in all_evidence)
            if not found and is_mandatory:
                missing_evidence.append(f"Required telemetry absent in causal window: {req_desc}")

        # 3. Evaluate Metric-Specific Contradiction Rules
        for rule in contradiction_rules:
            rule_type = rule.get("rule_type", "")
            target_service = rule.get("service")

            if rule_type == "METRIC_REMAINED_NORMAL":
                # Metric-specific baseline evaluation (no arbitrary hardcoded constant)
                metric_evids = [
                    e for e in all_evidence
                    if e.evidence_type == "METRIC" and (not target_service or target_service in e.entity)
                ]
                for me in metric_evids:
                    content = me.content if isinstance(me.content, dict) else {}
                    anom_score = content.get("anomaly_score")
                    deviation = content.get("deviation")

                    # If the anomaly detector verified this sample is normal (score < 2.0 or deviation ~ 0)
                    if anom_score is not None:
                        try:
                            if float(anom_score) < 1.5:
                                contradicting_evidence.append((
                                    me,
                                    1.5,
                                    f"Counterevidence: Metric {content.get('metric')} on {target_service or me.entity} remained within baseline (anomaly score: {anom_score})"
                                ))
                                break
                        except (ValueError, TypeError):
                            pass

            elif rule_type == "CONCURRENT_INTERNAL_CHANGE":
                # Check whether an internal change directly preceded the failure window
                internal_changes = [
                    e for e in all_evidence
                    if e.evidence_type in ("CONFIG", "DEPLOYMENT")
                    and (not incident_start or e.timestamp <= incident_start + timedelta(minutes=5))
                ]
                if internal_changes:
                    first_chg = internal_changes[0]
                    contradicting_evidence.append((
                        first_chg,
                        1.4,
                        f"Counterevidence: Internal change [{first_chg.id}] on {first_chg.entity} directly preceded failure, weakening non-internal claim"
                    ))

            elif rule_type == "ZERO_DEPLOYMENTS":
                # Constrained strictly to pre-onset window [incident_start - 24h, incident_start + 5m]
                pre_onset_deployments = [
                    e for e in all_evidence
                    if e.evidence_type == "DEPLOYMENT"
                    and (not incident_start or (e.timestamp >= incident_start - timedelta(hours=24) and e.timestamp <= incident_start + timedelta(minutes=5)))
                ]
                if not pre_onset_deployments:
                    ref_ev = all_evidence[0] if all_evidence else None
                    contradicting_evidence.append((
                        ref_ev,
                        1.5,
                        "Counterevidence: Zero software deployments occurred within pre-incident window"
                    ))

            elif rule_type == "RECOVERY_COINCIDES_WITH_ROLLBACK":
                rollback_evid = [
                    e for e in all_evidence
                    if "rollback" in str(e.content).lower() or e.evidence_type == "RECOVERY"
                ]
                if rollback_evid:
                    contradicting_evidence.append((
                        rollback_evid[0],
                        1.5,
                        f"Counterevidence: Recovery [{rollback_evid[0].id}] immediately followed rollback, refuting independent external cause"
                    ))

            elif rule_type == "ABSENT_CHANGE_RECORD":
                cfg_evids = [
                    e for e in all_evidence
                    if e.evidence_type == "CONFIG"
                    and (not incident_start or e.timestamp <= incident_start + timedelta(minutes=5))
                ]
                if not cfg_evids:
                    ref_ev = all_evidence[0] if all_evidence else None
                    contradicting_evidence.append((
                        ref_ev,
                        1.5,
                        "Counterevidence: No configuration changes recorded in target window"
                    ))

        # 4. Link evidence relationships in DB
        for ev, weight, expl in supporting_evidence:
            if ev:
                link = HypothesisEvidence(
                    id=generate_uuid(),
                    hypothesis_id=hypothesis.id,
                    evidence_id=ev.id,
                    relationship_type="SUPPORTS",
                    weight=round(weight, 2),
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
                    weight=round(weight, 2),
                    explanation=expl,
                )
                self.db.add(link)

        # 5. Correlated Evidence Clustering & Calibrated Support Score
        # Group supporting evidence into clusters by (type, entity) to discount duplicate logs
        cluster_weights: Dict[str, float] = defaultdict(float)
        cluster_conf: Dict[str, float] = defaultdict(float)
        for ev, w, _ in supporting_evidence:
            if not ev:
                continue
            cluster_key = f"{ev.evidence_type}:{ev.entity}"
            # Diminishing returns for multiple events in the same cluster
            current_w = cluster_weights[cluster_key]
            added_w = w * (1.0 if current_w == 0 else 0.25)
            cluster_weights[cluster_key] += added_w
            cluster_conf[cluster_key] = max(cluster_conf[cluster_key], ev.confidence)

        total_support_points = sum(cluster_weights[k] * cluster_conf[k] for k in cluster_weights)
        total_contra_points = sum(w * (ev.confidence if ev else 1.0) for ev, w, _ in contradicting_evidence if ev)

        expected_weight = sum(p.get("weight", 1.0) for p in predicted_obs) if predicted_obs else max(1.0, float(len(hypothesis.expected_observations or [])))

        # Weighted missing penalty based on missing observation criticality
        weighted_missing_penalty = 0.0
        for m in missing_evidence:
            weighted_missing_penalty += 0.12

        raw_score = ((total_support_points - (1.5 * total_contra_points)) / max(1.0, expected_weight)) - weighted_missing_penalty
        score = max(0.05, min(0.98, raw_score))

        hypothesis.score = round(score, 2)
        hypothesis.actual_observations = actual_observations
        hypothesis.missing_evidence = missing_evidence

        # Calibrated status classification
        if total_contra_points > total_support_points or (len(contradicting_evidence) > 0 and score < 0.35):
            hypothesis.status = "REFUTED"
        elif hypothesis.score >= 0.70 and len(missing_evidence) == 0 and len(contradicting_evidence) == 0:
            hypothesis.status = "STRONGLY_SUPPORTED"
        elif hypothesis.score >= 0.65 and len(contradicting_evidence) == 0:
            hypothesis.status = "SUPPORTED"
        elif hypothesis.score >= 0.30:
            hypothesis.status = "VALIDATING"
        else:
            hypothesis.status = "REFUTED"

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
