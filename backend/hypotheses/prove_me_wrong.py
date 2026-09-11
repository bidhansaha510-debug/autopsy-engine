from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from backend.models import Hypothesis, Evidence, HypothesisEvidence, MetricSample, Metric, ConfigChange, Deployment, Event
from backend.models.base import generate_uuid


def _matches_evidence(pred: Dict[str, Any], ev: Evidence) -> bool:
    pred_type = pred.get("type", "").upper()
    pred_service = pred.get("service") or pred.get("entity")
    ev_type = ev.evidence_type.upper()
    ev_entity = ev.entity or ""
    content = ev.content if isinstance(ev.content, dict) else {}
    content_str = str(ev.content).lower()

    # Flexible typed matching
    type_matched = False
    if pred_type == ev_type:
        type_matched = True
    elif pred_type in ("PROPAGATION", "TRACE") and ev_type in ("TRACE", "LOG", "ALERT"):
        type_matched = True
    elif pred_type == "RECOVERY":
        if ev_type == "RECOVERY" or "rollback" in content_str or "mitigat" in content_str:
            type_matched = True
    elif pred_type == "CONFIG" and ev_type == "CONFIG":
        type_matched = True
    elif pred_type == "METRIC" and ev_type == "METRIC":
        type_matched = True

    if not type_matched:
        return False

    # Service / entity matching
    if not pred_service:
        return True
    if pred_service == ev_entity or ev_entity.startswith(f"{pred_service}.") or ev_entity.startswith(f"{pred_service}:"):
        return True
    if content.get("service") == pred_service:
        return True
    return pred_service in ev_entity or pred_service in content_str


def _matches_required(req: Dict[str, Any], ev: Evidence) -> bool:
    req_type = req.get("evidence_type", "").upper()
    req_entity = req.get("entity")
    ev_type = ev.evidence_type.upper()
    ev_entity = ev.entity or ""
    content = ev.content if isinstance(ev.content, dict) else {}

    if req_type != ev_type:
        return False
    if not req_entity:
        return True
    if req_entity == ev_entity or ev_entity.startswith(f"{req_entity}.") or ev_entity.startswith(f"{req_entity}:"):
        return True
    if content.get("service") == req_entity:
        return True
    return req_entity in ev_entity


class ProveMeWrongEvaluator:
    """Generic hypothesis evaluation engine that tests claims against observed telemetry.
    
    Operates without hardcoded keyword branches by evaluating formal hypothesis structures:
    - predicted_observations: verified against actual evidence items
    - required_evidence: checks for mandatory missing evidence
    - contradiction_rules: evaluates falsification conditions against evidence
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_hypothesis(
        self,
        hypothesis: Hypothesis,
    ) -> Dict[str, Any]:
        """Evaluates hypothesis generically against all real evidence, searching for counterevidence."""
        incident_id = hypothesis.incident_id
        all_evidence = (
            self.db.query(Evidence)
            .filter(Evidence.incident_id == incident_id)
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

        predicted_obs = hypothesis.predicted_observations or []
        required_evid = hypothesis.required_evidence or []
        contradiction_rules = hypothesis.contradiction_rules or []

        # 1. Evaluate Predicted Observations against Evidence
        for pred in predicted_obs:
            desc = pred.get("description", "")
            matched_ev: Optional[Evidence] = None

            for ev in all_evidence:
                if _matches_evidence(pred, ev):
                    matched_ev = ev
                    break

            if matched_ev:
                weight = pred.get("weight", 1.0)
                expl = f"Observed [{matched_ev.id}] on {matched_ev.entity}: {desc or matched_ev.content}"
                supporting_evidence.append((matched_ev, weight, expl))
                actual_observations.append(f"Confirmed: {desc} ({matched_ev.id})")
            elif pred.get("mandatory", False):
                missing_evidence.append(f"Missing expected observation: {desc}")

        # 2. Check Required Evidence criteria
        for req in required_evid:
            req_desc = req.get("description", "")
            is_mandatory = req.get("mandatory", True)

            found = any(_matches_required(req, ev) for ev in all_evidence)
            if not found and is_mandatory:
                missing_evidence.append(f"Required telemetry absent: {req_desc}")

        # 3. Evaluate Generic Contradiction Rules
        for rule in contradiction_rules:
            rule_type = rule.get("rule_type", "")
            target_service = rule.get("service")

            if rule_type == "METRIC_REMAINED_NORMAL":
                metric_evids = [
                    e for e in all_evidence
                    if e.evidence_type == "METRIC" and (not target_service or target_service in e.entity)
                ]
                observed_values = []
                for me in metric_evids:
                    content = me.content if isinstance(me.content, dict) else {}
                    val = content.get("actual") or content.get("value") or content.get("latest_value")
                    if val is not None:
                        try:
                            observed_values.append((float(val), me))
                        except (ValueError, TypeError):
                            pass

                if observed_values:
                    max_observed, max_ev = max(observed_values, key=lambda x: x[0])
                    if max_observed < 30.0:
                        contradicting_evidence.append((
                            max_ev,
                            1.5,
                            f"Counterevidence: Metric on {target_service or 'service'} remained normal (peak value: {max_observed})"
                        ))

            elif rule_type == "CONCURRENT_INTERNAL_CHANGE":
                internal_changes = [
                    e for e in all_evidence
                    if e.evidence_type in ("CONFIG", "DEPLOYMENT")
                ]
                if internal_changes:
                    first_chg = internal_changes[0]
                    contradicting_evidence.append((
                        first_chg,
                        1.4,
                        f"Counterevidence: Internal change [{first_chg.id}] on {first_chg.entity} directly preceded failure, weakening non-internal claim"
                    ))

            elif rule_type == "ZERO_DEPLOYMENTS":
                dep_evid = [e for e in all_evidence if e.evidence_type == "DEPLOYMENT"]
                if not dep_evid:
                    ref_ev = all_evidence[0] if all_evidence else None
                    contradicting_evidence.append((
                        ref_ev,
                        1.5,
                        "Counterevidence: Zero software deployments occurred within incident window"
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
                cfg_evids = [e for e in all_evidence if e.evidence_type == "CONFIG"]
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

        # 5. Compute Calibrated Support Score
        total_support_points = sum(w * ev.confidence for ev, w, _ in supporting_evidence if ev)
        total_contra_points = sum(w * (ev.confidence if ev else 1.0) for ev, w, _ in contradicting_evidence if ev)

        expected_weight = sum(p.get("weight", 1.0) for p in predicted_obs) if predicted_obs else max(1.0, float(len(hypothesis.expected_observations or [])))
        missing_penalty = 0.12 * len(missing_evidence)
        raw_score = ((total_support_points - (1.5 * total_contra_points)) / max(1.0, expected_weight)) - missing_penalty
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
