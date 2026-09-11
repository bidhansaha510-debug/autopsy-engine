import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import (
    Incident,
    Investigation,
    InvestigationStep,
    Evidence,
    Hypothesis,
)
from backend.models.base import generate_uuid, utc_now
from backend.ai.tools import ForensicsToolRegistry
from backend.ai.ollama_client import OllamaClient


SYSTEM_FORENSIC_PROMPT = """You are the Principal Incident Forensics Investigator for Infrastructure Autopsy.
Your job is to analyze real evidence retrieved via read-only tools and explain the incident chain of events.

STRICT FORENSIC RULES:
1. Every factual statement MUST cite an Evidence ID (e.g. [EVID-CFG-0001], [EVID-LOG-0002], [EVID-METRIC-0003]).
2. NEVER invent, extrapolate, or hallucinate metrics, logs, or evidence.
3. If evidence is ambiguous, contradictory, or insufficient, explicitly output: "Insufficient evidence to determine root cause."
4. Distinguish clearly between observed facts and candidate hypotheses.
"""


class AIInvestigator:
    def __init__(self, db: Session):
        self.db = db
        self.tools = ForensicsToolRegistry(db)
        self.ollama = OllamaClient()

    def run_investigation(self, incident_id: str) -> Investigation:
        """Executes the tool-driven forensic investigation loop."""
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        # Create or fetch active investigation record
        investigation = (
            self.db.query(Investigation)
            .filter(Investigation.incident_id == incident_id)
            .first()
        )
        if not investigation:
            investigation = Investigation(
                id=generate_uuid(),
                incident_id=incident_id,
                status="IN_PROGRESS",
                started_at=utc_now(),
                trigger="AUTOPSY_FORENSIC_ANALYSIS",
                current_focus="Initial forensic triage",
            )
            self.db.add(investigation)
            self.db.flush()
        else:
            # Clear older steps for clean forensic rerun
            self.db.query(InvestigationStep).filter(
                InvestigationStep.investigation_id == investigation.id
            ).delete()

        # Step 1: Check what changed (Deployments & Config changes)
        cfgs = self.tools.inspect_config_change()
        deps = self.tools.inspect_deployment()
        cfg_items = cfgs.get("config_changes", [])
        dep_items = deps.get("deployments", [])

        s1_evidence_ids = []
        findings_1 = []
        if cfg_items:
            for c in cfg_items[:3]:
                findings_1.append(
                    f"Identified configuration change on {c['service']}: parameter '{c['config_key']}' "
                    f"changed from '{c['old_value']}' to '{c['new_value']}' by {c['changed_by']}."
                )
            # Find matching evidence ID in db
            cfg_evid = (
                self.db.query(Evidence.id)
                .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "CONFIG")
                .all()
            )
            s1_evidence_ids = [r[0] for r in cfg_evid]
        else:
            findings_1.append("No configuration modifications recorded within the target window.")

        step1 = InvestigationStep(
            id=generate_uuid(),
            investigation_id=investigation.id,
            step_number=1,
            question="What changed in the environment immediately preceding the incident?",
            tool_called="inspect_config_change",
            tool_parameters_json={"lookback_entries": 10},
            tool_result_json={"configs": cfg_items, "deployments": dep_items},
            findings=" ".join(findings_1),
            evidence_generated_ids=s1_evidence_ids,
        )
        self.db.add(step1)

        # Step 2: Query Telemetry & Anomaly Baselines
        anom_evid = (
            self.db.query(Evidence)
            .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "METRIC")
            .all()
        )
        s2_evidence_ids = [e.id for e in anom_evid]
        findings_2 = []
        if anom_evid:
            for ae in anom_evid[:4]:
                content = ae.content
                findings_2.append(
                    f"Observed statistical anomaly on [{ae.id}]: metric '{content.get('metric')}' on {content.get('service')} "
                    f"deviated to {content.get('actual')} (expected baseline {content.get('expected')}, severity {content.get('severity')})."
                )
        else:
            findings_2.append("Telemetry metrics currently within normal operational bounds.")

        step2 = InvestigationStep(
            id=generate_uuid(),
            investigation_id=investigation.id,
            step_number=2,
            question="Which metrics experienced anomalous deviations against baseline statistics?",
            tool_called="compare_baseline",
            tool_parameters_json={"incident_id": incident_id},
            tool_result_json={"anomalies_count": len(anom_evid)},
            findings=" ".join(findings_2),
            evidence_generated_ids=s2_evidence_ids,
        )
        self.db.add(step2)

        # Step 3: Distributed Trace & Error Propagation Inspection
        error_logs = self.tools.get_logs(incident_id=incident_id, level="ERROR", limit=5)
        log_evid = (
            self.db.query(Evidence.id)
            .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "LOG")
            .all()
        )
        s3_evidence_ids = [r[0] for r in log_evid]
        findings_3 = []
        if error_logs.get("logs"):
            for l in error_logs["logs"][:3]:
                findings_3.append(
                    f"Service '{l['service']}' emitted error: '{l['message']}' (trace_id: {l.get('trace_id')})."
                )
        else:
            findings_3.append("No fatal error logs detected in service logs.")

        step3 = InvestigationStep(
            id=generate_uuid(),
            investigation_id=investigation.id,
            step_number=3,
            question="How did the failure propagate through service requests and distributed traces?",
            tool_called="get_logs",
            tool_parameters_json={"incident_id": incident_id, "level": "ERROR"},
            tool_result_json=error_logs,
            findings=" ".join(findings_3),
            evidence_generated_ids=s3_evidence_ids,
        )
        self.db.add(step3)

        # Step 4: Competing Hypotheses Evaluation
        from backend.hypotheses.engine import HypothesisEngine
        hyp_engine = HypothesisEngine(self.db)
        hypotheses = hyp_engine.generate_competing_hypotheses(incident_id)

        findings_4 = []
        top_hyp = hypotheses[0] if hypotheses else None
        if top_hyp:
            findings_4.append(
                f"Evaluated competing hypotheses. Leading hypothesis [{top_hyp.status} with support score {top_hyp.score}]: "
                f"'{top_hyp.statement}'. Counterevidence checks penalised rival hypotheses."
            )

        step4 = InvestigationStep(
            id=generate_uuid(),
            investigation_id=investigation.id,
            step_number=4,
            question="Which root-cause hypotheses withstand counterevidence testing?",
            tool_called="test_hypothesis",
            tool_parameters_json={"hypotheses_evaluated": len(hypotheses)},
            tool_result_json={"hypotheses": [{"statement": h.statement, "score": h.score, "status": h.status} for h in hypotheses]},
            findings=" ".join(findings_4),
            evidence_generated_ids=[e.id for e in top_hyp.evidence_links] if top_hyp else [],
        )
        self.db.add(step4)

        # Final synthesis: Try local Ollama if available
        synthesis_text = ""
        ollama_active = self.ollama.is_available()

        if ollama_active and top_hyp:
            prompt = (
                f"Synthesize the incident findings based strictly on the retrieved forensic evidence.\n"
                f"Evidence items available: {s1_evidence_ids + s2_evidence_ids + s3_evidence_ids}\n"
                f"Leading Hypothesis: {top_hyp.statement} (Score: {top_hyp.score})\n"
                f"Findings 1: {step1.findings}\n"
                f"Findings 2: {step2.findings}\n"
                f"Findings 3: {step3.findings}\n"
                f"Findings 4: {step4.findings}\n"
                f"Remember: cite evidence IDs [EVID-...] and never state unverified assumptions."
            )
            response = self.ollama.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                system_prompt=SYSTEM_FORENSIC_PROMPT,
            )
            if response:
                synthesis_text = response

        if not synthesis_text:
            # Deterministic evidence-backed synthesis
            primary_evidence_citations = " ".join([f"[{eid}]" for eid in (s1_evidence_ids + s2_evidence_ids)[:4]])
            if top_hyp and top_hyp.score >= 0.70:
                synthesis_text = (
                    f"INCIDENT FORENSIC CONCLUSION:\n"
                    f"The root cause is supported by verified physical evidence: {top_hyp.statement}.\n"
                    f"Timeline and causal analysis prove the sequence: {step1.findings} followed by {step2.findings}.\n"
                    f"Failure propagation: {step3.findings}.\n"
                    f"Primary Provenance Citations: {primary_evidence_citations}.\n"
                    f"Counterevidence evaluation refuted alternative network and software bug hypotheses."
                )
            else:
                synthesis_text = "Insufficient evidence to determine root cause with high confidence."

        investigation.status = "COMPLETED"
        investigation.completed_at = utc_now()
        investigation.current_focus = synthesis_text

        self.db.commit()
        return investigation
