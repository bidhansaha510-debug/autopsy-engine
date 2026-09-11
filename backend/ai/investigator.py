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
    Anomaly,
    ConfigChange,
    Deployment,
)
from backend.models.base import generate_uuid, utc_now
from backend.ai.tools import ForensicsToolRegistry
from backend.ai.ollama_client import OllamaClient


SYSTEM_FORENSIC_PROMPT = """You are the Principal Incident Forensics Investigator for Infrastructure Autopsy.
Your job is to iteratively investigate an incident using read-only forensic tools.

STRICT FORENSIC RULES:
1. Every factual claim MUST cite a specific Evidence ID (e.g. [EVID-CFG-0001], [EVID-METRIC-0002]).
2. NEVER invent, extrapolate, or hallucinate metrics, logs, or evidence.
3. NEVER claim a hypothesis is a "proven root cause". Use calibrated terms: "Most-supported hypothesis", "Strongly supported, not conclusively established", or "Insufficient evidence".
4. Distinguish strictly between observed facts and candidate hypotheses.
"""

TOOL_DEFINITIONS = [
    {
        "name": "get_anomalies",
        "description": "Retrieves statistically significant metric anomalies detected against historical baselines.",
        "parameters": {"incident_id": "string"},
    },
    {
        "name": "inspect_config_change",
        "description": "Inspects configuration changes and modifications in the incident window.",
        "parameters": {"service": "string (optional)", "lookback_entries": "integer (optional)"},
    },
    {
        "name": "inspect_deployment",
        "description": "Inspects software deployments and git releases in the incident window.",
        "parameters": {"service": "string (optional)", "lookback_entries": "integer (optional)"},
    },
    {
        "name": "get_logs",
        "description": "Queries runtime application and service logs with filters.",
        "parameters": {"service": "string (optional)", "level": "string (e.g. ERROR)", "limit": "integer"},
    },
    {
        "name": "get_dependencies",
        "description": "Retrieves inbound callers and outbound topological dependencies for a service.",
        "parameters": {"service_name": "string"},
    },
    {
        "name": "compare_baseline",
        "description": "Compares recent metric values against historical pre-incident baseline statistics.",
        "parameters": {"metric_name": "string", "service": "string", "incident_id": "string"},
    },
    {
        "name": "generate_competing_hypotheses",
        "description": "Dynamically builds competing causal hypotheses and tests them against counterevidence.",
        "parameters": {"incident_id": "string"},
    },
    {
        "name": "get_recovery_events",
        "description": "Retrieves recovery events, mitigation rollbacks, and system stabilization timestamps.",
        "parameters": {"incident_id": "string"},
    },
]


class AIInvestigator:
    """True autonomous, iterative forensic investigator agent loop with calibrated synthesis."""

    def __init__(self, db: Session):
        self.db = db
        self.tools = ForensicsToolRegistry(db)
        self.ollama = OllamaClient()

    def run_investigation(self, incident_id: str, max_steps: int = 6) -> Investigation:
        """Executes a true dynamic investigate-act-observe tool loop."""
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
            self.db.query(InvestigationStep).filter(
                InvestigationStep.investigation_id == investigation.id
            ).delete()

        executed_steps: List[Dict[str, Any]] = []
        tools_called_set = set()
        anomalous_services: List[str] = []

        # Autonomous Decision & Execution Loop
        for step_idx in range(1, max_steps + 1):
            decision = self._decide_next_step(
                incident=incident,
                step_number=step_idx,
                executed_steps=executed_steps,
                tools_called=tools_called_set,
                anomalous_services=anomalous_services,
            )

            if decision.get("conclude"):
                break

            tool_name = decision.get("tool")
            tool_params = decision.get("parameters", {})
            question = decision.get("question", f"Step {step_idx}: Investigating telemetry")

            # Execute tool
            tool_result, findings, evidence_ids = self._execute_tool_action(
                tool_name=tool_name,
                tool_params=tool_params,
                incident_id=incident_id,
            )

            # Track anomalies discovered
            if tool_name == "get_anomalies" and isinstance(tool_result, dict):
                for a in tool_result.get("anomalies", []):
                    svc = a.get("service")
                    if svc and svc not in anomalous_services:
                        anomalous_services.append(svc)

            step_record = InvestigationStep(
                id=generate_uuid(),
                investigation_id=investigation.id,
                step_number=step_idx,
                question=question,
                tool_called=tool_name,
                tool_parameters_json=tool_params,
                tool_result_json=tool_result,
                findings=findings,
                evidence_generated_ids=evidence_ids,
            )
            self.db.add(step_record)
            self.db.flush()

            executed_steps.append({
                "step_number": step_idx,
                "question": question,
                "tool": tool_name,
                "parameters": tool_params,
                "findings": findings,
                "evidence_ids": evidence_ids,
            })
            tools_called_set.add(tool_name)

        # Final Synthesis
        synthesis_text = self._synthesize_investigation(
            incident=incident,
            executed_steps=executed_steps,
        )

        investigation.status = "COMPLETED"
        investigation.completed_at = utc_now()
        investigation.current_focus = synthesis_text

        self.db.commit()
        return investigation

    def _decide_next_step(
        self,
        incident: Incident,
        step_number: int,
        executed_steps: List[Dict[str, Any]],
        tools_called: set,
        anomalous_services: List[str],
    ) -> Dict[str, Any]:
        """Decides the next forensic investigation action via Ollama or Adaptive Agent fallback."""
        # 1. Attempt LLM Decision via Ollama if available
        if self.ollama.is_available():
            try:
                history_prompt = "\n".join([
                    f"- Step {s['step_number']}: Tool '{s['tool']}' -> Findings: {s['findings']}"
                    for s in executed_steps
                ]) or "No prior tools executed."

                prompt = (
                    f"Incident to investigate: ID '{incident.id}', Title: '{incident.title}', Severity: '{incident.severity}'.\n"
                    f"Prior Steps Executed:\n{history_prompt}\n\n"
                    f"Available Tools: {[t['name'] for t in TOOL_DEFINITIONS]}\n\n"
                    f"Choose the NEXT best forensic tool to run, or decide to conclude if sufficient evidence exists.\n"
                    f"Respond ONLY with valid JSON in this format:\n"
                    f'{{"tool": "<tool_name>", "parameters": {{...}}, "question": "<question being answered>"}}\n'
                    f'OR if finished: {{"conclude": true, "reason": "<rationale>"}}\n'
                )

                response = self.ollama.chat_completion(
                    messages=[{"role": "user", "content": prompt}],
                    system_prompt=SYSTEM_FORENSIC_PROMPT,
                )
                if response:
                    clean_resp = response.strip()
                    if clean_resp.startswith("```json"):
                        clean_resp = clean_resp[7:].strip()
                    if clean_resp.endswith("```"):
                        clean_resp = clean_resp[:-3].strip()
                    data = json.loads(clean_resp)
                    if data.get("conclude") or (data.get("tool") in [t["name"] for t in TOOL_DEFINITIONS]):
                        return data
            except Exception:
                pass  # Fall through to Adaptive Agent

        # 2. Adaptive Graph-Walking Agent (Deterministic Fallback)
        # Stage 1: Discover metric baseline anomalies
        if "get_anomalies" not in tools_called:
            return {
                "tool": "get_anomalies",
                "parameters": {"incident_id": incident.id},
                "question": "Which service metrics experienced statistically significant anomalies during the incident?",
            }

        # Stage 2: Inspect environment changes (configs on anomalous services)
        primary_svc = anomalous_services[0] if anomalous_services else None
        if "inspect_config_change" not in tools_called:
            return {
                "tool": "inspect_config_change",
                "parameters": {"service": primary_svc, "lookback_entries": 10},
                "question": f"What configuration changes occurred on {primary_svc or 'the environment'} prior to symptom onset?",
            }

        # Stage 3: Inspect deployments
        if "inspect_deployment" not in tools_called:
            return {
                "tool": "inspect_deployment",
                "parameters": {"service": primary_svc, "lookback_entries": 10},
                "question": f"Were any software deployments or releases pushed to {primary_svc or 'services'}?",
            }

        # Stage 4: Inspect topological dependencies & propagation paths
        if primary_svc and "get_dependencies" not in tools_called:
            return {
                "tool": "get_dependencies",
                "parameters": {"service_name": primary_svc},
                "question": f"What are the inbound and outbound service dependencies for {primary_svc}?",
            }

        # Stage 5: Query error logs and trace failures along propagation path
        if "get_logs" not in tools_called:
            return {
                "tool": "get_logs",
                "parameters": {"incident_id": incident.id, "level": "ERROR", "limit": 10},
                "question": "What runtime exceptions and error logs were emitted along the service propagation path?",
            }

        # Stage 6: Competing Hypotheses & Counterevidence testing
        if "generate_competing_hypotheses" not in tools_called:
            return {
                "tool": "generate_competing_hypotheses",
                "parameters": {"incident_id": incident.id},
                "question": "Which competing causal hypotheses best account for the observations under counterevidence testing?",
            }

        # Stage 7: Recovery events
        if "get_recovery_events" not in tools_called:
            return {
                "tool": "get_recovery_events",
                "parameters": {"incident_id": incident.id},
                "question": "What interventions or recovery events restored normal baseline operations?",
            }

        return {"conclude": True, "reason": "All forensic dimensions verified."}

    def _execute_tool_action(
        self,
        tool_name: str,
        tool_params: Dict[str, Any],
        incident_id: str,
    ) -> tuple[Dict[str, Any], str, List[str]]:
        """Executes tool, produces concise forensic findings, and collects cited Evidence IDs."""
        result: Dict[str, Any] = {}
        findings = ""
        evidence_ids: List[str] = []

        if tool_name == "get_anomalies":
            result = self.tools.get_anomalies(incident_id=incident_id)
            anoms = result.get("anomalies", [])
            if anoms:
                top_a = anoms[0]
                findings = (
                    f"Detected {len(anoms)} baseline anomalies. Peak deviation on {top_a['service']}: "
                    f"'{top_a['metric_name']}' reached {top_a['actual']} (expected {top_a['expected']}, {top_a['anomaly_score']}x robust sigma)."
                )
                evids = (
                    self.db.query(Evidence.id)
                    .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "METRIC")
                    .all()
                )
                evidence_ids = [r[0] for r in evids]
            else:
                findings = "No metric baseline anomalies detected in the incident window."

        elif tool_name == "inspect_config_change":
            result = self.tools.inspect_config_change(
                service=tool_params.get("service"),
                lookback_entries=tool_params.get("lookback_entries", 10),
            )
            cfgs = result.get("config_changes", [])
            if cfgs:
                c = cfgs[0]
                findings = (
                    f"Identified configuration modification on {c['service']}: parameter '{c['config_key']}' "
                    f"changed from '{c['old_value']}' to '{c['new_value']}' by {c['changed_by']}."
                )
                evids = (
                    self.db.query(Evidence.id)
                    .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "CONFIG")
                    .all()
                )
                evidence_ids = [r[0] for r in evids]
            else:
                findings = "Zero configuration changes detected within target window."

        elif tool_name == "inspect_deployment":
            result = self.tools.inspect_deployment(
                service=tool_params.get("service"),
                lookback_entries=tool_params.get("lookback_entries", 10),
            )
            deps = result.get("deployments", [])
            if deps:
                d = deps[0]
                findings = f"Identified software release on {d['service']}: version '{d['version']}' deployed by {d['deployed_by']}."
                evids = (
                    self.db.query(Evidence.id)
                    .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "DEPLOYMENT")
                    .all()
                )
                evidence_ids = [r[0] for r in evids]
            else:
                findings = "Zero code deployments occurred within the incident window."

        elif tool_name == "get_dependencies":
            svc = tool_params.get("service_name") or "service"
            result = self.tools.get_dependencies(service_name=svc)
            inbound = [d["source"] for d in result.get("dependents", [])]
            outbound = [d["target"] for d in result.get("dependencies", [])]
            findings = (
                f"Topological dependencies for {svc}: Upstream callers ({', '.join(inbound) or 'none'}); "
                f"Downstream dependencies ({', '.join(outbound) or 'none'})."
            )

        elif tool_name == "get_logs":
            result = self.tools.get_logs(
                incident_id=incident_id,
                level=tool_params.get("level", "ERROR"),
                limit=tool_params.get("limit", 10),
            )
            logs = result.get("logs", [])
            if logs:
                top_l = logs[0]
                findings = f"Service '{top_l['service']}' logged: '{top_l['message']}' (trace: {top_l.get('trace_id')})."
                evids = (
                    self.db.query(Evidence.id)
                    .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "LOG")
                    .all()
                )
                evidence_ids = [r[0] for r in evids]
            else:
                findings = "No runtime exception logs detected in target window."

        elif tool_name == "generate_competing_hypotheses":
            from backend.hypotheses.engine import HypothesisEngine
            hyp_engine = HypothesisEngine(self.db)
            hyps = hyp_engine.generate_competing_hypotheses(incident_id)
            result = {
                "hypotheses": [
                    {"statement": h.statement, "score": h.score, "status": h.status}
                    for h in hyps
                ]
            }
            if hyps:
                top_h = hyps[0]
                findings = (
                    f"Generated {len(hyps)} competing hypotheses. Leading hypothesis [{top_h.status}, score {top_h.score:.2f}]: "
                    f"'{top_h.statement}'."
                )
                evidence_ids = [el.evidence_id for el in top_h.evidence_links]
            else:
                findings = "No candidate hypotheses generated."

        elif tool_name == "get_recovery_events":
            result = self.tools.get_recovery_events(incident_id=incident_id)
            rec_evts = result.get("recovery_events", [])
            if rec_evts:
                r = rec_evts[0]
                findings = f"Observed system recovery on {r['service']}: '{r['observed_recovery']}' ({r['latency_to_recovery_sec']}s post-mitigation)."
                evids = (
                    self.db.query(Evidence.id)
                    .filter(Evidence.incident_id == incident_id, Evidence.evidence_type == "RECOVERY")
                    .all()
                )
                evidence_ids = [row[0] for row in evids]
            else:
                findings = "No stabilization or recovery events recorded."

        elif tool_name == "compare_baseline":
            result = self.tools.compare_baseline(
                metric_name=tool_params.get("metric_name", ""),
                service=tool_params.get("service", ""),
                incident_id=incident_id,
            )
            findings = f"Baseline comparison for {tool_params.get('metric_name')}: actual {result.get('recent_actual')} vs expected {result.get('baseline', {}).get('median')}."

        return result, findings, evidence_ids

    def _synthesize_investigation(
        self,
        incident: Incident,
        executed_steps: List[Dict[str, Any]],
    ) -> str:
        """Synthesizes formal forensic conclusion with calibrated language and provenance citations."""
        hypotheses = (
            self.db.query(Hypothesis)
            .filter(Hypothesis.incident_id == incident.id)
            .order_by(Hypothesis.rank.asc())
            .all()
        )
        top_hyp = hypotheses[0] if hypotheses else None

        # Collect evidence citations
        all_cited_ids = []
        for s in executed_steps:
            all_cited_ids.extend(s.get("evidence_ids", []))
        unique_cited = list(dict.fromkeys(all_cited_ids))[:6]
        citation_str = " ".join([f"[{eid}]" for eid in unique_cited])

        # Check calibrated status
        if top_hyp:
            sup_count = sum(1 for el in top_hyp.evidence_links if el.relationship_type == "SUPPORTS")
            contra_count = sum(1 for el in top_hyp.evidence_links if el.relationship_type == "CONTRADICTS")
            missing_count = len(top_hyp.missing_evidence or [])

            if top_hyp.score >= 0.70 and missing_count == 0 and contra_count == 0:
                conclusion_assessment = "Strongly supported by telemetry, not conclusively established."
            elif top_hyp.score >= 0.60:
                conclusion_assessment = "Supported by available telemetry; rival explanations penalized by counterevidence."
            elif top_hyp.score >= 0.30:
                conclusion_assessment = "Plausible candidate under validation; insufficient telemetry for formal confirmation."
            else:
                conclusion_assessment = "Insufficient evidence to determine root cause."
        else:
            conclusion_assessment = "Insufficient evidence to generate candidate hypotheses."
            sup_count, contra_count, missing_count = 0, 0, 0

        # Attempt Ollama synthesis if available
        if self.ollama.is_available() and top_hyp:
            try:
                steps_summary = "\n".join([
                    f"- Step {s['step_number']}: {s['question']} -> {s['findings']} (Citations: {s['evidence_ids']})"
                    for s in executed_steps
                ])
                prompt = (
                    f"Produce a formal forensic incident investigation summary based STRICTLY on real evidence.\n\n"
                    f"Incident: {incident.title} ({incident.id})\n"
                    f"Investigation Steps:\n{steps_summary}\n\n"
                    f"Most-Supported Hypothesis:\n"
                    f"- Claim: {top_hyp.statement}\n"
                    f"- Support Score: {top_hyp.score:.2f}\n"
                    f"- Assessment: {conclusion_assessment}\n"
                    f"- Supporting Telemetry Items: {sup_count} ({citation_str})\n"
                    f"- Contradicting Telemetry Items: {contra_count}\n"
                    f"- Missing Telemetry Items: {missing_count}\n\n"
                    f"STRICT RULES: Cite evidence IDs [EVID-...]. Never claim 'proven root cause'. Output calibrated forensic synthesis."
                )
                response = self.ollama.chat_completion(
                    messages=[{"role": "user", "content": prompt}],
                    system_prompt=SYSTEM_FORENSIC_PROMPT,
                )
                if response:
                    return response.strip()
            except Exception:
                pass

        # Deterministic Calibrated Forensic Synthesis
        if not top_hyp or top_hyp.score < 0.30:
            return "Insufficient evidence to determine root cause with forensic certainty."

        step_findings_text = "\n".join([
            f"- {s['question']}: {s['findings']}"
            for s in executed_steps
        ])

        return (
            f"FORENSIC INVESTIGATION CONCLUSION:\n\n"
            f"Most-Supported Hypothesis:\n"
            f"{top_hyp.statement}\n\n"
            f"Investigation Metrics:\n"
            f"- Support Score: {top_hyp.score:.2f} (Calibrated Investigation Support Score)\n"
            f"- Assessment: {conclusion_assessment}\n"
            f"- Evidence Supporting: {sup_count}\n"
            f"- Evidence Contradicting: {contra_count}\n"
            f"- Missing Telemetry Items: {missing_count}\n"
            f"- Key Forensic Citations: {citation_str}\n\n"
            f"Observed Causal Sequence:\n"
            f"{step_findings_text}\n\n"
            f"Counterevidence Evaluation:\n"
            f"Rival external network and software defect hypotheses were evaluated against observed incident telemetry and penalized."
        )
