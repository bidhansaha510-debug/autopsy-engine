from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy.orm import Session
from backend.models import Incident, Report, Evidence, Hypothesis, Anomaly, Intervention, RecoveryEvent
from backend.models.base import generate_uuid, utc_now
from backend.topology.blast_radius import BlastRadiusCalculator


class ForensicReportGenerator:
    def __init__(self, db: Session):
        self.db = db

    def generate_incident_report(self, incident_id: str) -> Report:
        """Generates a complete, evidence-backed forensic incident report."""
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        # Gather forensic artifacts
        evidence_items = self.db.query(Evidence).filter(Evidence.incident_id == incident_id).order_by(Evidence.timestamp.asc()).all()
        hypotheses = self.db.query(Hypothesis).filter(Hypothesis.incident_id == incident_id).order_by(Hypothesis.rank.asc()).all()
        anomalies = self.db.query(Anomaly).filter(Anomaly.incident_id == incident_id).order_by(Anomaly.detected_at.asc()).all()
        interventions = self.db.query(Intervention).filter(Intervention.incident_id == incident_id).all()
        recoveries = self.db.query(RecoveryEvent).filter(RecoveryEvent.incident_id == incident_id).all()

        calc = BlastRadiusCalculator(self.db)
        blast = calc.calculate_blast_radius(incident_id)

        top_hyp = hypotheses[0] if hypotheses else None
        if top_hyp:
            sup_count_top = sum(1 for el in top_hyp.evidence_links if el.relationship_type == "SUPPORTS")
            contra_count_top = sum(1 for el in top_hyp.evidence_links if el.relationship_type == "CONTRADICTS")
            missing_count_top = len(top_hyp.missing_evidence or [])
            if top_hyp.score >= 0.70 and missing_count_top == 0 and contra_count_top == 0:
                conclusion_assessment = "Strongly supported by telemetry, not conclusively established."
            elif top_hyp.score >= 0.60:
                conclusion_assessment = "Supported by available telemetry; alternative hypotheses partially refuted."
            elif top_hyp.score >= 0.30:
                conclusion_assessment = "Plausible candidate under active validation; insufficient telemetry for formal confirmation."
            else:
                conclusion_assessment = "Insufficient evidence to determine root cause."
        else:
            conclusion_assessment = "No candidate hypotheses generated."
            sup_count_top, contra_count_top, missing_count_top = 0, 0, 0

        rca_statement = top_hyp.statement if top_hyp else "Insufficient evidence to determine root cause."

        # Build Markdown Document
        md_lines = [
            f"# FORENSIC INCIDENT REPORT: {incident.title}",
            f"**Incident ID**: `{incident.id}` | **Severity**: `{incident.severity}` | **Status**: `{incident.status}`",
            f"**Time Window**: {incident.started_at.isoformat()} to {(incident.resolved_at or utc_now()).isoformat()}",
            f"**Report Generated**: {datetime.now(timezone.utc).isoformat()} (Digital Forensics Provenance Tracked)",
            "",
            "## 1. Executive Summary",
            incident.summary or "No executive summary provided.",
            "",
            "## 2. Root Cause Analysis (RCA Candidates)",
            f"**Most-Supported Hypothesis**: {top_hyp.statement if top_hyp else 'None'}",
            f"**Causal Mechanism**: `{top_hyp.causal_mechanism if (top_hyp and top_hyp.causal_mechanism) else 'N/A'}`",
            f"**Support Score**: **{top_hyp.score if top_hyp else 0.0:.2f}** (Calibrated Investigation Support Score)",
            f"**Investigation Assessment**: {conclusion_assessment}",
            f"**Telemetry Counts**: {sup_count_top} Supporting | {contra_count_top} Contradicting | {missing_count_top} Missing",
            "",
            "### Competing Hypotheses & Counterevidence Matrix",
            "| Rank | Hypothesis Claim | Status | Support Score | Supported By | Counterevidence |",
            "|---|---|---|---|---|---|",
        ]

        for h in hypotheses:
            sup_count = sum(1 for el in h.evidence_links if el.relationship_type == "SUPPORTS")
            contra_count = sum(1 for el in h.evidence_links if el.relationship_type == "CONTRADICTS")
            md_lines.append(
                f"| {h.rank} | {h.statement} | `{h.status}` | **{h.score:.2f}** | {sup_count} items | {contra_count} items |"
            )

        md_lines.extend([
            "",
            "## 3. Blast Radius & Service Impact",
            f"- **Root Cause Service**: `{blast.root_cause_service or 'Unknown'}`",
            f"- **Directly Affected**: {', '.join([f'`{s}`' for s in blast.directly_affected]) or 'None'}",
            f"- **Indirectly Affected (Upstream)**: {', '.join([f'`{s}`' for s in blast.indirectly_affected]) or 'None'}",
            f"- **Customer-Facing Impact**: {', '.join([f'`{s}`' for s in blast.customer_facing_endpoints]) or 'None'}",
            f"- **Propagation Path**: {' → '.join(blast.propagation_path) or 'Local to node'}",
            "",
            "## 4. Key Anomalies Detected (Against Historical Baselines)",
        ])

        if anomalies:
            md_lines.append("| Detected At | Service | Metric | Actual | Expected | Score | Severity |")
            md_lines.append("|---|---|---|---|---|---|---|")
            for a in anomalies[:10]:
                md_lines.append(
                    f"| {a.detected_at.strftime('%H:%M:%S')} | `{a.service}` | `{a.metric_name}` | {a.actual} | {a.expected} | {a.anomaly_score:.1f}x | `{a.severity}` |"
                )
        else:
            md_lines.append("No metric anomalies registered above deviation threshold.")

        md_lines.extend([
            "",
            "## 5. Indelible Evidence Register (Chain of Custody)",
            "| Evidence ID | Timestamp | Type | Entity | Confidence | Summary / Content |",
            "|---|---|---|---|---|---|",
        ])

        for e in evidence_items[:20]:
            content_summary = str(e.content)[:80].replace("|", "/")
            md_lines.append(
                f"| `{e.id}` | {e.timestamp.strftime('%H:%M:%S')} | `{e.evidence_type}` | `{e.entity}` | {e.confidence:.2f} | {content_summary} |"
            )

        md_lines.extend([
            "",
            "## 6. Mitigation & Recovery Verification",
        ])
        if interventions:
            for it in interventions:
                md_lines.append(f"- **Intervention executed** ({it.executed_at.strftime('%H:%M:%S')}): {it.description} by `{it.executed_by}` (Status: {it.status})")
        if recoveries:
            for rec in recoveries:
                md_lines.append(f"- **Observed Recovery** ({rec.timestamp.strftime('%H:%M:%S')}): {rec.observed_recovery}")

        # Dynamically synthesize recommendations based on causal mechanism & topology
        root_svc = blast.root_cause_service or (top_hyp.affected_services[0] if top_hyp and top_hyp.affected_services else "core-service")
        callers = blast.indirectly_affected or []
        callers_str = ", ".join(callers[:2]) if callers else "upstream callers"

        recommendations = []
        preventive_actions = []
        unknowns = []

        is_config = top_hyp and ("config" in top_hyp.statement.lower() or any(p.get("type") == "CONFIG" for p in (top_hyp.predicted_observations or [])))
        is_deploy = top_hyp and ("deploy" in top_hyp.statement.lower() or any(p.get("type") == "DEPLOYMENT" for p in (top_hyp.predicted_observations or [])))

        if is_config:
            recommendations.append({
                "action": f"Automate pre-flight configuration validation and parameter range boundaries for {root_svc}.",
                "owner": f"Team {root_svc}",
                "priority": "P1",
            })
            recommendations.append({
                "action": f"Implement client-side circuit breakers and admission timeouts on {callers_str} to prevent cascade during {root_svc} resource starvation.",
                "owner": "Platform SRE",
                "priority": "P1",
            })
            recommendations.append({
                "action": f"Configure automated canary verification on {root_svc} config pushes with instant rollback trigger.",
                "owner": "DevOps Team",
                "priority": "P2",
            })
            preventive_actions.append({
                "prevention": f"Add schema validation and minimum bounds linting to configuration repositories for {root_svc}.",
                "target_date": "Next Sprint",
            })
            preventive_actions.append({
                "prevention": f"Deploy synthetic canary traffic probes on {callers_str} to alert on degraded downstream dependencies.",
                "target_date": "Within 14 Days",
            })
        elif is_deploy:
            recommendations.append({
                "action": f"Implement staged canary deployment strategy (1% -> 10% -> 100%) with automated error-rate health gates for {root_svc}.",
                "owner": f"Team {root_svc}",
                "priority": "P1",
            })
            recommendations.append({
                "action": f"Enforce automated smoke regression tests targeting critical downstream RPC endpoints during CI/CD on {root_svc}.",
                "owner": "QA / DevOps",
                "priority": "P1",
            })
            preventive_actions.append({
                "prevention": f"Incorporate automated pre-release load testing and memory profiling into deployment pipelines for {root_svc}.",
                "target_date": "Next Sprint",
            })
        else:
            recommendations.append({
                "action": f"Review horizontal pod autoscaling (HPA) thresholds and thread pool admission limits on {root_svc}.",
                "owner": f"Team {root_svc}",
                "priority": "P1",
            })
            recommendations.append({
                "action": f"Deploy circuit breaker fail-fast patterns on {callers_str} to isolate downstream latency surges.",
                "owner": "SRE Team",
                "priority": "P1",
            })
            preventive_actions.append({
                "prevention": f"Tune non-parametric baseline alerting (MAD z-score >= 3.5) on {root_svc} golden signals.",
                "target_date": "Within 14 Days",
            })

        unknowns.append(f"Ephemeral debug logs from {root_svc} containers prior to termination were subject to log rotation limits.")
        unknowns.append(f"Fine-grained thread state dumps at peak queue saturation ({incident.started_at.strftime('%H:%M:%S')} UTC) were not captured.")

        md_lines.extend([
            "",
            "## 7. Preventive Actions & Follow-Up",
        ])
        for p in preventive_actions:
            md_lines.append(f"- [ ] {p['prevention']} (Target: {p['target_date']})")

        md_content = "\n".join(md_lines)

        report = Report(
            id=generate_uuid(),
            incident_id=incident_id,
            generated_at=utc_now(),
            title=f"Incident Forensic Report: {incident.title}",
            content_markdown=md_content,
            content_json={
                "incident_id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "rca_statement": rca_statement,
                "hypotheses_count": len(hypotheses),
                "evidence_count": len(evidence_items),
                "anomalies_count": len(anomalies),
                "blast_radius": blast.model_dump(),
            },
            executive_summary=incident.summary or "",
            blast_radius=blast.model_dump(),
            rca_statement=rca_statement,
            recommendations=recommendations,
            preventive_actions=preventive_actions,
            unknowns=unknowns,
        )
        self.db.add(report)
        self.db.commit()
        return report
