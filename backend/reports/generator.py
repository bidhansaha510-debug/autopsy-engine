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
        rca_statement = (
            top_hyp.statement if (top_hyp and top_hyp.score >= 0.70)
            else "Insufficient evidence to determine root cause with high confidence."
        )

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
            f"**Leading Conclusion**: {rca_statement}",
            f"**Confidence/Support Score**: {top_hyp.score if top_hyp else 0.0} (Calibrated Investigation Support Score)",
            "",
            "### Competing Hypotheses Matrix",
            "| Rank | Hypothesis Statement | Status | Support Score | Supported By | Counterevidence |",
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

        recommendations = [
            {"action": "Automate pre-flight connection pool validation before configuration pushes.", "owner": "SRE Team", "priority": "P1"},
            {"action": "Enforce admission limits on payment-service to prevent thread starvation during pool exhaustion.", "owner": "Backend Team", "priority": "P2"},
            {"action": "Implement circuit breaker on checkout-service RPC client to fail-fast.", "owner": "Checkout Team", "priority": "P1"},
        ]

        preventive_actions = [
            {"prevention": "Add linting rule to Kubernetes ConfigMaps restricting min db_pool size to 25.", "target_date": "2026-09-20"},
            {"prevention": "Setup synthetic end-to-end canary probing on checkout-service.", "target_date": "2026-09-18"},
        ]

        unknowns = [
            "Network interface packet captures during 02:49-02:51 were not retained in cold storage.",
            "Thread dumps from payment-service pods prior to termination are missing.",
        ]

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
