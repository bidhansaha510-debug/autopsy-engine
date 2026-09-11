from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.ingestion.base import BaseIngestionAdapter, IngestionResult
from backend.models import Alert, Evidence
from backend.models.base import generate_uuid
from backend.normalization.normalizer import normalize_event_payload, normalize_timestamp
from backend.core.security import sanitize_text


class AlertIngestionAdapter(BaseIngestionAdapter):
    @property
    def source_type(self) -> str:
        return "ALERT"

    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "alertmanager",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        name = raw_payload.get("name") or raw_payload.get("alertname") or "SystemAlert"
        service = raw_payload.get("service") or raw_payload.get("app") or "system"
        severity = str(raw_payload.get("severity") or "CRITICAL").upper()
        query = raw_payload.get("query") or raw_payload.get("expr")
        threshold = str(raw_payload.get("threshold", ""))
        condition = str(raw_payload.get("condition", ""))

        ts, _ = normalize_timestamp(raw_payload.get("triggered_at") or raw_payload.get("startsAt"))
        resolved_ts = None
        if raw_payload.get("resolved_at") or raw_payload.get("endsAt"):
            resolved_ts, _ = normalize_timestamp(raw_payload.get("resolved_at") or raw_payload.get("endsAt"))

        alert_rec = Alert(
            id=generate_uuid(),
            incident_id=incident_id,
            name=sanitize_text(name),
            severity=severity,
            service=sanitize_text(service),
            triggered_at=ts,
            resolved_at=resolved_ts,
            query=sanitize_text(query),
            threshold=threshold,
            condition=condition,
        )
        db.add(alert_rec)

        norm_info = normalize_event_payload(
            raw_payload,
            source_type=self.source_type,
            source=source,
            environment=environment,
            service_hint=service,
        )

        event = self._create_event(incident_id, norm_info, source=source, is_simulated=is_simulated)
        db.add(event)

        evidence = None
        if incident_id:
            evid_id = self._next_evidence_id(db, incident_id, prefix="EVID-ALT")
            evidence = Evidence(
                id=evid_id,
                incident_id=incident_id,
                timestamp=ts,
                evidence_type="ALERT",
                source=source,
                entity=f"{service}:{name}",
                content={
                    "alert": name,
                    "service": service,
                    "severity": severity,
                    "condition": condition,
                    "threshold": threshold,
                },
                confidence=1.0,
                provenance=norm_info["provenance"],
            )
            db.add(evidence)

        db.flush()
        return IngestionResult(event=event, evidence=evidence, additional_records=[alert_rec])


class KubernetesEventAdapter(BaseIngestionAdapter):
    @property
    def source_type(self) -> str:
        return "KUBERNETES_EVENT"

    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "kube-apiserver",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        reason = raw_payload.get("reason") or "GenericK8sEvent"
        service = raw_payload.get("service") or raw_payload.get("namespace") or "kube-system"
        pod = raw_payload.get("pod") or raw_payload.get("involved_object") or "pod"
        message = raw_payload.get("message") or ""

        ts, _ = normalize_timestamp(raw_payload.get("timestamp") or raw_payload.get("lastTimestamp"))

        norm_info = normalize_event_payload(
            raw_payload,
            source_type=self.source_type,
            source=source,
            environment=environment,
            service_hint=service,
        )

        event = self._create_event(incident_id, norm_info, source=source, is_simulated=is_simulated)
        db.add(event)

        evidence = None
        if incident_id:
            evid_id = self._next_evidence_id(db, incident_id, prefix="EVID-K8S")
            evidence = Evidence(
                id=evid_id,
                incident_id=incident_id,
                timestamp=ts,
                evidence_type="KUBERNETES_EVENT",
                source=source,
                entity=f"{service}/{pod}",
                content={
                    "reason": reason,
                    "message": sanitize_text(message),
                    "pod": pod,
                    "service": service,
                },
                confidence=1.0,
                provenance=norm_info["provenance"],
            )
            db.add(evidence)

        db.flush()
        return IngestionResult(event=event, evidence=evidence, additional_records=[])
