import json
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.ingestion.base import BaseIngestionAdapter, IngestionResult
from backend.models import LogEntry, Evidence
from backend.models.base import generate_uuid
from backend.normalization.normalizer import normalize_event_payload
from backend.core.security import sanitize_text


class LogIngestionAdapter(BaseIngestionAdapter):
    @property
    def source_type(self) -> str:
        return "LOG"

    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "app-log-stream",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        # Support raw text inside payload or structured dict
        msg = str(raw_payload.get("message") or raw_payload.get("msg") or raw_payload.get("log") or "")
        level = str(raw_payload.get("level") or raw_payload.get("severity") or "INFO").upper()

        service = raw_payload.get("service") or raw_payload.get("app") or "unknown-service"
        host = raw_payload.get("host") or raw_payload.get("hostname")

        req_id = raw_payload.get("request_id") or raw_payload.get("req_id")
        trace_id = raw_payload.get("trace_id") or raw_payload.get("traceId")
        span_id = raw_payload.get("span_id") or raw_payload.get("spanId")

        # Try to parse JSON from message string if message itself is JSON
        attributes = raw_payload.get("attributes") or {}
        if not attributes and msg.strip().startswith("{") and msg.strip().endswith("}"):
            try:
                parsed = json.loads(msg)
                attributes.update(parsed)
                if not req_id:
                    req_id = parsed.get("request_id") or parsed.get("req_id")
                if not trace_id:
                    trace_id = parsed.get("trace_id")
            except Exception:
                pass

        norm_info = normalize_event_payload(
            raw_payload,
            source_type=self.source_type,
            source=source,
            environment=environment,
            service_hint=service,
            host_hint=host,
        )

        event = self._create_event(incident_id, norm_info, source=source, is_simulated=is_simulated)
        db.add(event)

        log_entry = LogEntry(
            id=generate_uuid(),
            incident_id=incident_id,
            event_id=event.id,
            timestamp=norm_info["utc_time"],
            level=level,
            service=norm_info["service"],
            host=norm_info["host"],
            message=sanitize_text(msg),
            request_id=str(req_id) if req_id else None,
            trace_id=str(trace_id) if trace_id else None,
            span_id=str(span_id) if span_id else None,
            attributes_json=attributes,
        )
        db.add(log_entry)

        # Generate referenceable Evidence item if attached to an incident and WARN/ERROR/FATAL
        evidence = None
        if incident_id and level in ("WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"):
            evid_id = self._next_evidence_id(db, incident_id, prefix="EVID-LOG")
            evidence = Evidence(
                id=evid_id,
                incident_id=incident_id,
                timestamp=norm_info["utc_time"],
                evidence_type="LOG",
                source=source,
                entity=norm_info["service"],
                content={
                    "level": level,
                    "message": sanitize_text(msg),
                    "request_id": req_id,
                    "trace_id": trace_id,
                    "host": norm_info["host"],
                },
                confidence=1.0,
                provenance=norm_info["provenance"],
            )
            db.add(evidence)

        db.flush()
        return IngestionResult(event=event, evidence=evidence, additional_records=[log_entry])
