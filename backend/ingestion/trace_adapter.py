from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.ingestion.base import BaseIngestionAdapter, IngestionResult
from backend.models import Trace, Span, Evidence
from backend.models.base import generate_uuid
from backend.normalization.normalizer import normalize_event_payload, normalize_timestamp


class TraceIngestionAdapter(BaseIngestionAdapter):
    @property
    def source_type(self) -> str:
        return "TRACE"

    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "opentelemetry",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        trace_id = raw_payload.get("trace_id") or raw_payload.get("traceId")
        if not trace_id:
            raise ValueError("trace_id is required for trace ingestion")

        spans_data = raw_payload.get("spans") or []
        if not spans_data and "span_id" in raw_payload:
            spans_data = [raw_payload]

        # Calculate overall trace properties
        root_service = raw_payload.get("root_service") or "unknown-root"
        has_error = False
        total_duration = 0.0
        earliest_time = None
        status_code = 200

        created_spans = []
        for s in spans_data:
            s_time, _ = normalize_timestamp(s.get("start_time"))
            if earliest_time is None or s_time < earliest_time:
                earliest_time = s_time

            dur = float(s.get("duration_ms", 0.0))
            if dur > total_duration:
                total_duration = dur

            s_status = str(s.get("status", "OK")).upper()
            if s_status == "ERROR":
                has_error = True
                status_code = int(s.get("attributes", {}).get("http.status_code", 500))

            if not s.get("parent_span_id") and s.get("service"):
                root_service = s["service"]

            span = Span(
                id=generate_uuid(),
                trace_id=trace_id,
                span_id=str(s.get("span_id") or s.get("spanId")),
                parent_span_id=str(s["parent_span_id"]) if s.get("parent_span_id") else None,
                service=s.get("service", "unknown-service"),
                name=s.get("name", "operation"),
                start_time=s_time,
                duration_ms=dur,
                status=s_status,
                attributes_json=s.get("attributes", {}),
                events_json=s.get("events", []),
            )
            db.add(span)
            created_spans.append(span)

        # Upsert or create Trace header
        trace_record = db.query(Trace).filter(Trace.trace_id == trace_id).first()
        if not trace_record:
            trace_record = Trace(
                id=generate_uuid(),
                trace_id=trace_id,
                incident_id=incident_id,
                root_service=root_service,
                start_time=earliest_time or normalize_timestamp(None)[0],
                duration_ms=total_duration,
                status_code=status_code,
                has_error=has_error,
            )
            db.add(trace_record)
        else:
            trace_record.duration_ms = max(trace_record.duration_ms, total_duration)
            if has_error:
                trace_record.has_error = True
                trace_record.status_code = status_code

        norm_info = normalize_event_payload(
            raw_payload,
            source_type=self.source_type,
            source=source,
            environment=environment,
            service_hint=root_service,
        )

        event = self._create_event(incident_id, norm_info, source=source, is_simulated=is_simulated)
        db.add(event)

        # Generate Evidence if error trace or associated with incident
        evidence = None
        if incident_id and (has_error or total_duration > 500):
            evid_id = self._next_evidence_id(db, incident_id, prefix="EVID-TRACE")
            evidence = Evidence(
                id=evid_id,
                incident_id=incident_id,
                timestamp=norm_info["utc_time"],
                evidence_type="TRACE",
                source=source,
                entity=f"trace:{trace_id}",
                content={
                    "trace_id": trace_id,
                    "root_service": root_service,
                    "duration_ms": total_duration,
                    "has_error": has_error,
                    "status_code": status_code,
                    "span_count": len(created_spans),
                },
                confidence=1.0,
                provenance=norm_info["provenance"],
            )
            db.add(evidence)

        db.flush()
        return IngestionResult(event=event, evidence=evidence, additional_records=created_spans + [trace_record])
