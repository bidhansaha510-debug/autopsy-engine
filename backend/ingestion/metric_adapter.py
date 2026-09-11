from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.ingestion.base import BaseIngestionAdapter, IngestionResult
from backend.models import Metric, MetricSample, Evidence
from backend.models.base import generate_uuid, utc_now
from backend.normalization.normalizer import normalize_event_payload, normalize_timestamp


class MetricIngestionAdapter(BaseIngestionAdapter):
    @property
    def source_type(self) -> str:
        return "METRIC"

    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "prometheus",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        metric_name = raw_payload.get("name") or raw_payload.get("metric") or "system_metric"
        service = raw_payload.get("service") or "system"
        unit = raw_payload.get("unit") or "count"
        metric_type = raw_payload.get("type") or "GAUGE"
        tags = raw_payload.get("tags") or {}

        # Look up or create Metric metadata definition
        metric = (
            db.query(Metric)
            .filter(Metric.name == metric_name, Metric.service == service)
            .first()
        )
        if not metric:
            metric = Metric(
                id=generate_uuid(),
                name=metric_name,
                service=service,
                unit=unit,
                metric_type=metric_type,
                tags_json=tags,
            )
            db.add(metric)
            db.flush()

        # Ingest samples
        samples_data = raw_payload.get("samples") or []
        if not samples_data and "value" in raw_payload:
            samples_data = [{
                "timestamp": raw_payload.get("timestamp"),
                "value": float(raw_payload["value"]),
                "labels": raw_payload.get("labels", {}),
            }]

        created_samples = []
        last_val = 0.0
        for item in samples_data:
            ts, _ = normalize_timestamp(item.get("timestamp"))
            val = float(item.get("value", 0.0))
            last_val = val
            sample = MetricSample(
                id=generate_uuid(),
                metric_id=metric.id,
                incident_id=incident_id,
                timestamp=ts,
                value=val,
                labels_json=item.get("labels", {}),
            )
            db.add(sample)
            created_samples.append(sample)

        norm_info = normalize_event_payload(
            raw_payload,
            source_type=self.source_type,
            source=source,
            environment=environment,
            service_hint=service,
        )

        event = self._create_event(incident_id, norm_info, source=source, is_simulated=is_simulated)
        db.add(event)

        # Generate Evidence if metric is associated with an active incident
        evidence = None
        if incident_id:
            evid_id = self._next_evidence_id(db, incident_id, prefix="EVID-METRIC")
            evidence = Evidence(
                id=evid_id,
                incident_id=incident_id,
                timestamp=norm_info["utc_time"],
                evidence_type="METRIC",
                source=source,
                entity=f"{service}:{metric_name}",
                content={
                    "metric": metric_name,
                    "service": service,
                    "unit": unit,
                    "latest_value": last_val,
                    "samples_count": len(created_samples),
                },
                confidence=1.0,
                provenance=norm_info["provenance"],
            )
            db.add(evidence)

        db.flush()
        return IngestionResult(event=event, evidence=evidence, additional_records=created_samples)
