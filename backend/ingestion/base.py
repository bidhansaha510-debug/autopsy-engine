from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import Event, Evidence
from backend.models.base import generate_uuid, utc_now
from backend.normalization.normalizer import normalize_event_payload


class IngestionResult:
    def __init__(
        self,
        event: Event,
        evidence: Optional[Evidence] = None,
        additional_records: Optional[List[Any]] = None,
    ):
        self.event = event
        self.evidence = evidence
        self.additional_records = additional_records or []


class BaseIngestionAdapter(ABC):
    @property
    @abstractmethod
    def source_type(self) -> str:
        """E.g. LOG, METRIC, TRACE, DEPLOY, CONFIG, ALERT, K8S"""
        pass

    @abstractmethod
    def process(
        self,
        db: Session,
        raw_payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        source: str = "adapter",
        environment: str = "production",
        is_simulated: bool = False,
    ) -> IngestionResult:
        """Parses payload, creates Event, creates domain record, and generates Evidence item."""
        pass

    def _create_event(
        self,
        incident_id: Optional[str],
        normalized_info: Dict[str, Any],
        source: str,
        is_simulated: bool = False,
    ) -> Event:
        return Event(
            id=generate_uuid(),
            incident_id=incident_id,
            timestamp=normalized_info["utc_time"],
            ingested_at=utc_now(),
            source=source,
            source_type=self.source_type,
            environment=normalized_info["normalized"]["environment"],
            service=normalized_info["service"],
            host=normalized_info["host"],
            raw_data=normalized_info["raw"],
            normalized_data=normalized_info["normalized"],
            provenance=normalized_info["provenance"],
            is_simulated=is_simulated,
        )

    def _next_evidence_id(self, db: Session, incident_id: str, prefix: str = "EVID") -> str:
        """Generates monotonically increasing and collision-free readable evidence ID."""
        import uuid
        count = db.query(Evidence).filter(Evidence.incident_id == incident_id).count()
        uid = uuid.uuid4().hex[:6].upper()
        return f"{prefix}-{count + 1:04d}-{uid}"
