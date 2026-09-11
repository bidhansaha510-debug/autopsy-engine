from sqlalchemy import Column, String, Boolean, Float, Integer, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.core.database import Base
from backend.models.base import generate_uuid, utc_now, TimestampMixin


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(256), nullable=False)
    severity = Column(String(16), default="SEV1", nullable=False)  # SEV1, SEV2, SEV3, SEV4
    status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, MITIGATED, RESOLVED
    started_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    detected_at = Column(DateTime, nullable=True, index=True)
    mitigated_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    summary = Column(Text, nullable=True)
    blast_radius_summary = Column(JSON, default=dict, nullable=False)
    is_simulated = Column(Boolean, default=False, nullable=False, index=True)

    # Relationships
    events = relationship("Event", back_populates="incident", cascade="all, delete-orphan")
    evidence_items = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    hypotheses = relationship("Hypothesis", back_populates="incident", cascade="all, delete-orphan")
    anomalies = relationship("Anomaly", back_populates="incident", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="incident", cascade="all, delete-orphan")


class Event(Base, TimestampMixin):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=utc_now, index=True)
    ingested_at = Column(DateTime, nullable=False, default=utc_now)
    source = Column(String(128), nullable=False, index=True)
    source_type = Column(String(64), nullable=False)  # LOG, METRIC, TRACE, DEPLOY, CONFIG, ALERT, K8S
    environment = Column(String(64), default="production", nullable=False)
    service = Column(String(128), nullable=False, index=True)
    host = Column(String(128), nullable=True)
    raw_data = Column(JSON, nullable=False)
    normalized_data = Column(JSON, nullable=False)
    provenance = Column(JSON, nullable=False)
    is_simulated = Column(Boolean, default=False, nullable=False)

    incident = relationship("Incident", back_populates="events")


class EventRelationship(Base, TimestampMixin):
    __tablename__ = "event_relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    source_event_id = Column(String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)
    target_event_id = Column(String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(32), nullable=False)  # PRECEDED, FOLLOWED, AFFECTED, DEPENDS_ON, CORRELATED_WITH, RECOVERED_AFTER, SUPPORTS, CONTRADICTS
    score = Column(Float, default=1.0, nullable=False)
    reason = Column(String(512), nullable=False)
    provenance = Column(JSON, default=dict, nullable=False)

    source_event = relationship("Event", foreign_keys=[source_event_id])
    target_event = relationship("Event", foreign_keys=[target_event_id])


class LogEntry(Base, TimestampMixin):
    __tablename__ = "log_entries"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    event_id = Column(String(36), ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=utc_now, index=True)
    level = Column(String(16), default="INFO", nullable=False, index=True)  # DEBUG, INFO, WARN, ERROR, FATAL
    service = Column(String(128), nullable=False, index=True)
    host = Column(String(128), nullable=True)
    message = Column(Text, nullable=False)
    request_id = Column(String(128), nullable=True, index=True)
    trace_id = Column(String(128), nullable=True, index=True)
    span_id = Column(String(128), nullable=True)
    attributes_json = Column(JSON, default=dict, nullable=False)


class Metric(Base, TimestampMixin):
    __tablename__ = "metrics"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(128), nullable=False, index=True)
    service = Column(String(128), nullable=False, index=True)
    unit = Column(String(32), default="count", nullable=False)
    metric_type = Column(String(32), default="GAUGE", nullable=False)  # COUNTER, GAUGE, HISTOGRAM
    tags_json = Column(JSON, default=dict, nullable=False)


class MetricSample(Base):
    __tablename__ = "metric_samples"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    metric_id = Column(String(36), ForeignKey("metrics.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=utc_now, index=True)
    value = Column(Float, nullable=False)
    labels_json = Column(JSON, default=dict, nullable=False)

    metric = relationship("Metric")


class Trace(Base, TimestampMixin):
    __tablename__ = "traces"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    trace_id = Column(String(128), unique=True, nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    root_service = Column(String(128), nullable=False, index=True)
    start_time = Column(DateTime, nullable=False, default=utc_now, index=True)
    duration_ms = Column(Float, nullable=False)
    status_code = Column(Integer, default=200, nullable=False)
    has_error = Column(Boolean, default=False, nullable=False, index=True)


class Span(Base, TimestampMixin):
    __tablename__ = "spans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    trace_id = Column(String(128), nullable=False, index=True)
    span_id = Column(String(128), nullable=False, index=True)
    parent_span_id = Column(String(128), nullable=True, index=True)
    service = Column(String(128), nullable=False, index=True)
    name = Column(String(256), nullable=False)
    start_time = Column(DateTime, nullable=False, default=utc_now, index=True)
    duration_ms = Column(Float, nullable=False)
    status = Column(String(16), default="OK", nullable=False)  # OK, ERROR
    attributes_json = Column(JSON, default=dict, nullable=False)
    events_json = Column(JSON, default=list, nullable=False)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String(256), nullable=False, index=True)
    severity = Column(String(32), default="CRITICAL", nullable=False)  # CRITICAL, WARNING, INFO
    service = Column(String(128), nullable=False, index=True)
    triggered_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    resolved_at = Column(DateTime, nullable=True)
    query = Column(String(512), nullable=True)
    threshold = Column(String(128), nullable=True)
    condition = Column(String(256), nullable=True)
