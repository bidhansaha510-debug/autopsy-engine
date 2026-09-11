from sqlalchemy import Column, String, Float, Integer, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.core.database import Base
from backend.models.base import generate_uuid, utc_now, TimestampMixin


class Intervention(Base, TimestampMixin):
    __tablename__ = "interventions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(64), nullable=False)  # ROLLBACK, SCALE_UP, POOL_EXPANSION, RESTART
    description = Column(String(512), nullable=False)
    executed_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    executed_by = Column(String(128), default="operator", nullable=False)
    status = Column(String(32), default="COMPLETED", nullable=False)
    target_service = Column(String(128), nullable=False, index=True)
    parameters_json = Column(JSON, default=dict, nullable=False)


class RecoveryEvent(Base, TimestampMixin):
    __tablename__ = "recovery_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=utc_now, index=True)
    service = Column(String(128), nullable=False, index=True)
    metric_id = Column(String(36), nullable=True)
    observed_recovery = Column(String(256), nullable=False)
    latency_to_recovery_sec = Column(Float, default=0.0, nullable=False)
    verified_by_evidence_id = Column(String(64), nullable=True)


class Investigation(Base, TimestampMixin):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default="IN_PROGRESS", nullable=False)  # IN_PROGRESS, COMPLETED, INSUFFICIENT_EVIDENCE
    started_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    completed_at = Column(DateTime, nullable=True)
    trigger = Column(String(128), default="AUTOMATIC", nullable=False)
    current_focus = Column(String(256), nullable=True)

    steps = relationship("InvestigationStep", back_populates="investigation", cascade="all, delete-orphan")


class InvestigationStep(Base, TimestampMixin):
    __tablename__ = "investigation_steps"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    step_number = Column(Integer, nullable=False)
    question = Column(String(512), nullable=False)
    tool_called = Column(String(64), nullable=False)
    tool_parameters_json = Column(JSON, default=dict, nullable=False)
    tool_result_json = Column(JSON, default=dict, nullable=False)
    findings = Column(Text, nullable=False)
    evidence_generated_ids = Column(JSON, default=list, nullable=False)

    investigation = relationship("Investigation", back_populates="steps")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    generated_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    title = Column(String(256), nullable=False)
    content_markdown = Column(Text, nullable=False)
    content_json = Column(JSON, default=dict, nullable=False)
    executive_summary = Column(Text, nullable=False)
    blast_radius = Column(JSON, default=dict, nullable=False)
    rca_statement = Column(Text, nullable=False)
    recommendations = Column(JSON, default=list, nullable=False)
    preventive_actions = Column(JSON, default=list, nullable=False)
    unknowns = Column(JSON, default=list, nullable=False)

    incident = relationship("Incident", back_populates="reports")
