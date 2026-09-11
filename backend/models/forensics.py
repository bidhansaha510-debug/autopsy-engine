from sqlalchemy import Column, String, Float, Integer, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship as orm_relationship
from backend.core.database import Base
from backend.models.base import generate_uuid, utc_now, TimestampMixin


class Anomaly(Base, TimestampMixin):
    __tablename__ = "anomalies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    metric_id = Column(String(36), ForeignKey("metrics.id", ondelete="SET NULL"), nullable=True, index=True)
    metric_name = Column(String(128), nullable=False, index=True)
    service = Column(String(128), nullable=False, index=True)
    detected_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    actual = Column(Float, nullable=False)
    expected = Column(Float, nullable=False)
    deviation = Column(Float, nullable=False)
    severity = Column(String(16), default="HIGH", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    anomaly_score = Column(Float, default=1.0, nullable=False)
    baseline_window = Column(String(64), default="1h_pre_incident", nullable=False)

    incident = orm_relationship("Incident", back_populates="anomalies")


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"

    # Human-readable referenceable ID e.g. EVID-101
    id = Column(String(64), primary_key=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=utc_now, index=True)
    evidence_type = Column(String(32), nullable=False, index=True)
    # LOG, METRIC, TRACE, DEPLOYMENT, CONFIG, ALERT, KUBERNETES_EVENT, GIT_CHANGE, RECOVERY, QUERY_RESULT, OBSERVATION
    source = Column(String(128), nullable=False)
    entity = Column(String(128), nullable=False, index=True)
    entity_id = Column(String(64), nullable=True, index=True)
    entity_type = Column(String(32), nullable=True, index=True)  # SERVICE, METRIC, TRACE, SPAN, DEPLOYMENT, CONFIG_CHANGE
    content = Column(JSON, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    provenance = Column(JSON, default=dict, nullable=False)

    incident = orm_relationship("Incident", back_populates="evidence_items")
    hypothesis_links = orm_relationship("HypothesisEvidence", back_populates="evidence", cascade="all, delete-orphan")


class Hypothesis(Base, TimestampMixin):
    __tablename__ = "hypotheses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    statement = Column(Text, nullable=False)
    claim = Column(Text, nullable=True)
    causal_mechanism = Column(Text, nullable=True)
    score = Column(Float, default=0.0, nullable=False)  # Support score 0.00 - 1.00
    status = Column(String(32), default="CANDIDATE", nullable=False)  # CANDIDATE, VALIDATING, SUPPORTED, STRONGLY_SUPPORTED, REFUTED
    affected_services = Column(JSON, default=list, nullable=False)
    expected_observations = Column(JSON, default=list, nullable=False)
    predicted_observations = Column(JSON, default=list, nullable=False)
    required_evidence = Column(JSON, default=list, nullable=False)
    supporting_rules = Column(JSON, default=list, nullable=False)
    contradiction_rules = Column(JSON, default=list, nullable=False)
    actual_observations = Column(JSON, default=list, nullable=False)
    missing_evidence = Column(JSON, default=list, nullable=False)
    rank = Column(Integer, default=1, nullable=False)

    incident = orm_relationship("Incident", back_populates="hypotheses")
    evidence_links = orm_relationship("HypothesisEvidence", back_populates="hypothesis", cascade="all, delete-orphan")


class HypothesisEvidence(Base, TimestampMixin):
    __tablename__ = "hypothesis_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    hypothesis_id = Column(String(36), ForeignKey("hypotheses.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(16), nullable=False)  # SUPPORTS, CONTRADICTS, NEUTRAL
    weight = Column(Float, default=1.0, nullable=False)
    explanation = Column(String(512), nullable=False)

    hypothesis = orm_relationship("Hypothesis", back_populates="evidence_links")
    evidence = orm_relationship("Evidence", back_populates="hypothesis_links")
