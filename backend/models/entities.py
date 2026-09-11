from sqlalchemy import Column, String, Boolean, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.core.database import Base
from backend.models.base import generate_uuid, utc_now, TimestampMixin


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(128), unique=True, nullable=False, index=True)
    tier = Column(String(32), default="tier-1", nullable=False)
    repo_url = Column(String(256), nullable=True)
    oncall_team = Column(String(128), nullable=True)
    environment = Column(String(64), default="production", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)

    # Relationships
    outbound_dependencies = relationship(
        "ServiceDependency",
        foreign_keys="ServiceDependency.source_service_id",
        back_populates="source_service",
        cascade="all, delete-orphan",
    )
    inbound_dependencies = relationship(
        "ServiceDependency",
        foreign_keys="ServiceDependency.target_service_id",
        back_populates="target_service",
        cascade="all, delete-orphan",
    )


class ServiceDependency(Base, TimestampMixin):
    __tablename__ = "service_dependencies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_service_id = Column(String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=False, index=True)
    target_service_id = Column(String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=False, index=True)
    dependency_type = Column(String(32), default="RPC", nullable=False)  # RPC, DB, CACHE, QUEUE
    is_critical = Column(Boolean, default=True, nullable=False)
    avg_latency_ms = Column(Float, default=10.0, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)

    source_service = relationship("Service", foreign_keys=[source_service_id], back_populates="outbound_dependencies")
    target_service = relationship("Service", foreign_keys=[target_service_id], back_populates="inbound_dependencies")


class Deployment(Base, TimestampMixin):
    __tablename__ = "deployments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    service = Column(String(128), nullable=False, index=True)
    version = Column(String(64), nullable=False)
    commit_sha = Column(String(64), nullable=True, index=True)
    deployed_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    deployed_by = Column(String(128), default="automation", nullable=False)
    status = Column(String(32), default="SUCCESS", nullable=False)  # SUCCESS, FAILED, IN_PROGRESS
    changelog = Column(String(1024), nullable=True)
    environment = Column(String(64), default="production", nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)


class ConfigChange(Base, TimestampMixin):
    __tablename__ = "config_changes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    service = Column(String(128), nullable=False, index=True)
    config_key = Column(String(128), nullable=False, index=True)
    old_value = Column(String(512), nullable=True)
    new_value = Column(String(512), nullable=False)
    changed_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    changed_by = Column(String(128), default="operator", nullable=False)
    reason = Column(String(512), nullable=True)
    environment = Column(String(64), default="production", nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
