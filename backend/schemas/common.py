from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class ProvenanceSchema(BaseModel):
    source: str = Field(..., description="Origin of telemetry e.g. /var/log/api.log, prometheus-k8s")
    source_type: str = Field(..., description="LOG, METRIC, TRACE, DEPLOY, CONFIG, ALERT, K8S")
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    raw_fingerprint: Optional[str] = Field(None, description="SHA256 or hash of raw payload")
    collector: Optional[str] = Field("autopsy-ingest-agent", description="Collector daemon name")
    extra: Dict[str, Any] = Field(default_factory=dict)


class TimeRangeFilter(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    service: Optional[str] = None
    severity: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
