from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import LogEntry, MetricSample, Metric, Trace, Span, Event, EventRelationship
from backend.schemas.telemetry import (
    LogEntryResponse,
    MetricSampleResponse,
    SpanResponse,
    TraceDetailResponse,
    EventResponse,
)
from backend.tracing.analyzer import TraceAnalyzer

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.get("/logs", response_model=List[LogEntryResponse])
def get_logs(
    incident_id: Optional[str] = None,
    service: Optional[str] = None,
    level: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(LogEntry)
    if incident_id:
        q = q.filter(LogEntry.incident_id == incident_id)
    if service:
        q = q.filter(LogEntry.service.ilike(f"%{service}%"))
    if level:
        q = q.filter(LogEntry.level == level.upper())
    if query:
        q = q.filter(LogEntry.message.ilike(f"%{query}%"))
    logs = q.order_by(LogEntry.timestamp.desc()).limit(limit).all()
    return logs


@router.get("/metrics")
def get_metrics(
    incident_id: Optional[str] = None,
    service: Optional[str] = None,
    metric_name: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(MetricSample).join(Metric, MetricSample.metric_id == Metric.id)
    if incident_id:
        q = q.filter(MetricSample.incident_id == incident_id)
    if service:
        q = q.filter(Metric.service == service)
    if metric_name:
        q = q.filter(Metric.name == metric_name)
    samples = q.order_by(MetricSample.timestamp.asc()).limit(200).all()
    return [
        {
            "id": s.id,
            "metric_id": s.metric_id,
            "timestamp": s.timestamp.isoformat(),
            "value": s.value,
            "service": s.metric.service if s.metric else "",
            "metric_name": s.metric.name if s.metric else "",
            "unit": s.metric.unit if s.metric else "",
        }
        for s in samples
    ]


@router.get("/traces")
def list_traces(
    incident_id: Optional[str] = None,
    has_error: Optional[bool] = None,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
):
    q = db.query(Trace)
    if incident_id:
        q = q.filter(Trace.incident_id == incident_id)
    if has_error is not None:
        q = q.filter(Trace.has_error == has_error)
    traces = q.order_by(Trace.start_time.desc()).limit(limit).all()
    return [
        {
            "trace_id": t.trace_id,
            "root_service": t.root_service,
            "start_time": t.start_time.isoformat(),
            "duration_ms": t.duration_ms,
            "status_code": t.status_code,
            "has_error": t.has_error,
        }
        for t in traces
    ]


@router.get("/traces/{trace_id}")
def inspect_trace_detail(trace_id: str, db: Session = Depends(get_db)):
    trace = db.query(Trace).filter(Trace.trace_id == trace_id).first()
    if not trace:
        raise HTTPException(status_code=404, detail=f"Trace {trace_id} not found")
    spans = db.query(Span).filter(Span.trace_id == trace_id).all()
    analysis = TraceAnalyzer.analyze_trace(trace, spans)
    return analysis.model_dump()


@router.get("/events", response_model=List[EventResponse])
def get_events(
    incident_id: Optional[str] = None,
    source_type: Optional[str] = None,
    service: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(Event)
    if incident_id:
        q = q.filter(Event.incident_id == incident_id)
    if source_type:
        q = q.filter(Event.source_type == source_type.upper())
    if service:
        q = q.filter(Event.service.ilike(f"%{service}%"))
    events = q.order_by(Event.timestamp.asc()).limit(limit).all()
    return events


@router.get("/correlations")
def get_correlations(incident_id: str, db: Session = Depends(get_db)):
    rels = (
        db.query(EventRelationship)
        .filter(EventRelationship.incident_id == incident_id)
        .order_by(EventRelationship.score.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "source_event_id": r.source_event_id,
            "target_event_id": r.target_event_id,
            "relationship_type": r.relationship_type,
            "score": r.score,
            "reason": r.reason,
            "provenance": r.provenance,
        }
        for r in rels
    ]
