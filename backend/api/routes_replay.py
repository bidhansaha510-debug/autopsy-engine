from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import Event
from backend.replay.engine import IncidentReplayEngine
from backend.normalization.normalizer import normalize_timestamp

router = APIRouter(prefix="/replay", tags=["Replay"])


@router.get("/{incident_id}/slice")
def get_replay_slice(
    incident_id: str,
    cursor_time: Optional[str] = None,
    db: Session = Depends(get_db),
):
    replay = IncidentReplayEngine(db)
    dt_cursor = None
    if cursor_time:
        dt_cursor, _ = normalize_timestamp(cursor_time)
    return replay.get_timeline_slice(incident_id, dt_cursor)


@router.get("/{incident_id}/timestamps", response_model=List[str])
def get_event_timestamps(incident_id: str, db: Session = Depends(get_db)):
    events = (
        db.query(Event.timestamp)
        .filter(Event.incident_id == incident_id)
        .order_by(Event.timestamp.asc())
        .all()
    )
    return [e[0].isoformat() for e in events]
