import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
from backend.core.security import sanitize_text


class NormalizationError(Exception):
    pass


def normalize_timestamp(ts: Optional[Any]) -> Tuple[datetime, Optional[str]]:
    """Converts any timestamp to UTC datetime and returns (utc_dt, original_tz_str)."""
    if ts is None:
        now = datetime.now(timezone.utc)
        return now, "+00:00"

    if isinstance(ts, (int, float)):
        # Epoch seconds or milliseconds
        if ts > 1e11:  # milliseconds
            ts = ts / 1000.0
        utc_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return utc_dt, "UTC"

    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            utc_dt = ts.replace(tzinfo=timezone.utc)
            return utc_dt, "none"
        else:
            original_tz = str(ts.tzinfo)
            utc_dt = ts.astimezone(timezone.utc)
            return utc_dt, original_tz

    if isinstance(ts, str):
        try:
            # Handle ISO format
            cleaned_str = ts.strip()
            # Replace Z with +00:00 for fromisoformat compatibility
            if cleaned_str.endswith("Z"):
                cleaned_str = cleaned_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(cleaned_str)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc), "none"
            return dt.astimezone(timezone.utc), str(dt.tzinfo)
        except Exception:
            # Fallback to current UTC
            return datetime.now(timezone.utc), "parse_fallback"

    return datetime.now(timezone.utc), "unknown"


def compute_fingerprint(data: Any) -> str:
    """Computes SHA-256 hash of serialized data for provenance tracking."""
    try:
        if isinstance(data, (dict, list)):
            serialized = json.dumps(data, sort_keys=True, default=str)
        else:
            serialized = str(data)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    except Exception:
        return hashlib.sha256(b"unserializable").hexdigest()


def normalize_event_payload(
    raw_payload: Dict[str, Any],
    source_type: str,
    source: str,
    environment: str = "production",
    service_hint: Optional[str] = None,
    host_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """Extracts standardized forensic fields and guarantees provenance integrity."""
    raw_time = raw_payload.get("timestamp") or raw_payload.get("time") or raw_payload.get("event_time")
    utc_time, orig_tz = normalize_timestamp(raw_time)

    service = service_hint or raw_payload.get("service") or raw_payload.get("app") or raw_payload.get("service_name") or "unknown-service"
    host = host_hint or raw_payload.get("host") or raw_payload.get("hostname") or raw_payload.get("node") or "unknown-host"

    raw_fp = compute_fingerprint(raw_payload)

    provenance = {
        "source": source,
        "source_type": source_type,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "original_timezone": orig_tz,
        "fingerprint": raw_fp,
        "environment": environment,
    }

    normalized = {
        "service": sanitize_text(str(service)),
        "host": sanitize_text(str(host)),
        "utc_timestamp": utc_time.isoformat(),
        "environment": sanitize_text(environment),
        "source_type": source_type,
        "fingerprint": raw_fp,
    }

    return {
        "utc_time": utc_time,
        "service": sanitize_text(str(service)),
        "host": sanitize_text(str(host)),
        "provenance": provenance,
        "normalized": normalized,
        "raw": raw_payload,
    }
