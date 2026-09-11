from datetime import datetime, timezone
from backend.models import Trace, Span
from backend.tracing.analyzer import TraceAnalyzer


def test_distributed_trace_critical_path_and_failure():
    t_now = datetime.now(timezone.utc)
    trace = Trace(
        id="trace-test-uuid",
        trace_id="tr-100",
        root_service="api-gateway",
        start_time=t_now,
        duration_ms=150.0,
        status_code=500,
        has_error=True,
    )

    span1 = Span(
        id="s1",
        trace_id="tr-100",
        span_id="sp-root",
        parent_span_id=None,
        service="api-gateway",
        name="GET /orders",
        start_time=t_now,
        duration_ms=150.0,
        status="ERROR",
        attributes_json={"http.status_code": 500},
    )

    span2 = Span(
        id="s2",
        trace_id="tr-100",
        span_id="sp-child-checkout",
        parent_span_id="sp-root",
        service="checkout-service",
        name="ProcessCheckout",
        start_time=t_now,
        duration_ms=140.0,
        status="ERROR",
        attributes_json={},
    )

    span3 = Span(
        id="s3",
        trace_id="tr-100",
        span_id="sp-child-db",
        parent_span_id="sp-child-checkout",
        service="payment-db",
        name="SELECT FOR UPDATE",
        start_time=t_now,
        duration_ms=135.0,
        status="ERROR",
        attributes_json={"error": "Connection timed out"},
    )

    spans = [span1, span2, span3]
    result = TraceAnalyzer.analyze_trace(trace, spans)

    assert result.has_error
    assert result.span_count == 3
    assert "sp-root" in result.critical_path
    assert "sp-child-db" in result.critical_path
    # Root cause failure is the leaf-most failing span (payment-db)
    assert result.root_failure_span_id == "sp-child-db"


def test_concurrent_overlapping_spans_interval_union():
    """Verifies that concurrent/overlapping child spans do not distort parent self-time
    via interval union arithmetic."""
    from datetime import timedelta
    t_now = datetime.now(timezone.utc)

    trace = Trace(
        id="trace-overlap-uuid",
        trace_id="tr-200",
        root_service="aggregator",
        start_time=t_now,
        duration_ms=100.0,
        status_code=200,
        has_error=False,
    )

    parent_span = Span(
        id="sp-p",
        trace_id="tr-200",
        span_id="sp-parent",
        parent_span_id=None,
        service="aggregator",
        name="FanOutQuery",
        start_time=t_now,
        duration_ms=100.0,
        status="OK",
    )

    # Child 1: [0ms, 80ms]
    child_b = Span(
        id="sp-b",
        trace_id="tr-200",
        span_id="sp-child-b",
        parent_span_id="sp-parent",
        service="search-backend",
        name="SearchService",
        start_time=t_now,
        duration_ms=80.0,
        status="OK",
    )

    # Child 2: [10ms, 80ms] (concurrently overlapping with Child 1)
    child_c = Span(
        id="sp-c",
        trace_id="tr-200",
        span_id="sp-child-c",
        parent_span_id="sp-parent",
        service="inventory-backend",
        name="InventoryCheck",
        start_time=t_now + timedelta(milliseconds=10),
        duration_ms=70.0,
        status="OK",
    )

    spans = [parent_span, child_b, child_c]
    result = TraceAnalyzer.analyze_trace(trace, spans)

    assert result.tree is not None
    # Combined child interval union is [0ms, 80ms], length = 80ms
    # Parent self-time = 100ms - 80ms = 20ms
    assert abs(result.tree.self_time_ms - 20.0) < 0.1
    # Critical path includes parent and child that determined the completion boundary
    assert "sp-parent" in result.critical_path
    assert "sp-child-b" in result.critical_path or "sp-child-c" in result.critical_path
