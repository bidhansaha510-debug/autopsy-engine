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
