from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from backend.models import Span, Trace


class SpanNode(BaseModel):
    span_id: str
    parent_span_id: Optional[str]
    service: str
    name: str
    start_time: str
    duration_ms: float
    status: str
    attributes: Dict[str, Any]
    events: List[Dict[str, Any]]
    self_time_ms: float = 0.0
    latency_percentage: float = 0.0
    is_critical_path: bool = False
    is_root_cause_failure: bool = False
    children: List["SpanNode"] = []


class TraceAnalysisResult(BaseModel):
    trace_id: str
    root_service: str
    total_duration_ms: float
    has_error: bool
    status_code: int
    span_count: int
    critical_path: List[str]
    failing_services: List[str]
    root_failure_span_id: Optional[str]
    fan_out_max: int
    tree: Optional[SpanNode]


class TraceAnalyzer:
    @staticmethod
    def analyze_trace(trace: Trace, spans: List[Span]) -> TraceAnalysisResult:
        if not spans:
            return TraceAnalysisResult(
                trace_id=trace.trace_id,
                root_service=trace.root_service,
                total_duration_ms=trace.duration_ms,
                has_error=trace.has_error,
                status_code=trace.status_code,
                span_count=0,
                critical_path=[],
                failing_services=[],
                root_failure_span_id=None,
                fan_out_max=0,
                tree=None,
            )

        # Index spans by span_id
        span_map: Dict[str, Span] = {s.span_id: s for s in spans}
        children_map: Dict[str, List[Span]] = {}
        for s in spans:
            pid = s.parent_span_id
            children_map.setdefault(pid, []).append(s)

        # Find root span (no parent or parent not in map)
        root_span = None
        for s in spans:
            if not s.parent_span_id or s.parent_span_id not in span_map:
                root_span = s
                break
        if not root_span and spans:
            root_span = spans[0]

        total_trace_duration = max(trace.duration_ms, root_span.duration_ms if root_span else 1.0)
        if total_trace_duration <= 0:
            total_trace_duration = 1.0

        # Build tree recursively and compute self-times via interval union
        def build_node(s: Span) -> SpanNode:
            child_spans = children_map.get(s.span_id, [])
            child_nodes = [build_node(c) for c in child_spans]

            # Compute interval union of child executions to account for concurrency/overlap
            intervals = []
            for c in child_spans:
                try:
                    c_offset = max(0.0, (c.start_time - s.start_time).total_seconds() * 1000.0)
                except Exception:
                    c_offset = 0.0
                c_end = c_offset + c.duration_ms
                intervals.append([c_offset, c_end])

            # Merge overlapping intervals
            merged = []
            for start, end in sorted(intervals, key=lambda x: x[0]):
                if not merged or merged[-1][1] < start:
                    merged.append([start, end])
                else:
                    merged[-1][1] = max(merged[-1][1], end)

            child_active_time = sum(end - start for start, end in merged)
            self_time = max(0.0, s.duration_ms - child_active_time)
            latency_pct = round((s.duration_ms / total_trace_duration) * 100.0, 2)

            return SpanNode(
                span_id=s.span_id,
                parent_span_id=s.parent_span_id,
                service=s.service,
                name=s.name,
                start_time=s.start_time.isoformat(),
                duration_ms=round(s.duration_ms, 2),
                status=s.status,
                attributes=s.attributes_json or {},
                events=s.events_json or [],
                self_time_ms=round(self_time, 2),
                latency_percentage=latency_pct,
                children=child_nodes,
            )

        root_node = build_node(root_span) if root_span else None

        # Compute Critical Path via interval bottleneck progression
        critical_path_ids: List[str] = []

        def find_critical_path(curr: Optional[SpanNode]):
            if not curr:
                return
            critical_path_ids.append(curr.span_id)
            curr.is_critical_path = True
            if not curr.children:
                return
            # True distributed critical path: child that determined the latest completion boundary
            def child_bottleneck_score(child: SpanNode) -> float:
                span_obj = span_map.get(child.span_id)
                curr_obj = span_map.get(curr.span_id)
                if span_obj and curr_obj:
                    try:
                        start_delta = max(0.0, (span_obj.start_time - curr_obj.start_time).total_seconds() * 1000.0)
                        end_delta = start_delta + child.duration_ms
                        return end_delta
                    except Exception:
                        pass
                return child.duration_ms

            bottleneck_child = max(curr.children, key=child_bottleneck_score)
            find_critical_path(bottleneck_child)

        find_critical_path(root_node)

        # Identify failing spans and pinpoint root initiating failure via causal analysis
        failing_spans = [s for s in spans if s.status.upper() == "ERROR"]
        failing_services = list({s.service for s in failing_spans})
        root_failure_span_id = None

        if failing_spans:
            def failure_causality_score(fs: Span) -> Tuple[int, float, int]:
                # 1. Spans with explicit error details / exception attributes
                attrs = fs.attributes_json or {}
                has_explicit_error = 1 if any(k in attrs for k in ("error", "error.message", "exception", "exception.message")) else 0
                
                # 2. Leaf-most failing position in call tree (no failing children)
                fs_children = children_map.get(fs.span_id, [])
                is_originating_leaf = 1 if not any(c.status.upper() == "ERROR" for c in fs_children) else 0

                # 3. Temporal onset: earlier start time favored
                try:
                    onset_delta = (fs.start_time - trace.start_time).total_seconds()
                except Exception:
                    onset_delta = 0.0

                # Tuple for sorting: prioritize originating leaf with explicit error, breaking ties by earliest onset
                return (is_originating_leaf, has_explicit_error, -onset_delta)

            best_root_failure = max(failing_spans, key=failure_causality_score)
            root_failure_span_id = best_root_failure.span_id

        # Mark root failure on node
        def mark_root_failure(node: Optional[SpanNode]):
            if not node:
                return
            if node.span_id == root_failure_span_id:
                node.is_root_cause_failure = True
            for ch in node.children:
                mark_root_failure(ch)

        mark_root_failure(root_node)

        # Fan-out max
        fan_out_max = max([len(c) for c in children_map.values()], default=0)

        return TraceAnalysisResult(
            trace_id=trace.trace_id,
            root_service=trace.root_service,
            total_duration_ms=round(total_trace_duration, 2),
            has_error=trace.has_error or len(failing_spans) > 0,
            status_code=trace.status_code,
            span_count=len(spans),
            critical_path=critical_path_ids,
            failing_services=failing_services,
            root_failure_span_id=root_failure_span_id,
            fan_out_max=fan_out_max,
            tree=root_node,
        )
