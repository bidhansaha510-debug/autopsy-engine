// Distributed Trace Waterfall and Critical Path Component
export class TraceWaterfallComponent {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.traceData = null;
  }

  setTrace(traceAnalysis) {
    this.traceData = traceAnalysis;
    this.render();
  }

  render() {
    if (!this.container || !this.traceData) return;

    const { trace_id, total_duration_ms, critical_path, root_failure_span_id, tree } = this.traceData;

    // Flatten tree into rows with depth indentation
    const flatRows = [];
    const flatten = (node, depth = 0) => {
      if (!node) return;
      flatRows.push({ ...node, depth });
      if (node.children) {
        node.children.forEach((c) => flatten(c, depth + 1));
      }
    };
    flatten(tree, 0);

    const rowsHtml = flatRows
      .map((span) => {
        const isCritical = critical_path && critical_path.includes(span.span_id);
        const isRootCause = span.span_id === root_failure_span_id;
        const indentPx = span.depth * 20;

        const barWidthPct = Math.max(2, (span.duration_ms / total_duration_ms) * 100);
        const barClass = span.status === 'ERROR' ? 'waterfall-bar error-bar' : 'waterfall-bar';

        return `
          <tr class="waterfall-row ${isCritical ? 'critical-path' : ''}">
            <td style="padding-left: ${indentPx + 12}px; min-width: 220px;">
              <span style="font-weight: 600; color: #fff;">${span.name}</span>
              <div style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono);">
                ${span.service} ${isCritical ? '• <span style="color:#ef4444;">CRITICAL PATH</span>' : ''} ${isRootCause ? '• <span style="color:#ef4444; font-weight:700;">ROOT FAILURE LEAF</span>' : ''}
              </div>
            </td>
            <td style="font-family: var(--font-mono); font-size: 11px;">${span.duration_ms.toFixed(1)} ms</td>
            <td style="font-family: var(--font-mono); font-size: 11px;">${span.self_time_ms.toFixed(1)} ms (${span.latency_percentage}%)</td>
            <td style="min-width: 200px;">
              <div class="waterfall-bar-container">
                <div class="${barClass}" style="width: ${barWidthPct}%;"></div>
              </div>
            </td>
            <td>
              <span class="badge ${span.status === 'ERROR' ? 'badge-sev1' : 'badge-resolved'}">${span.status}</span>
            </td>
          </tr>
        `;
      })
      .join('');

    this.container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <span class="mono" style="font-size: 12px; color: var(--text-secondary);">
          Trace ID: <strong style="color:var(--accent-cyan);">${trace_id}</strong> (Total Duration: <strong>${total_duration_ms} ms</strong>)
        </span>
        <span class="badge badge-sev1">Dependency Cascade Detected</span>
      </div>
      <table class="waterfall-table">
        <thead>
          <tr>
            <th>Operation / Service</th>
            <th>Total Latency</th>
            <th>Self-Time (Contrib)</th>
            <th>Execution Span Waterfall</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    `;
  }
}
