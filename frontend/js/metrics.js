// Metric Anomalies & Baseline Chart Component
export class MetricsComponent {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.anomalies = [];
  }

  setAnomalies(anomalies) {
    this.anomalies = anomalies || [];
    this.render();
  }

  render() {
    if (!this.container) return;

    if (this.anomalies.length === 0) {
      this.container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          No statistical metric anomalies detected.
        </div>
      `;
      return;
    }

    const cardsHtml = this.anomalies
      .map((a) => {
        const timeStr = new Date(a.detected_at).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        });

        const sevClass = a.severity === 'CRITICAL' ? 'badge-sev1' : a.severity === 'HIGH' ? 'badge-sev1' : 'badge-provenance';

        return `
          <div class="glass-card" style="margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
              <div>
                <span class="badge ${sevClass}">${a.severity}</span>
                <span style="font-weight:700; color:#fff; margin-left:8px; font-size:14px;">${a.metric_name}</span>
                <span style="font-size:12px; color:var(--text-muted); margin-left:6px;">(${a.service})</span>
              </div>
              <span class="mono" style="font-size:11px; color:var(--text-muted);">${timeStr}</span>
            </div>

            <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:12px; background:var(--bg-surface); padding:10px; border-radius:4px; font-size:12px;">
              <div>
                <div style="color:var(--text-muted); font-size:10px; text-transform:uppercase;">Observed Value</div>
                <div style="font-weight:700; font-size:15px; color:#ef4444;">${a.actual}</div>
              </div>
              <div>
                <div style="color:var(--text-muted); font-size:10px; text-transform:uppercase;">Expected Baseline</div>
                <div style="font-weight:700; font-size:15px; color:#10b981;">${a.expected}</div>
              </div>
              <div>
                <div style="color:var(--text-muted); font-size:10px; text-transform:uppercase;">Deviation Δ</div>
                <div style="font-weight:700; font-size:15px; color:#f59e0b;">+${a.deviation}</div>
              </div>
              <div>
                <div style="color:var(--text-muted); font-size:10px; text-transform:uppercase;">Anomaly Score</div>
                <div style="font-weight:700; font-size:15px; color:#00f0ff;">${a.anomaly_score}x MAD</div>
              </div>
            </div>

            <div style="margin-top:8px; font-size:11px; color:var(--text-muted);">
              Baseline Window: <code>${a.baseline_window}</code> • Calculated via non-parametric Robust Median Absolute Deviation (MAD).
            </div>
          </div>
        `;
      })
      .join('');

    this.container.innerHTML = `
      <div style="margin-bottom:14px;">
        <span style="font-size:12px; color:var(--text-secondary);">
          Telemetry Deviations Detected Against Pre-Incident Rolling Baseline
        </span>
      </div>
      <div>
        ${cardsHtml}
      </div>
    `;
  }
}
