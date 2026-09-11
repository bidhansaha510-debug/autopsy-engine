// API Client for Infrastructure Autopsy Forensic Engine
const API_BASE = '/api';

export const Api = {
  async fetchJson(url, options = {}) {
    try {
      const res = await fetch(`${API_BASE}${url}`, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
      });
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP ${res.status}: ${res.statusText}`);
      }
      return await res.json();
    } catch (err) {
      console.error(`[API ERROR] ${url}:`, err);
      throw err;
    }
  },

  getHealth() {
    return this.fetchJson('/health');
  },

  getIncidents() {
    return this.fetchJson('/incidents');
  },

  getIncident(id) {
    return this.fetchJson(`/incidents/${id}`);
  },

  bootstrapCanonical() {
    return this.fetchJson('/incidents/bootstrap-canonical', { method: 'POST' });
  },

  getEvents(incidentId, params = {}) {
    const query = new URLSearchParams({ incident_id: incidentId, ...params });
    return this.fetchJson(`/telemetry/events?${query}`);
  },

  getLogs(incidentId, params = {}) {
    const query = new URLSearchParams({ incident_id: incidentId, ...params });
    return this.fetchJson(`/telemetry/logs?${query}`);
  },

  getMetrics(incidentId, params = {}) {
    const query = new URLSearchParams({ incident_id: incidentId, ...params });
    return this.fetchJson(`/telemetry/metrics?${query}`);
  },

  getTraces(incidentId) {
    return this.fetchJson(`/telemetry/traces?incident_id=${incidentId}`);
  },

  getTraceDetail(traceId) {
    return this.fetchJson(`/telemetry/traces/${traceId}`);
  },

  getCorrelations(incidentId) {
    return this.fetchJson(`/telemetry/correlations?incident_id=${incidentId}`);
  },

  getTopologyServices() {
    return this.fetchJson('/topology/services');
  },

  getBlastRadius(incidentId) {
    return this.fetchJson(`/topology/blast-radius/${incidentId}`);
  },

  getAnomalies(incidentId) {
    return this.fetchJson(`/forensics/anomalies/${incidentId}`);
  },

  getEvidence(incidentId) {
    return this.fetchJson(`/forensics/evidence/${incidentId}`);
  },

  getHypotheses(incidentId) {
    return this.fetchJson(`/forensics/hypotheses/${incidentId}`);
  },

  recalculateHypotheses(incidentId) {
    return this.fetchJson(`/forensics/hypotheses/recalculate/${incidentId}`, { method: 'POST' });
  },

  getInvestigation(incidentId) {
    return this.fetchJson(`/investigation/${incidentId}`);
  },

  runInvestigation(incidentId) {
    return this.fetchJson(`/investigation/run/${incidentId}`, { method: 'POST' });
  },

  getReplaySlice(incidentId, cursorTime) {
    const query = cursorTime ? `?cursor_time=${encodeURIComponent(cursorTime)}` : '';
    return this.fetchJson(`/replay/${incidentId}/slice${query}`);
  },

  getReplayTimestamps(incidentId) {
    return this.fetchJson(`/replay/${incidentId}/timestamps`);
  },

  getReport(incidentId) {
    return this.fetchJson(`/reports/${incidentId}`);
  },

  generateFreshReport(incidentId) {
    return this.fetchJson(`/reports/generate/${incidentId}`, { method: 'POST' });
  },

  async uploadCodebaseFolder(formData) {
    const res = await fetch(`${API_BASE}/codebase/upload-folder`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Upload failed: ${res.statusText}`);
    }
    return await res.json();
  },

  async scanLocalCodebase(path, caseTitle) {
    return this.fetchJson('/codebase/scan-local-path', {
      method: 'POST',
      body: JSON.stringify({ path, case_title: caseTitle }),
    });
  },

  updateReport(reportId, updateData) {
    return this.fetchJson(`/reports/${reportId}`, {
      method: 'PUT',
      body: JSON.stringify(updateData),
    });
  },

  pullStackTelemetry(data) {
    return this.fetchJson('/connectors/pull', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
};

