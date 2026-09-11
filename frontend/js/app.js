// Master Application Controller for Infrastructure Autopsy
import { Api } from './api.js';
import { TimelineComponent } from './timeline.js';
import { TopologyComponent } from './topology.js';
import { TraceWaterfallComponent } from './waterfall.js';
import { HypothesesComponent } from './hypotheses.js';
import { EvidenceComponent } from './evidence.js';
import { AIConsoleComponent } from './ai_console.js';
import { MetricsComponent } from './metrics.js';
import { ReportsComponent } from './reports.js';
import { ReplayController } from './replay.js';

class AutopsyApp {
  constructor() {
    this.currentIncidentId = null;
    this.activeTab = 'overview';

    this.timelineComp = null;
    this.topologyComp = null;
    this.waterfallComp = null;
    this.hypothesesComp = null;
    this.evidenceComp = null;
    this.aiConsoleComp = null;
    this.metricsComp = null;
    this.reportsComp = null;
    this.replayCtrl = null;
  }

  async init() {
    console.log('[AUTOPSY] Initializing Forensic Workspace...');
    this.setupNavigation();
    this.setupComponents();
    this.setupCodebaseModal();

    // Check health
    try {
      const health = await Api.getHealth();
      const dot = document.getElementById('ollama-status-dot');
      const text = document.getElementById('ollama-status-text');
      if (dot && text) {
        if (health.ollama_connected) {
          dot.style.background = '#10b981';
          text.innerText = `Ollama Online (${health.ollama_model})`;
        } else {
          dot.style.background = '#f59e0b';
          text.innerText = 'Ollama Offline (Deterministic Fallback Active)';
        }
      }
    } catch (e) {
      console.warn('Health check warning:', e);
    }

    // Load incidents
    await this.loadIncidents();
  }

  setupNavigation() {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        tabs.forEach((t) => t.classList.remove('active'));
        tab.classList.add('active');
        const viewName = tab.dataset.view;
        this.switchView(viewName);
      });
    });

    const sel = document.getElementById('select-incident');
    if (sel) {
      sel.addEventListener('change', (e) => {
        this.switchIncident(e.target.value);
      });
    }

    const btnBootstrap = document.getElementById('btn-bootstrap-incident');
    if (btnBootstrap) {
      btnBootstrap.addEventListener('click', async () => {
        btnBootstrap.disabled = true;
        btnBootstrap.innerText = 'Reconstructing...';
        try {
          const inc = await Api.bootstrapCanonical();
          await this.loadIncidents();
          this.switchIncident(inc.id);
        } catch (err) {
          alert(`Bootstrap error: ${err.message}`);
        } finally {
          btnBootstrap.disabled = false;
          btnBootstrap.innerText = '+ Bootstrap Canonical Incident';
        }
      });
    }

    // Timeline filter buttons
    document.querySelectorAll('.filter-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        const filter = btn.dataset.filter;
        if (this.timelineComp) this.timelineComp.setFilter(filter);
      });
    });
  }

  setupComponents() {
    this.timelineComp = new TimelineComponent('timeline-container', (ev) => {
      this.switchView('evidence');
    });

    this.topologyComp = new TopologyComponent('topology-container', (nodeName) => {
      console.log('Selected node:', nodeName);
    });

    this.waterfallComp = new TraceWaterfallComponent('waterfall-container');

    this.hypothesesComp = new HypothesesComponent('hypotheses-container', (evidId) => {
      this.switchView('evidence');
    });

    this.evidenceComp = new EvidenceComponent('evidence-container');

    this.aiConsoleComp = new AIConsoleComponent(
      'ai-console-container',
      async () => {
        if (!this.currentIncidentId) return;
        const inv = await Api.runInvestigation(this.currentIncidentId);
        this.aiConsoleComp.setInvestigation(inv);
        await this.loadIncidentForensics(this.currentIncidentId);
      },
      (evidId) => {
        this.switchView('evidence');
      }
    );

    this.metricsComp = new MetricsComponent('metrics-container');

    this.reportsComp = new ReportsComponent('reports-container', async () => {
      if (!this.currentIncidentId) return;
      const rep = await Api.generateFreshReport(this.currentIncidentId);
      this.reportsComp.setReport(rep);
    });

    this.replayCtrl = new ReplayController('scrubber-slider', async (cursorTime) => {
      if (!this.currentIncidentId) return;
      const slice = await Api.getReplaySlice(this.currentIncidentId, cursorTime);
      if (this.timelineComp) this.timelineComp.setEvents(slice.events);
      if (this.evidenceComp) this.evidenceComp.setEvidence(slice.evidence);
    });
  }

  setupCodebaseModal() {
    const modal = document.getElementById('modal-codebase-upload');
    const btnOpen = document.getElementById('btn-open-upload-modal');
    const btnClose = document.getElementById('btn-close-modal');

    if (!modal) return;

    if (btnOpen) {
      btnOpen.addEventListener('click', () => {
        modal.classList.add('open');
      });
    }

    if (btnClose) {
      btnClose.addEventListener('click', () => {
        modal.classList.remove('open');
      });
    }

    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.remove('open');
    });

    // Tab switching in modal
    const tabFolder = document.getElementById('tab-upload-folder');
    const tabPath = document.getElementById('tab-upload-path');
    const secFolder = document.getElementById('section-folder-upload');
    const secPath = document.getElementById('section-path-scan');
    const feedback = document.getElementById('upload-status-feedback');

    if (tabFolder && tabPath) {
      tabFolder.addEventListener('click', () => {
        tabFolder.classList.add('active');
        tabPath.classList.remove('active');
        secFolder.style.display = 'block';
        secPath.style.display = 'none';
        if (feedback) feedback.style.display = 'none';
      });
      tabPath.addEventListener('click', () => {
        tabPath.classList.add('active');
        tabFolder.classList.remove('active');
        secFolder.style.display = 'none';
        secPath.style.display = 'block';
        if (feedback) feedback.style.display = 'none';
      });
    }

    // File inputs
    const inputFolder = document.getElementById('file-input-folder');
    const inputArchive = document.getElementById('file-input-archive');
    const statusText = document.getElementById('upload-file-status');
    let selectedFiles = [];

    if (inputFolder) {
      inputFolder.addEventListener('change', (e) => {
        selectedFiles = Array.from(e.target.files);
        if (statusText) {
          statusText.innerText = `Selected folder containing ${selectedFiles.length} files.`;
        }
      });
    }

    if (inputArchive) {
      inputArchive.addEventListener('change', (e) => {
        selectedFiles = Array.from(e.target.files);
        if (statusText && selectedFiles.length > 0) {
          statusText.innerText = `Selected archive: ${selectedFiles[0].name}`;
        }
      });
    }

    // Submit Folder Upload
    const btnSubmitUpload = document.getElementById('btn-submit-upload');
    if (btnSubmitUpload) {
      btnSubmitUpload.addEventListener('click', async () => {
        if (!selectedFiles || selectedFiles.length === 0) {
          alert('Please choose a codebase folder or archive file first.');
          return;
        }

        btnSubmitUpload.disabled = true;
        btnSubmitUpload.innerText = 'Extracting & Scanning Codebase...';
        if (feedback) {
          feedback.style.display = 'block';
          feedback.style.background = 'rgba(0, 240, 255, 0.1)';
          feedback.style.color = 'var(--accent-cyan)';
          feedback.innerText = 'Uploading directory tree, discovering microservices, and parsing configuration models...';
        }

        try {
          const formData = new FormData();
          selectedFiles.forEach((file) => {
            // Use webkitRelativePath if available so directory structure is preserved
            const relPath = file.webkitRelativePath || file.name;
            formData.append('files', file, relPath);
          });

          const titleInput = document.getElementById('input-upload-title');
          if (titleInput && titleInput.value.trim()) {
            formData.append('case_title', titleInput.value.trim());
          }

          const res = await Api.uploadCodebaseFolder(formData);
          if (feedback) {
            feedback.style.background = 'rgba(16, 185, 129, 0.15)';
            feedback.style.color = '#34d399';
            feedback.innerHTML = `<strong>Scan Complete!</strong> Discovered ${res.data.services_discovered.length} services (${res.data.services_discovered.join(', ')}), extracted ${res.data.configs_extracted} configs, and ingested ${res.data.logs_ingested} logs.`;
          }

          await this.loadIncidents();
          this.switchIncident(res.data.incident_id);

          setTimeout(() => {
            modal.classList.remove('open');
          }, 1800);
        } catch (err) {
          if (feedback) {
            feedback.style.background = 'rgba(239, 68, 68, 0.15)';
            feedback.style.color = '#f87171';
            feedback.innerText = `Ingestion Error: ${err.message}`;
          }
        } finally {
          btnSubmitUpload.disabled = false;
          btnSubmitUpload.innerText = 'Extract Services, Parse Telemetry & Ingest';
        }
      });
    }

    // Submit Local Path Scan
    const btnSubmitPath = document.getElementById('btn-submit-path-scan');
    if (btnSubmitPath) {
      btnSubmitPath.addEventListener('click', async () => {
        const pathInput = document.getElementById('input-local-path');
        const titleInput = document.getElementById('input-path-title');
        const pathVal = pathInput ? pathInput.value.trim() : '';

        if (!pathVal) {
          alert('Please enter a directory path on disk.');
          return;
        }

        btnSubmitPath.disabled = true;
        btnSubmitPath.innerText = 'Scanning Local Path...';
        if (feedback) {
          feedback.style.display = 'block';
          feedback.style.background = 'rgba(0, 240, 255, 0.1)';
          feedback.style.color = 'var(--accent-cyan)';
          feedback.innerText = `Scanning directory '${pathVal}'...`;
        }

        try {
          const res = await Api.scanLocalCodebase(pathVal, titleInput ? titleInput.value.trim() : null);
          if (feedback) {
            feedback.style.background = 'rgba(16, 185, 129, 0.15)';
            feedback.style.color = '#34d399';
            feedback.innerHTML = `<strong>Local Scan Complete!</strong> Discovered ${res.data.services_discovered.length} services (${res.data.services_discovered.join(', ')}), extracted ${res.data.configs_extracted} configs, and ingested ${res.data.logs_ingested} logs.`;
          }

          await this.loadIncidents();
          this.switchIncident(res.data.incident_id);

          setTimeout(() => {
            modal.classList.remove('open');
          }, 1800);
        } catch (err) {
          if (feedback) {
            feedback.style.background = 'rgba(239, 68, 68, 0.15)';
            feedback.style.color = '#f87171';
            feedback.innerText = `Scan Error: ${err.message}`;
          }
        } finally {
          btnSubmitPath.disabled = false;
          btnSubmitPath.innerText = 'Scan Local Directory & Reconstruct Case';
        }
      });
    }
  }

  switchView(viewName) {
    this.activeTab = viewName;
    document.querySelectorAll('.view-panel').forEach((p) => p.classList.remove('active'));
    const panel = document.getElementById(`view-${viewName}`);
    if (panel) panel.classList.add('active');
  }

  async loadIncidents() {
    const incidents = await Api.getIncidents();
    const sel = document.getElementById('select-incident');
    if (!sel) return;

    sel.innerHTML = incidents
      .map((inc) => `<option value="${inc.id}">${inc.title} (${inc.severity})</option>`)
      .join('');

    if (incidents.length > 0) {
      this.switchIncident(incidents[0].id);
    }
  }

  async switchIncident(incidentId) {
    this.currentIncidentId = incidentId;
    const inc = await Api.getIncident(incidentId);

    // Update Banner
    const elTitle = document.getElementById('banner-incident-title');
    const elSev = document.getElementById('banner-severity');
    const elStatus = document.getElementById('banner-status');
    const elMode = document.getElementById('banner-mode');
    const elTime = document.getElementById('banner-time');
    const elLeadingHyp = document.getElementById('banner-leading-hypothesis');
    const elLeadingScore = document.getElementById('banner-leading-score');

    if (elTitle) elTitle.innerText = inc.title;
    if (elSev) {
      elSev.innerText = inc.severity;
      elSev.className = `badge badge-${inc.severity.toLowerCase()}`;
    }
    if (elStatus) {
      elStatus.innerText = inc.status;
      elStatus.className = `badge badge-${inc.status === 'RESOLVED' ? 'resolved' : 'sev1'}`;
    }
    if (elMode) {
      elMode.innerText = inc.is_simulated ? 'SIMULATION' : 'LIVE';
      elMode.className = `badge ${inc.is_simulated ? 'badge-simulated' : 'badge-live'}`;
    }
    if (elTime) {
      const start = new Date(inc.started_at).toLocaleTimeString();
      const end = inc.resolved_at ? new Date(inc.resolved_at).toLocaleTimeString() : 'Ongoing';
      elTime.innerText = `${start} → ${end}`;
    }

    await this.loadIncidentForensics(incidentId);
  }

  async loadIncidentForensics(incidentId) {
    try {
      // 1. Events & Timeline
      const events = await Api.getEvents(incidentId);
      if (this.timelineComp) this.timelineComp.setEvents(events);

      // 2. Blast Radius & Topology
      const blast = await Api.getBlastRadius(incidentId);
      if (this.topologyComp) this.topologyComp.setData(blast);

      // Also render mini-topology in Overview cockpit
      const overviewTopology = new TopologyComponent('overview-topology-container');
      overviewTopology.setData(blast);

      // 3. Hypotheses
      const hypotheses = await Api.getHypotheses(incidentId);
      if (this.hypothesesComp) this.hypothesesComp.setHypotheses(hypotheses);

      // Recalculate button handler
      const btnRecalc = document.getElementById('btn-recalculate-hyp');
      if (btnRecalc) {
        btnRecalc.onclick = async () => {
          btnRecalc.disabled = true;
          btnRecalc.innerText = 'Calculating...';
          const fresh = await Api.recalculateHypotheses(incidentId);
          this.hypothesesComp.setHypotheses(fresh);
          btnRecalc.disabled = false;
          btnRecalc.innerText = '↻ Re-evaluate Counterevidence';
        };
      }

      if (hypotheses.length > 0) {
        const top = hypotheses[0];
        const elLeadingHyp = document.getElementById('banner-leading-hypothesis');
        const elLeadingScore = document.getElementById('banner-leading-score');
        if (elLeadingHyp) elLeadingHyp.innerText = top.statement;
        if (elLeadingScore) elLeadingScore.innerText = `Support: ${(top.score * 100).toFixed(0)}%`;
      }

      // 4. Evidence Locker
      const evidence = await Api.getEvidence(incidentId);
      if (this.evidenceComp) this.evidenceComp.setEvidence(evidence);

      // 5. Distributed Traces
      const traces = await Api.getTraces(incidentId);
      if (traces && traces.length > 0) {
        const traceDetail = await Api.getTraceDetail(traces[0].trace_id);
        if (this.waterfallComp) this.waterfallComp.setTrace(traceDetail);
      }

      // 6. Anomalies
      const anomalies = await Api.getAnomalies(incidentId);
      if (this.metricsComp) this.metricsComp.setAnomalies(anomalies);

      // 7. AI Investigator
      const inv = await Api.getInvestigation(incidentId);
      if (this.aiConsoleComp) this.aiConsoleComp.setInvestigation(inv);

      // 8. Report
      const rep = await Api.getReport(incidentId);
      if (this.reportsComp) this.reportsComp.setReport(rep);

      // 9. Replay Timestamps
      const timestamps = await Api.getReplayTimestamps(incidentId);
      if (this.replayCtrl) this.replayCtrl.setTimestamps(timestamps);
    } catch (err) {
      console.error('Forensic loading error:', err);
    }
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const app = new AutopsyApp();
  app.init();
});
