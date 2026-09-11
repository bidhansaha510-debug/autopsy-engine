// AI Investigator Tool-Execution Console Component
export class AIConsoleComponent {
  constructor(containerId, onRunInvestigation, onSelectEvidence) {
    this.container = document.getElementById(containerId);
    this.onRunInvestigation = onRunInvestigation;
    this.onSelectEvidence = onSelectEvidence;
    this.investigation = null;
  }

  setInvestigation(inv) {
    this.investigation = inv;
    this.render();
  }

  render() {
    if (!this.container) return;

    if (!this.investigation) {
      this.container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          AI Investigator is idle. Click "Run Forensic Investigation" to begin.
        </div>
      `;
      return;
    }

    const { status, started_at, completed_at, current_focus, steps } = this.investigation;

    const stepsHtml = (steps || [])
      .map((s) => {
        // Highlight citations in findings
        const formattedFindings = s.findings.replace(
          /\[(EVID-[A-Z0-9-]+)\]/g,
          '<span class="ai-citation" data-ev-id="$1">[$1]</span>'
        );

        return `
          <div class="ai-step-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <span style="font-weight:700; color:#fff;">STEP ${s.step_number}: ${s.question}</span>
              <span class="badge badge-provenance">TOOL: ${s.tool_called}</span>
            </div>
            <div class="mono" style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
              Parameters: ${JSON.stringify(s.tool_parameters_json)}
            </div>
            <div style="font-size:12px; line-height:1.6; color:#e2e8f0;">
              ${formattedFindings}
            </div>
          </div>
        `;
      })
      .join('');

    const formattedSynthesis = (current_focus || '').replace(
      /\[(EVID-[A-Z0-9-]+)\]/g,
      '<span class="ai-citation" data-ev-id="$1">[$1]</span>'
    );

    this.container.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <div>
          <span style="font-size:13px; font-weight:700; color:#fff;">Forensic Investigator Session</span>
          <span class="badge ${status === 'COMPLETED' ? 'badge-resolved' : 'badge-simulated'}" style="margin-left:8px;">${status}</span>
        </div>
        <button id="btn-trigger-ai" class="ctrl-btn" style="border-color:var(--accent-purple); color:var(--accent-purple);">
          <span>⚡</span> Re-Run AI Forensics Tool Loop
        </button>
      </div>

      <div class="ai-console">
        <div style="color:var(--accent-cyan); font-weight:700; margin-bottom:12px;">
          > FORENSIC AUDIT TRAIL [READ-ONLY TOOL EXECUTION ACTIVE]
        </div>

        ${stepsHtml}

        <div style="background:rgba(15, 23, 42, 0.8); border:1px solid var(--accent-cyan); border-radius:4px; padding:14px; margin-top:16px;">
          <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--accent-cyan); margin-bottom:6px;">
            Synthesis & Chain-of-Custody Provenance Conclusion
          </div>
          <div style="font-size:13px; white-space:pre-wrap; line-height:1.6; color:#fff;">
            ${formattedSynthesis}
          </div>
        </div>
      </div>
    `;

    // Trigger AI button
    const btn = this.container.querySelector('#btn-trigger-ai');
    if (btn) {
      btn.addEventListener('click', () => {
        btn.disabled = true;
        btn.innerText = 'Investigating...';
        if (this.onRunInvestigation) this.onRunInvestigation();
      });
    }

    // Citation clicks
    this.container.querySelectorAll('.ai-citation').forEach((cit) => {
      cit.addEventListener('click', () => {
        const id = cit.dataset.evId;
        if (this.onSelectEvidence) this.onSelectEvidence(id);
      });
    });
  }
}
