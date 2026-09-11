// Competing Hypotheses & Prove Me Wrong Component
export class HypothesesComponent {
  constructor(containerId, onSelectEvidence) {
    this.container = document.getElementById(containerId);
    this.onSelectEvidence = onSelectEvidence;
    this.hypotheses = [];
  }

  setHypotheses(hypotheses) {
    this.hypotheses = hypotheses || [];
    this.render();
  }

  render() {
    if (!this.container) return;

    if (this.hypotheses.length === 0) {
      this.container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          No hypotheses generated yet. Trigger forensic analysis.
        </div>
      `;
      return;
    }

    const cardsHtml = this.hypotheses
      .map((h, idx) => {
        const isLeading = idx === 0 && h.score >= 0.6;
        const scorePct = Math.round(h.score * 100);

        // Separate links
        const supLinks = (h.evidence_links || []).filter((l) => l.relationship_type === 'SUPPORTS');
        const contraLinks = (h.evidence_links || []).filter((l) => l.relationship_type === 'CONTRADICTS');

        const supItemsHtml = supLinks.length
          ? supLinks
              .map(
                (l) => `
              <div style="font-size:12px; margin-bottom:4px; display:flex; gap:6px;">
                <span class="badge badge-supports" style="cursor:pointer;" data-ev-id="${l.evidence_id}">${l.evidence_id}</span>
                <span style="color:#cbd5e1;">${l.explanation}</span>
              </div>
            `
              )
              .join('')
          : '<div style="font-size:11px; color:var(--text-muted);">No supporting telemetry recorded.</div>';

        const contraItemsHtml = contraLinks.length
          ? contraLinks
              .map(
                (l) => `
              <div style="font-size:12px; margin-bottom:4px; display:flex; gap:6px;">
                <span class="badge badge-contradicts" style="cursor:pointer;" data-ev-id="${l.evidence_id}">${l.evidence_id}</span>
                <span style="color:#f87171;">${l.explanation}</span>
              </div>
            `
              )
              .join('')
          : '<div style="font-size:11px; color:var(--text-muted);">No counterevidence detected.</div>';

        const missingItemsHtml = (h.missing_evidence || []).length
          ? h.missing_evidence.map((m) => `<li style="font-size:11px; color:var(--text-muted);">${m}</li>`).join('')
          : '<li style="font-size:11px; color:var(--text-muted);">All expected telemetry verified.</li>';

        return `
          <div class="hypothesis-card ${isLeading ? 'leading' : ''}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start;">
              <span class="badge" style="background:rgba(255,255,255,0.06);">RANK #${h.rank}</span>
              <span class="badge ${h.status === 'SUPPORTED' ? 'badge-resolved' : h.status === 'REFUTED' ? 'badge-sev1' : 'badge-provenance'}">${h.status}</span>
            </div>
            <div style="font-size:14px; font-weight:700; color:#fff;">${h.statement}</div>

            <div class="score-bar-wrapper">
              <div style="display:flex; justify-content:space-between; font-size:11px;">
                <span style="color:var(--text-muted);">Investigation Support Score</span>
                <strong style="color:${isLeading ? 'var(--accent-cyan)' : '#fff'};">${h.score.toFixed(2)} (${scorePct}%)</strong>
              </div>
              <div class="score-bar-bg">
                <div class="score-bar-fill ${h.status === 'REFUTED' ? 'refuted' : ''}" style="width: ${scorePct}%;"></div>
              </div>
            </div>

            <div style="margin-top:6px;">
              <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:#34d399; margin-bottom:6px;">
                Supporting Evidence (${supLinks.length})
              </div>
              ${supItemsHtml}
            </div>

            <div style="margin-top:6px;">
              <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:#f87171; margin-bottom:6px;">
                Counterevidence Penalties (${contraLinks.length})
              </div>
              ${contraItemsHtml}
            </div>

            <div style="margin-top:6px; border-top:1px solid var(--border-color); padding-top:8px;">
              <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">
                Missing Evidence Checklist
              </div>
              <ul style="padding-left:16px;">
                ${missingItemsHtml}
              </ul>
            </div>
          </div>
        `;
      })
      .join('');

    this.container.innerHTML = `
      <div style="margin-bottom:14px; display:flex; justify-content:space-between; align-items:center;">
        <span style="color:var(--text-secondary); font-size:12px;">
          Competing Root-Cause Hypotheses evaluated with <strong>Prove Me Wrong</strong> counterevidence checks.
        </span>
        <button id="btn-recalculate-hyp" class="ctrl-btn">
          <span>↻</span> Re-evaluate Counterevidence
        </button>
      </div>
      <div class="hypotheses-grid">
        ${cardsHtml}
      </div>
    `;

    // Evidence chip clicks
    this.container.querySelectorAll('[data-ev-id]').forEach((chip) => {
      chip.addEventListener('click', () => {
        const evidId = chip.dataset.evId;
        if (this.onSelectEvidence) this.onSelectEvidence(evidId);
      });
    });
  }
}
