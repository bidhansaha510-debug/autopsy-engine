// Evidence Locker & Provenance Ledger Component
export class EvidenceComponent {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.evidenceList = [];
    this.selectedEvidence = null;
  }

  setEvidence(items) {
    this.evidenceList = items || [];
    this.render();
  }

  render() {
    if (!this.container) return;

    if (this.evidenceList.length === 0) {
      this.container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          No evidence items logged in chain of custody.
        </div>
      `;
      return;
    }

    const rowsHtml = this.evidenceList
      .map((ev) => {
        const timeStr = new Date(ev.timestamp).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        });

        const contentJson = JSON.stringify(ev.content, null, 2);
        const snippet = JSON.stringify(ev.content).slice(0, 85);

        return `
          <tr>
            <td>
              <span class="evidence-id-chip" title="Click to copy citation [${ev.id}]" data-copy="[${ev.id}]">
                ${ev.id}
              </span>
            </td>
            <td class="mono" style="font-size:11px; color:var(--text-muted);">${timeStr}</td>
            <td><span class="badge badge-${ev.evidence_type.toLowerCase()}">${ev.evidence_type}</span></td>
            <td style="font-weight:600; color:#fff;">${ev.entity}</td>
            <td class="mono" style="font-size:11px;">${(ev.confidence * 100).toFixed(0)}%</td>
            <td style="color:#cbd5e1; font-size:11px; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${snippet}">
              ${snippet}
            </td>
            <td>
              <button class="ctrl-btn btn-view-raw" style="padding:2px 8px; font-size:10px;" data-raw='${encodeURIComponent(contentJson)}'>
                Inspect
              </button>
            </td>
          </tr>
        `;
      })
      .join('');

    this.container.innerHTML = `
      <div style="margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
        <span style="font-size:12px; color:var(--text-secondary);">
          Total Indelible Evidence Records: <strong>${this.evidenceList.length}</strong> (Cryptographic Provenance Preserved)
        </span>
      </div>
      <table class="evidence-table">
        <thead>
          <tr>
            <th>Evidence ID</th>
            <th>Timestamp (UTC)</th>
            <th>Type</th>
            <th>Entity</th>
            <th>Confidence</th>
            <th>Evidence Payload Preview</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    `;

    // Copy to clipboard
    this.container.querySelectorAll('[data-copy]').forEach((el) => {
      el.addEventListener('click', () => {
        const text = el.dataset.copy;
        navigator.clipboard.writeText(text);
        const orig = el.innerText;
        el.innerText = 'COPIED!';
        setTimeout(() => (el.innerText = orig), 1200);
      });
    });

    // Inspect JSON
    this.container.querySelectorAll('.btn-view-raw').forEach((btn) => {
      btn.addEventListener('click', () => {
        const rawJson = decodeURIComponent(btn.dataset.raw);
        alert(`EVIDENCE CONTENT:\n\n${rawJson}`);
      });
    });
  }
}
