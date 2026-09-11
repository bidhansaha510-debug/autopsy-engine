// Forensic Report Component
export class ReportsComponent {
  constructor(containerId, onGenerateFresh) {
    this.container = document.getElementById(containerId);
    this.onGenerateFresh = onGenerateFresh;
    this.report = null;
  }

  setReport(rep) {
    this.report = rep;
    this.render();
  }

  render() {
    if (!this.container) return;

    if (!this.report) {
      this.container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          No report generated yet.
        </div>
      `;
      return;
    }

    // Convert basic markdown headings and tables to HTML
    let md = this.report.content_markdown || '';

    // Simple markdown formatting helper
    let formattedHtml = md
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
      .replace(/`([^`]+)`/gim, '<code>$1</code>')
      .replace(/\n\n/gim, '<br/><br/>');

    // Parse markdown tables if any
    const lines = md.split('\n');
    let inTable = false;
    let tableHtml = '';
    let processedLines = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith('|') && line.endsWith('|')) {
        if (!inTable) {
          inTable = true;
          tableHtml = '<table class="evidence-table"><thead>';
          const headers = line
            .split('|')
            .filter((c) => c.trim().length > 0)
            .map((c) => `<th>${c.trim()}</th>`)
            .join('');
          tableHtml += `<tr>${headers}</tr></thead><tbody>`;
          // skip delimiter line
          i++;
        } else {
          const cells = line
            .split('|')
            .filter((c) => c.trim().length > 0)
            .map((c) => `<td>${c.trim()}</td>`)
            .join('');
          tableHtml += `<tr>${cells}</tr>`;
        }
      } else {
        if (inTable) {
          inTable = false;
          tableHtml += '</tbody></table>';
          processedLines.push(tableHtml);
        }
        processedLines.push(line);
      }
    }
    if (inTable) {
      tableHtml += '</tbody></table>';
      processedLines.push(tableHtml);
    }

    const finalHtml = processedLines
      .join('\n')
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
      .replace(/`([^`]+)`/gim, '<code>$1</code>');

    this.container.innerHTML = `
      <div style="margin-bottom:16px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-weight:700; color:#fff; font-size:14px;">Evidence-Backed Incident Report</span>
          <span class="badge badge-resolved" style="margin-left:8px;">AUDITED FORENSIC RECORD</span>
        </div>
        <div style="display:flex; gap:8px;">
          <button id="btn-export-report" class="ctrl-btn">
            <span>💾</span> Export Markdown
          </button>
          <button id="btn-regen-report" class="ctrl-btn" style="border-color:var(--accent-cyan); color:var(--accent-cyan);">
            <span>↻</span> Regenerate Report
          </button>
        </div>
      </div>

      <div class="report-content-body">
        ${finalHtml}
      </div>
    `;

    // Export button
    const expBtn = this.container.querySelector('#btn-export-report');
    if (expBtn) {
      expBtn.addEventListener('click', () => {
        const blob = new Blob([this.report.content_markdown], { type: 'text/markdown' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `incident_autopsy_${this.report.incident_id}.md`;
        a.click();
      });
    }

    // Regen button
    const regenBtn = this.container.querySelector('#btn-regen-report');
    if (regenBtn) {
      regenBtn.addEventListener('click', () => {
        if (this.onGenerateFresh) this.onGenerateFresh();
      });
    }
  }
}
