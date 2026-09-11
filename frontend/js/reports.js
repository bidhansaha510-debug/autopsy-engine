// Interactive Forensic Post-Mortem Component with Live Markdown Editing & Sharing
import { Api } from './api.js';

export class ReportsComponent {
  constructor(containerId, onGenerateFresh) {
    this.container = document.getElementById(containerId);
    this.onGenerateFresh = onGenerateFresh;
    this.report = null;
    this.isEditing = false;
    this.editedMarkdown = '';
  }

  setReport(rep) {
    this.report = rep;
    this.editedMarkdown = rep ? rep.content_markdown : '';
    this.isEditing = false;
    this.render();
  }

  render() {
    if (!this.container) return;

    if (!this.report) {
      this.container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          No post-mortem report generated yet. Run investigation or click Regenerate.
        </div>
      `;
      return;
    }

    if (this.isEditing) {
      this.renderEditor();
    } else {
      this.renderViewer();
    }
  }

  renderViewer() {
    const md = this.report.content_markdown || '';
    const finalHtml = this.parseMarkdownToHtml(md);

    this.container.innerHTML = `
      <div style="margin-bottom:16px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-weight:700; color:#fff; font-size:14px;">Evidence-Backed Incident Report</span>
          <span class="badge badge-resolved">AUDITED FORENSIC RECORD</span>
          <span id="report-share-toast" style="display:none; color:var(--accent-cyan); font-size:12px; font-weight:600; padding:2px 8px; border-radius:4px; background:rgba(0,240,255,0.1);">
            ✓ Link copied!
          </span>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <button id="btn-edit-report" class="ctrl-btn" style="border-color:var(--accent-cyan); color:var(--accent-cyan);">
            <span>✏️</span> Edit Post-Mortem Draft
          </button>
          <button id="btn-share-report" class="ctrl-btn" style="border-color:var(--accent-magenta); color:var(--accent-magenta);">
            <span>🔗</span> Share Link
          </button>
          <button id="btn-export-report" class="ctrl-btn">
            <span>💾</span> Export Markdown
          </button>
          <button id="btn-regen-report" class="ctrl-btn">
            <span>↻</span> Regenerate
          </button>
        </div>
      </div>

      <div class="report-content-body glass-card" style="padding:24px; line-height:1.7;">
        ${finalHtml}
      </div>
    `;

    // Bind Buttons
    const editBtn = this.container.querySelector('#btn-edit-report');
    if (editBtn) {
      editBtn.addEventListener('click', () => {
        this.isEditing = true;
        this.editedMarkdown = this.report.content_markdown || '';
        this.render();
      });
    }

    const shareBtn = this.container.querySelector('#btn-share-report');
    if (shareBtn) {
      shareBtn.addEventListener('click', () => {
        const shareUrl = `${window.location.origin}${window.location.pathname}?incident=${this.report.incident_id}&view=reports`;
        navigator.clipboard.writeText(shareUrl).then(() => {
          const toast = this.container.querySelector('#report-share-toast');
          if (toast) {
            toast.style.display = 'inline-block';
            setTimeout(() => {
              toast.style.display = 'none';
            }, 2500);
          }
        }).catch(() => {
          prompt('Copy Post-Mortem Share Link:', shareUrl);
        });
      });
    }

    const expBtn = this.container.querySelector('#btn-export-report');
    if (expBtn) {
      expBtn.addEventListener('click', () => {
        const blob = new Blob([this.report.content_markdown], { type: 'text/markdown' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `incident_postmortem_${this.report.incident_id}.md`;
        a.click();
      });
    }

    const regenBtn = this.container.querySelector('#btn-regen-report');
    if (regenBtn) {
      regenBtn.addEventListener('click', () => {
        if (this.onGenerateFresh) this.onGenerateFresh();
      });
    }
  }

  renderEditor() {
    this.container.innerHTML = `
      <div style="margin-bottom:16px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-weight:700; color:var(--accent-cyan); font-size:14px;">Post-Mortem Draft Editor</span>
          <span class="badge badge-simulated">UNSAVED REVISIONS</span>
        </div>
        <div style="display:flex; gap:8px;">
          <button id="btn-save-report" class="ctrl-btn" style="background:rgba(0,240,255,0.15); border-color:var(--accent-cyan); color:var(--accent-cyan); font-weight:700;">
            <span>💾</span> Save Revisions
          </button>
          <button id="btn-cancel-edit" class="ctrl-btn" style="border-color:#64748b; color:#94a3b8;">
            <span>✕</span> Cancel
          </button>
        </div>
      </div>

      <!-- Quick Markdown Formatting Toolbar -->
      <div style="margin-bottom:10px; display:flex; gap:6px; flex-wrap:wrap; padding:8px 12px; background:rgba(15,23,42,0.8); border:1px solid var(--border-color); border-radius:6px;">
        <button class="md-tool-btn" data-wrap="**" data-placeholder="bold text"><strong>B</strong></button>
        <button class="md-tool-btn" data-wrap="*" data-placeholder="italic text"><em>I</em></button>
        <button class="md-tool-btn" data-prefix="## " data-placeholder="Heading">H2</button>
        <button class="md-tool-btn" data-prefix="### " data-placeholder="Subheading">H3</button>
        <button class="md-tool-btn" data-prefix="- " data-placeholder="List item">List</button>
        <button class="md-tool-btn" data-prefix="[EVID-XXX] " data-placeholder="[EVID-XXX]">Evidence Tag</button>
        <button class="md-tool-btn" data-snippet="| Service | Observation | Confidence |\n|---|---|---|\n| payment-service | Connection pool saturated | 0.98 |">Table</button>
      </div>

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px; height:600px;">
        <div style="display:flex; flex-direction:column; height:100%;">
          <div style="font-size:12px; color:var(--text-muted); margin-bottom:6px; font-weight:600;">MARKDOWN EDITOR (EDIT HERE)</div>
          <textarea id="report-editor-textarea" style="flex:1; width:100%; height:100%; background:rgba(10,15,28,0.95); color:#f1f5f9; font-family:'JetBrains Mono', monospace; font-size:13px; line-height:1.6; padding:16px; border:1px solid var(--border-color); border-radius:8px; resize:none; outline:none;">${this.editedMarkdown}</textarea>
        </div>
        <div style="display:flex; flex-direction:column; height:100%;">
          <div style="font-size:12px; color:var(--accent-cyan); margin-bottom:6px; font-weight:600;">LIVE PREVIEW</div>
          <div id="report-preview-container" class="report-content-body glass-card" style="flex:1; height:100%; overflow-y:auto; padding:16px; border:1px solid var(--border-color); border-radius:8px; line-height:1.7;">
            ${this.parseMarkdownToHtml(this.editedMarkdown)}
          </div>
        </div>
      </div>
    `;

    const textarea = this.container.querySelector('#report-editor-textarea');
    const preview = this.container.querySelector('#report-preview-container');

    if (textarea && preview) {
      textarea.addEventListener('input', (e) => {
        this.editedMarkdown = e.target.value;
        preview.innerHTML = this.parseMarkdownToHtml(this.editedMarkdown);
      });

      // Quick toolbar buttons
      this.container.querySelectorAll('.md-tool-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          const wrap = btn.dataset.wrap;
          const prefix = btn.dataset.prefix;
          const snippet = btn.dataset.snippet;
          const start = textarea.selectionStart;
          const end = textarea.selectionEnd;
          const val = textarea.value;

          let inserted = '';
          if (snippet) {
            inserted = snippet;
          } else if (wrap) {
            const sel = val.substring(start, end) || btn.dataset.placeholder;
            inserted = `${wrap}${sel}${wrap}`;
          } else if (prefix) {
            inserted = `\n${prefix}${val.substring(start, end) || btn.dataset.placeholder}\n`;
          }

          textarea.value = val.substring(0, start) + inserted + val.substring(end);
          this.editedMarkdown = textarea.value;
          preview.innerHTML = this.parseMarkdownToHtml(this.editedMarkdown);
          textarea.focus();
        });
      });
    }

    // Save Button
    const saveBtn = this.container.querySelector('#btn-save-report');
    if (saveBtn) {
      saveBtn.addEventListener('click', async () => {
        saveBtn.disabled = true;
        saveBtn.innerText = 'Saving...';
        try {
          const updated = await Api.updateReport(this.report.id, {
            content_markdown: this.editedMarkdown,
          });
          this.report = updated;
          this.isEditing = false;
          this.render();
        } catch (err) {
          alert(`Failed to save report: ${err.message}`);
          saveBtn.disabled = false;
          saveBtn.innerText = '💾 Save Revisions';
        }
      });
    }

    // Cancel Button
    const cancelBtn = this.container.querySelector('#btn-cancel-edit');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        this.isEditing = false;
        this.editedMarkdown = this.report.content_markdown || '';
        this.render();
      });
    }
  }

  parseMarkdownToHtml(md) {
    if (!md) return '<div style="color:var(--text-muted);">Empty report content.</div>';

    // Parse tables first
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
          // skip delimiter line if next line has dashes
          if (i + 1 < lines.length && lines[i + 1].includes('---')) {
            i++;
          }
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

    return processedLines
      .join('\n')
      .replace(/^# (.*$)/gim, '<h1 style="color:#fff; border-bottom:1px solid var(--border-color); padding-bottom:8px; margin-top:20px;">$1</h1>')
      .replace(/^## (.*$)/gim, '<h2 style="color:var(--accent-cyan); margin-top:24px; margin-bottom:10px;">$1</h2>')
      .replace(/^### (.*$)/gim, '<h3 style="color:#e2e8f0; margin-top:16px; margin-bottom:8px;">$1</h3>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
      .replace(/`([^`]+)`/gim, '<code style="background:rgba(0,240,255,0.1); color:var(--accent-cyan); padding:2px 6px; border-radius:4px; font-size:12px;">$1</code>')
      .replace(/\[(EVID-[A-Z0-9_-]+)\]/gim, '<span class="badge badge-evidence" style="margin:0 2px;">$1</span>')
      .replace(/^- \[(x| )\] (.*$)/gim, '<div style="display:flex; gap:8px; align-items:center; margin-bottom:4px;"><input type="checkbox" disabled checked/> <span>$2</span></div>')
      .replace(/^- (.*$)/gim, '<li style="margin-left:20px; color:#cbd5e1;">$1</li>')
      .replace(/\n\n/gim, '<br/><br/>');
  }
}
