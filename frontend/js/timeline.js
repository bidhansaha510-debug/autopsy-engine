// Timeline Rendering and Interactive Filter Component
export class TimelineComponent {
  constructor(containerId, onSelectEvent) {
    this.container = document.getElementById(containerId);
    this.onSelectEvent = onSelectEvent;
    this.events = [];
    this.activeFilter = 'ALL';
  }

  setEvents(events) {
    this.events = events || [];
    this.render();
  }

  setFilter(filterType) {
    this.activeFilter = filterType;
    this.render();
  }

  render() {
    if (!this.container) return;

    const filtered = this.events.filter((e) => {
      if (this.activeFilter === 'ALL') return true;
      return e.source_type === this.activeFilter;
    });

    if (filtered.length === 0) {
      this.container.innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          No timeline events recorded matching filter [${this.activeFilter}].
        </div>
      `;
      return;
    }

    const html = filtered
      .map((ev) => {
        const timeStr = new Date(ev.timestamp).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        });

        const raw = ev.raw_data || {};
        let summary = raw.message || raw.name || raw.config_key || ev.source_type;
        if (ev.source_type === 'CONFIG') {
          summary = `Config modified: ${raw.config_key} (${raw.old_value} → ${raw.new_value}) by ${raw.changed_by || 'operator'}`;
        } else if (ev.source_type === 'METRIC') {
          summary = `Metric observation: ${raw.name || 'metric'} = ${raw.value || (raw.samples && raw.samples[0] ? raw.samples[0].value : '')}`;
        } else if (ev.source_type === 'ALERT') {
          summary = `Alert triggered: ${raw.name} [${raw.severity}] - ${raw.condition || ''}`;
        }

        const traceBadge = raw.trace_id
          ? `<span class="badge badge-provenance">Trace: ${raw.trace_id}</span>`
          : '';

        const simBadge = ev.is_simulated
          ? `<span class="badge badge-simulated">SIM</span>`
          : '';

        return `
          <div class="timeline-event-card event-${ev.source_type}" data-event-id="${ev.id}">
            <div class="event-main">
              <span class="event-time">${timeStr}</span>
              <span class="badge badge-${ev.source_type.toLowerCase()}">${ev.source_type}</span>
              <span class="badge" style="background: rgba(255,255,255,0.06);">${ev.service}</span>
              <span class="event-desc">${summary}</span>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
              ${traceBadge}
              ${simBadge}
              <span class="badge badge-provenance" title="${ev.provenance?.fingerprint || ''}">${ev.provenance?.source || 'sys'}</span>
            </div>
          </div>
        `;
      })
      .join('');

    this.container.innerHTML = html;

    // Attach click events
    this.container.querySelectorAll('.timeline-event-card').forEach((card) => {
      card.addEventListener('click', () => {
        const id = card.dataset.eventId;
        const ev = this.events.find((e) => e.id === id);
        if (this.onSelectEvent && ev) this.onSelectEvent(ev);
      });
    });
  }
}
