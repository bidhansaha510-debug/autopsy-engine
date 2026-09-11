// Interactive SVG Topology Graph & Blast Radius Visualizer
export class TopologyComponent {
  constructor(containerId, onSelectNode) {
    this.container = document.getElementById(containerId);
    this.onSelectNode = onSelectNode;
    this.blastData = null;
  }

  setData(blastData) {
    this.blastData = blastData;
    this.render();
  }

  render() {
    if (!this.container || !this.blastData) return;

    const { nodes, edges, root_cause_service, propagation_path } = this.blastData;
    const width = this.container.clientWidth || 800;
    const height = 480;

    // Compute layout positions for nodes
    // tier-1 at left/top, tier-2 at right/bottom
    const nodePositions = {};
    const count = nodes.length;

    nodes.forEach((node, idx) => {
      // Stratify by name or tier
      let x = 120 + (idx * (width - 240) / Math.max(1, count - 1));
      let y = 240;

      if (node.name.includes('gateway') || node.name.includes('api')) {
        x = 100;
        y = 120;
      } else if (node.name.includes('checkout')) {
        x = width * 0.35;
        y = 200;
      } else if (node.name.includes('payment-service') || node.name === 'payment-service') {
        x = width * 0.65;
        y = 280;
      } else if (node.name.includes('db')) {
        x = width * 0.85;
        y = 360;
      } else if (node.name.includes('bank')) {
        x = width * 0.85;
        y = 180;
      }

      nodePositions[node.name] = { x, y, data: node };
    });

    // Render SVG lines for edges
    let edgesSvg = '';
    edges.forEach((e) => {
      const src = nodePositions[e.source];
      const tgt = nodePositions[e.target];
      if (!src || !tgt) return;

      const isPropagationEdge =
        propagation_path &&
        propagation_path.includes(e.source) &&
        propagation_path.includes(e.target);

      const edgeClass = isPropagationEdge ? 'edge-FAILING' : `edge-${e.status}`;

      edgesSvg += `
        <g class="edge-group">
          <line
            x1="${src.x}" y1="${src.y}"
            x2="${tgt.x}" y2="${tgt.y}"
            class="edge-path ${edgeClass}"
          />
          <text
            x="${(src.x + tgt.x) / 2}"
            y="${(src.y + tgt.y) / 2 - 8}"
            fill="var(--text-muted)"
            font-size="10"
            font-family="var(--font-mono)"
            text-anchor="middle"
          >${e.dependency_type}</text>
        </g>
      `;
    });

    // Render Nodes
    let nodesSvg = '';
    nodes.forEach((n) => {
      const pos = nodePositions[n.name];
      if (!pos) return;

      const isRoot = n.name === root_cause_service;
      const statusClass = n.status;
      const glowColor =
        statusClass === 'FAILED'
          ? '#ef4444'
          : statusClass === 'DEGRADED'
          ? '#f59e0b'
          : '#00f0ff';

      nodesSvg += `
        <g class="node-group" transform="translate(${pos.x - 70}, ${pos.y - 30})" data-node-name="${n.name}">
          <rect
            width="140" height="60"
            class="node-rect status-${statusClass}"
            filter="drop-shadow(0 4px 12px ${glowColor}33)"
          />
          ${isRoot ? `<circle cx="130" cy="10" r="5" fill="#ef4444"><animate attributeName="opacity" values="1;0.2;1" dur="1s" repeatCount="indefinite"/></circle>` : ''}
          <text x="14" y="24" fill="#fff" font-weight="700" font-size="12" font-family="var(--font-display)">${n.name}</text>
          <text x="14" y="42" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">${n.tier} • ${n.status}</text>
        </g>
      `;
    });

    this.container.innerHTML = `
      <svg class="topology-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
          </marker>
        </defs>
        ${edgesSvg}
        ${nodesSvg}
      </svg>
      <div style="position:absolute; bottom:14px; left:14px; font-size:11px; color:var(--text-muted); display:flex; gap:16px;">
        <span style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; background:#ef4444; border-radius:2px;"></span> Directly Affected / Origin</span>
        <span style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; background:#f59e0b; border-radius:2px;"></span> Indirect Caller Cascade</span>
        <span style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; background:#334155; border-radius:2px;"></span> Healthy / Unaffected</span>
      </div>
    `;

    this.container.querySelectorAll('.node-group').forEach((elem) => {
      elem.addEventListener('click', () => {
        const name = elem.dataset.nodeName;
        if (this.onSelectNode) this.onSelectNode(name);
      });
    });
  }
}
