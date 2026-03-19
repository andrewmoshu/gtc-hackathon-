import { useEffect, useRef, useState, useCallback } from 'react';
import { useScan } from '../store/scanStore';
import { SEVERITY_COLORS } from '../utils/constants';

const NODE_RADIUS = 10;
const HIT_RADIUS = 20;

function forceLayout(nodes, edges, width, height, iterations = 100) {
  const cx = width / 2;
  const cy = height / 2;
  const padding = 70;

  // Group by directory for initial placement
  const dirGroups = {};
  nodes.forEach((n) => {
    const dir = n.full_path?.includes('/')
      ? n.full_path.split('/').slice(0, -1).join('/')
      : '/';
    if (!dirGroups[dir]) dirGroups[dir] = [];
    dirGroups[dir].push(n);
  });

  const dirs = Object.keys(dirGroups);
  dirs.forEach((dir, di) => {
    const angle = (2 * Math.PI * di) / Math.max(dirs.length, 1);
    const clusterR = Math.min(width, height) * 0.28;
    const clusterCx = cx + clusterR * Math.cos(angle);
    const clusterCy = cy + clusterR * Math.sin(angle);
    dirGroups[dir].forEach((n, ni) => {
      const subAngle = (2 * Math.PI * ni) / Math.max(dirGroups[dir].length, 1);
      const subR = 15 + dirGroups[dir].length * 6;
      n.x = clusterCx + subR * Math.cos(subAngle);
      n.y = clusterCy + subR * Math.sin(subAngle);
      n.vx = 0;
      n.vy = 0;
    });
  });

  const edgeSet = new Set(edges.map((e) => `${e.from}|${e.to}`));

  for (let iter = 0; iter < iterations; iter++) {
    const alpha = 1 - iter / iterations;

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (1200 * alpha) / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        nodes[i].vx -= fx;
        nodes[i].vy -= fy;
        nodes[j].vx += fx;
        nodes[j].vy += fy;
      }
    }

    for (const edge of edges) {
      const a = nodes.find((n) => n.id === edge.from);
      const b = nodes.find((n) => n.id === edge.to);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = dist * 0.004 * alpha;
      nodes.forEach((n) => {
        if (n === a) { n.vx += (dx / dist) * force; n.vy += (dy / dist) * force; }
        if (n === b) { n.vx -= (dx / dist) * force; n.vy -= (dy / dist) * force; }
      });
    }

    for (const n of nodes) {
      n.vx += (cx - n.x) * 0.003 * alpha;
      n.vy += (cy - n.y) * 0.003 * alpha;
      n.vx *= 0.75;
      n.vy *= 0.75;
      n.x += n.vx;
      n.y += n.vy;
      n.x = Math.max(padding, Math.min(width - padding, n.x));
      n.y = Math.max(padding, Math.min(height - padding, n.y));
    }
  }

  return nodes;
}

export default function AttackGraph() {
  const { state } = useScan();
  const canvasRef = useRef(null);
  const nodesRef = useRef([]);
  const edgesRef = useRef([]);
  const animationRef = useRef(null);
  const hoveredRef = useRef(null);
  const [tooltip, setTooltip] = useState(null);

  useEffect(() => {
    const { nodes, edges } = state.graphData;
    if (nodes.length === 0) return;

    const container = canvasRef.current?.parentElement;
    if (!container) return;
    const width = container.clientWidth;
    const height = container.clientHeight;

    const canvas = canvasRef.current;
    canvas.width = width * 2;
    canvas.height = height * 2;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';

    const laid = forceLayout(nodes.map((n) => ({ ...n })), edges, width, height);
    nodesRef.current = laid;
    edgesRef.current = edges;

    let frame = 0;
    const draw = () => {
      const ctx = canvas.getContext('2d');
      ctx.setTransform(2, 0, 0, 2, 0, 0);
      ctx.clearRect(0, 0, width, height);
      frame++;

      const hovered = hoveredRef.current;
      const highlightIds = new Set();
      if (hovered) {
        highlightIds.add(hovered.id);
        for (const e of edgesRef.current) {
          if (e.from === hovered.id) highlightIds.add(e.to);
          if (e.to === hovered.id) highlightIds.add(e.from);
        }
      }
      const dimming = highlightIds.size > 0;

      // Edges
      for (const edge of edgesRef.current) {
        const from = nodesRef.current.find((n) => n.id === edge.from);
        const to = nodesRef.current.find((n) => n.id === edge.to);
        if (!from || !to) continue;

        const isHl = highlightIds.has(edge.from) && highlightIds.has(edge.to);
        const edgeColor = edge.label === 'data flow' ? '#00D4FF' : '#76B900';
        const opacity = dimming ? (isHl ? 'aa' : '10') : '35';

        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.strokeStyle = `${edgeColor}${opacity}`;
        ctx.lineWidth = isHl ? 2 : 1;
        ctx.stroke();

        // Arrow
        const angle = Math.atan2(to.y - from.y, to.x - from.x);
        const midX = (from.x + to.x) / 2;
        const midY = (from.y + to.y) / 2;
        ctx.beginPath();
        ctx.moveTo(midX + 7 * Math.cos(angle), midY + 7 * Math.sin(angle));
        ctx.lineTo(midX - 7 * Math.cos(angle - 0.5), midY - 7 * Math.sin(angle - 0.5));
        ctx.lineTo(midX - 7 * Math.cos(angle + 0.5), midY - 7 * Math.sin(angle + 0.5));
        ctx.fillStyle = `${edgeColor}${opacity}`;
        ctx.fill();

        if (isHl && edge.label) {
          ctx.font = '9px JetBrains Mono, monospace';
          ctx.fillStyle = `${edgeColor}90`;
          ctx.textAlign = 'center';
          ctx.fillText(edge.label, midX, midY - 8);
        }
      }

      // Nodes
      for (const node of nodesRef.current) {
        const isHov = hovered?.id === node.id;
        const isConn = highlightIds.has(node.id);
        const sevColor = SEVERITY_COLORS[node.vulnSeverity] || '#76B900';
        const nodeOpacity = dimming && !isConn ? 0.12 : 1;
        const r = NODE_RADIUS + Math.min(node.vulnCount || 1, 5) * 1.5 + (isHov ? 3 : 0);

        ctx.globalAlpha = nodeOpacity;

        // Pulsing glow
        const glowSize = r + 10 + 4 * Math.sin(frame * 0.04);
        ctx.beginPath();
        ctx.arc(node.x, node.y, glowSize, 0, Math.PI * 2);
        const gradient = ctx.createRadialGradient(node.x, node.y, r, node.x, node.y, glowSize);
        gradient.addColorStop(0, sevColor + '30');
        gradient.addColorStop(1, sevColor + '00');
        ctx.fillStyle = gradient;
        ctx.fill();

        // Hover ring
        if (isHov) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
          ctx.strokeStyle = sevColor + '50';
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fillStyle = sevColor;
        ctx.fill();

        // Inner dot
        ctx.beginPath();
        ctx.arc(node.x, node.y, r * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#0a0a0a';
        ctx.fill();

        // Vuln count
        if (node.vulnCount > 1) {
          ctx.font = 'bold 9px JetBrains Mono, monospace';
          ctx.fillStyle = '#fff';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(node.vulnCount, node.x, node.y);
          ctx.textBaseline = 'alphabetic';
        }

        // Label
        ctx.font = `${isHov ? '11' : '9'}px JetBrains Mono, monospace`;
        ctx.fillStyle = isHov ? sevColor : sevColor + '90';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + r + 14);

        ctx.globalAlpha = 1;
      }

      animationRef.current = requestAnimationFrame(draw);
    };

    draw();
    return () => { if (animationRef.current) cancelAnimationFrame(animationRef.current); };
  }, [state.graphData]);

  const findNodeAt = useCallback((e) => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    for (const node of nodesRef.current) {
      const dx = node.x - mx;
      const dy = node.y - my;
      if (dx * dx + dy * dy < HIT_RADIUS * HIT_RADIUS) return node;
    }
    return null;
  }, []);

  const handleMouseMove = useCallback((e) => {
    const node = findNodeAt(e);
    hoveredRef.current = node;
    canvasRef.current.style.cursor = node ? 'pointer' : 'default';
    if (node) {
      const rect = canvasRef.current.getBoundingClientRect();
      setTooltip({ x: e.clientX - rect.left, y: e.clientY - rect.top, node });
    } else {
      setTooltip(null);
    }
  }, [findNodeAt]);

  const handleMouseLeave = useCallback(() => {
    hoveredRef.current = null;
    setTooltip(null);
  }, []);

  if (state.graphData.nodes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-dimmed text-xs">
        <div className="text-center">
          <div className="text-3xl mb-2 opacity-20">{'\u{1F578}'}</div>
          <div>Attack surface graph</div>
          <div className="text-[10px] mt-1 opacity-50">builds from findings</div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full relative overflow-hidden">
      <canvas
        ref={canvasRef}
        className="w-full h-full"
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
      />

      {/* Header */}
      <div className="absolute top-2 left-3 text-[10px] text-dimmed flex items-center gap-3">
        <span className="uppercase tracking-wider">Vulnerability Map</span>
        <span className="text-nvidia">{state.graphData.nodes.length} files affected</span>
        {state.graphData.edges.length > 0 && (
          <span className="text-cyan">{state.graphData.edges.length} connections</span>
        )}
      </div>

      {/* Legend */}
      <div className="absolute bottom-2 left-3 flex items-center gap-3 text-[9px] text-dimmed">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <span key={sev} className="flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
            {sev.toLowerCase()}
          </span>
        ))}
        <span className="flex items-center gap-1">
          <span className="inline-block w-2 h-0.5 bg-cyan" /> data flow
        </span>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute pointer-events-none z-10 bg-surface border border-border rounded px-3 py-2 text-xs max-w-72 shadow-lg"
          style={{ left: tooltip.x + 16, top: tooltip.y - 10 }}
        >
          <div className="text-nvidia-bright font-bold text-[11px]">{tooltip.node.full_path}</div>
          <div className="mt-1.5 space-y-1">
            {(tooltip.node.findings || []).map((f, i) => (
              <div key={i} className="flex items-center gap-2">
                <span
                  className="text-[9px] font-bold uppercase px-1 rounded"
                  style={{ color: SEVERITY_COLORS[f.severity], border: `1px solid ${SEVERITY_COLORS[f.severity]}40` }}
                >
                  {f.severity}
                </span>
                <span className="text-[10px] text-dimmed truncate">{f.title}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
