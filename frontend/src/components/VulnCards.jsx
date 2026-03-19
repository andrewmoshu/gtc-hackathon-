import { useState, useMemo } from 'react';
import { useScan } from '../store/scanStore';
import SeverityBadge from './SeverityBadge';
import VulnDetail from './VulnDetail';
import { SEVERITY_ORDER, SEVERITY_COLORS } from '../utils/constants';

const SOURCE_CONFIG = {
  secrets: { label: 'Secrets', icon: '\u{1F511}', color: '#FF6600' },
  osv: { label: 'CVEs', icon: '\u{1F4E6}', color: '#FFD600' },
  code: { label: 'Code Vulns', icon: '\u{1F41B}', color: '#FF0033' },
  config: { label: 'Config', icon: '\u{1F433}', color: '#00D4FF' },
};

export default function VulnCards() {
  const { state } = useScan();
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [filter, setFilter] = useState('all');

  const allFindings = state.findings;
  const patches = state.patches;

  const sorted = useMemo(() => {
    return [...allFindings].sort(
      (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
    );
  }, [allFindings]);

  const grouped = useMemo(() => {
    const groups = {};
    for (const f of allFindings) {
      const src = f.source || 'code';
      if (!groups[src]) groups[src] = [];
      groups[src].push(f);
    }
    return groups;
  }, [allFindings]);

  const filtered = useMemo(() => {
    const list = filter === 'all' ? sorted : (grouped[filter] || []);
    return list;
  }, [filter, sorted, grouped]);

  const patchMap = useMemo(() => {
    const map = {};
    for (const p of patches) {
      map[p.vuln_id] = p;
    }
    return map;
  }, [patches]);

  if (allFindings.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-dimmed text-xs">
        <div className="text-center">
          {state.status === 'scanning' ? (
            <>
              <div className="text-2xl mb-2 opacity-30 animate-pulse-glow">{'\u{1F50D}'}</div>
              <div>Scanning for vulnerabilities...</div>
            </>
          ) : (
            <>
              <div className="text-2xl mb-2 opacity-20">{'\u{1F6E1}'}</div>
              <div>No findings yet</div>
            </>
          )}
        </div>
      </div>
    );
  }

  // Severity summary counts
  const severityCounts = {};
  for (const f of allFindings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header with severity summary + source filters */}
      <div className="px-3 pt-2 pb-1.5 border-b border-border shrink-0">
        {/* Severity overview */}
        <div className="flex items-center gap-3 mb-2">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
            const count = severityCounts[sev] || 0;
            if (count === 0) return null;
            return (
              <div key={sev} className="flex items-center gap-1.5">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: SEVERITY_COLORS[sev] }}
                />
                <span className="text-[10px] uppercase" style={{ color: SEVERITY_COLORS[sev] }}>
                  {count} {sev}
                </span>
              </div>
            );
          })}
        </div>

        {/* Source filters */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => setFilter('all')}
            className={`px-2 py-0.5 rounded text-[10px] uppercase tracking-wider transition-colors ${
              filter === 'all'
                ? 'bg-nvidia/15 text-nvidia'
                : 'text-dimmed hover:text-nvidia/60'
            }`}
          >
            All ({allFindings.length})
          </button>
          {Object.entries(SOURCE_CONFIG).map(([src, cfg]) => {
            const count = grouped[src]?.length || 0;
            if (count === 0) return null;
            return (
              <button
                key={src}
                onClick={() => setFilter(src)}
                className={`px-2 py-0.5 rounded text-[10px] uppercase tracking-wider transition-colors ${
                  filter === src
                    ? 'text-nvidia'
                    : 'text-dimmed hover:text-nvidia/60'
                }`}
                style={filter === src ? { backgroundColor: cfg.color + '15' } : {}}
              >
                {cfg.icon} {cfg.label} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings list — table-like rows instead of cards grid */}
      <div className="flex-1 overflow-y-auto">
        {filtered.map((f, i) => {
          const srcCfg = SOURCE_CONFIG[f.source] || SOURCE_CONFIG.code;
          const hasPatch = !!patchMap[f.id];
          return (
            <div
              key={f.id || i}
              onClick={() => setSelectedVuln(f)}
              className="flex items-center gap-3 px-3 py-2.5 border-b border-border/50
                         cursor-pointer transition-all hover:bg-surface/60 animate-slide-in"
              style={{ borderLeftWidth: '3px', borderLeftColor: srcCfg.color }}
            >
              {/* Severity */}
              <div className="shrink-0 w-16">
                <SeverityBadge severity={f.severity} />
              </div>

              {/* Source icon */}
              <span className="text-sm shrink-0 w-6 text-center opacity-60">
                {srcCfg.icon}
              </span>

              {/* Title + description */}
              <div className="flex-1 min-w-0">
                <div className="text-xs text-nvidia-bright font-medium truncate">
                  {f.title}
                </div>
                {f.description && (
                  <div className="text-[10px] text-dimmed/70 truncate mt-0.5">
                    {f.description.slice(0, 120)}
                  </div>
                )}
              </div>

              {/* File location */}
              <div className="text-[10px] text-dimmed shrink-0 text-right max-w-32 truncate">
                {f.file}
                {f.line ? `:${f.line}` : f.line_start ? `:${f.line_start}` : ''}
              </div>

              {/* Patch indicator */}
              {hasPatch && (
                <span className="text-[9px] text-nvidia border border-nvidia/30 rounded px-1.5 py-0.5 shrink-0">
                  FIX
                </span>
              )}

              {/* CWE badge */}
              {f.cwe_id && (
                <span className="text-[9px] text-dimmed border border-border rounded px-1.5 py-0.5 shrink-0">
                  {f.cwe_id}
                </span>
              )}

              {/* Arrow */}
              <span className="text-dimmed text-xs shrink-0">{'\u203A'}</span>
            </div>
          );
        })}
      </div>

      {/* Detail modal */}
      {selectedVuln && (
        <VulnDetail
          finding={selectedVuln}
          patch={patchMap[selectedVuln.id]}
          toolCalls={state.toolCalls}
          onClose={() => setSelectedVuln(null)}
        />
      )}
    </div>
  );
}
