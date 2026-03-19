import { useEffect, useRef } from 'react';
import { useScan } from '../store/scanStore';
import { TOOL_COLORS } from '../utils/constants';
import SeverityBadge from './SeverityBadge';

const AGENT_COLORS = {
  'hunter-injection': '#c084fc',
  'hunter-auth': '#FF6600',
  'hunter-config': '#00D4FF',
  'hunter-1': '#76B900',
  'hunter': '#76B900',
  'verifier': '#FFD600',
};

function AgentBadge({ agent }) {
  if (!agent || agent === 'hunter') return null;
  const color = AGENT_COLORS[agent] || '#76B900';
  const label = agent.replace('hunter-', '');
  return (
    <span
      className="text-[8px] uppercase tracking-wider font-bold px-1 py-0.5 rounded mr-1"
      style={{ color, border: `1px solid ${color}40` }}
    >
      {label}
    </span>
  );
}

function ToolCallCard({ call }) {
  const color = TOOL_COLORS[call.tool] || '#76B900';
  const isCmd = call.tool === 'run_command';

  const resultSummary = formatResult(call.tool, call.result);

  if (isCmd) {
    const cmd = call.args?.command || '';
    const stdout = call.result?.stdout || '';
    const preview = stdout.split('\n').slice(0, 6).join('\n');
    const lineCount = stdout.split('\n').length;

    return (
      <div className="mb-2 rounded border animate-slide-in"
           style={{ borderColor: color + '30', backgroundColor: '#12101a' }}>
        <div className="px-2 py-1.5 text-xs font-mono flex items-center" style={{ color }}>
          <AgentBadge agent={call.agent} />
          <span className="opacity-50">$</span> {cmd}
        </div>
        {preview && (
          <div className="px-2 pb-1.5 text-[10px] text-dimmed/80 font-mono whitespace-pre-wrap leading-tight max-h-32 overflow-hidden">
            {preview}
            {lineCount > 6 && (
              <div className="text-dimmed/40 mt-0.5">... ({lineCount} lines total)</div>
            )}
          </div>
        )}
      </div>
    );
  }

  const args = call.args || {};
  const argsStr = Object.entries(args)
    .map(([k, v]) => `--${k} "${v}"`)
    .join(' ');

  return (
    <div
      className="mb-2 p-2 rounded border animate-slide-in"
      style={{ borderColor: color + '40', backgroundColor: color + '08' }}
    >
      <div className="flex items-center gap-1 text-xs" style={{ color }}>
        <AgentBadge agent={call.agent} />
        <span className="opacity-60">$</span>
        <span className="font-bold">{call.tool}</span>
        <span className="text-dimmed text-[10px]">{argsStr}</span>
      </div>
      {resultSummary && (
        <div className="mt-1 text-[11px] text-nvidia/70 pl-3">
          {'\u2192'} {resultSummary}
        </div>
      )}
    </div>
  );
}

function ReasoningCard({ reasoning }) {
  const agentColor = AGENT_COLORS[reasoning.agent] || '#76B900';
  return (
    <div
      className="mb-2 px-2 py-1 text-[11px] italic animate-slide-in border-l-2"
      style={{ color: agentColor + '80', borderColor: agentColor + '30' }}
    >
      <AgentBadge agent={reasoning.agent} />
      {reasoning.text.length > 300 ? reasoning.text.slice(0, 300) + '...' : reasoning.text}
    </div>
  );
}

function FindingCard({ finding }) {
  return (
    <div className="mb-2 p-2 rounded border border-critical/30 bg-critical/5 animate-slide-in">
      <div className="flex items-center gap-2 text-xs">
        <span className="text-critical">{'\u26A0'} FINDING:</span>
        <span className="text-nvidia-bright">{finding.title}</span>
      </div>
      <div className="flex items-center gap-2 mt-1">
        <SeverityBadge severity={finding.severity} />
        {finding.cwe_id && (
          <span className="text-[10px] text-dimmed">{finding.cwe_id}</span>
        )}
        {finding.file && (
          <span className="text-[10px] text-dimmed">
            {finding.file}:{finding.line_start || finding.line || ''}
          </span>
        )}
      </div>
    </div>
  );
}

function formatResult(tool, result) {
  if (!result) return null;

  if (tool === 'cwe_lookup') {
    if (result.cwe_id) return `${result.cwe_id}: ${result.name}`;
    if (result.results) {
      return result.results
        .slice(0, 2)
        .map((r) => `${r.cwe_id}: ${r.name}`)
        .join(', ');
    }
    return result.error || 'No results';
  }

  if (tool === 'osv_query') {
    const vulns = result.vulnerabilities || [];
    if (vulns.length === 0) return 'No known vulnerabilities';
    return vulns
      .slice(0, 2)
      .map((v) => `${v.id} [${v.severity}] ${v.summary?.slice(0, 60)}`)
      .join('; ');
  }

  if (tool === 'web_search') {
    const results = result.results || [];
    if (results.length === 0) return 'No results';
    return results[0].snippet?.slice(0, 120) || results[0].title;
  }

  if (tool === 'run_command') {
    return null; // handled inline by ToolCallCard
  }

  if (tool === 'get_existing_findings') {
    const s = result.secrets?.length || 0;
    const c = result.dependency_cves?.length || 0;
    return `Already found: ${s} secrets, ${c} CVEs`;
  }

  return JSON.stringify(result).slice(0, 100);
}

export default function InvestigationFeed() {
  const { state } = useScan();
  const bottomRef = useRef(null);

  const items = [];

  // Interleave tool calls, reasoning, and findings by timestamp
  for (const tc of state.toolCalls) {
    items.push({ type: 'tool_call', data: tc, ts: tc.timestamp });
  }
  for (const r of state.reasoning) {
    items.push({ type: 'reasoning', data: r, ts: r.timestamp });
  }
  for (const f of state.hunterFindings) {
    items.push({ type: 'finding', data: f, ts: f.timestamp || '' });
  }

  items.sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [items.length]);

  if (items.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-dimmed text-xs">
        <div className="text-center">
          <div className="text-2xl mb-2 opacity-20">{'\u{1F50D}'}</div>
          <div>Investigation feed</div>
          <div className="text-[10px] mt-1 opacity-50">
            live tool calls appear here
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto p-2 text-xs">
      <div className="text-dimmed mb-2 uppercase tracking-wider text-[10px]">
        Hunter Agent Investigation
      </div>
      {items.map((item, i) => {
        if (item.type === 'tool_call') return <ToolCallCard key={`tc-${i}`} call={item.data} />;
        if (item.type === 'reasoning') return <ReasoningCard key={`r-${i}`} reasoning={item.data} />;
        if (item.type === 'finding') return <FindingCard key={`f-${i}`} finding={item.data} />;
        return null;
      })}
      <div ref={bottomRef} />
    </div>
  );
}
