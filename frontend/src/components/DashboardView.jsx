import { useState } from 'react';
import { useScan } from '../store/scanStore';
import { API_BASE } from '../utils/constants';
import FileTree from './FileTree';
import AttackGraph from './AttackGraph';
import InvestigationFeed from './InvestigationFeed';
import VulnCards from './VulnCards';

async function downloadReport(state) {
  try {
    // Capture the attack graph canvas as PNG
    let graphImage = '';
    const canvas = document.querySelector('canvas');
    if (canvas) {
      graphImage = canvas.toDataURL('image/png');
    }

    const res = await fetch(`${API_BASE}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        findings: state.findings,
        patches: state.patches,
        summary: state.summary,
        repo_url: state.summary?.repo_url || '',
        graph_image: graphImage,
      }),
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = res.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || 'codesentinel-report.pdf';
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    console.error('Report download failed:', e);
  }
}

function TopBar() {
  const { state } = useScan();
  const { summary, findings, status, currentLayer, statusMessage } = state;
  const isScanning = status === 'scanning';

  return (
    <div className="border-b border-border px-4 py-2 flex items-center gap-4 shrink-0">
      <span className="font-display text-lg font-bold text-nvidia glow tracking-wide">
        CodeSentinel
      </span>

      <div className="h-4 w-px bg-border" />

      {/* Live stats */}
      <div className="flex items-center gap-4 text-xs">
        <div>
          <span className="text-nvidia glow text-base font-bold">{findings.length}</span>
          <span className="text-dimmed ml-1">findings</span>
        </div>
        {summary && (
          <>
            {summary.by_source?.secrets > 0 && (
              <div className="text-dimmed">
                secrets: <span className="text-high">{summary.by_source.secrets}</span>
              </div>
            )}
            {summary.by_source?.osv > 0 && (
              <div className="text-dimmed">
                CVEs: <span className="text-medium">{summary.by_source.osv}</span>
              </div>
            )}
            {summary.by_source?.code > 0 && (
              <div className="text-dimmed">
                code: <span className="text-critical">{summary.by_source.code}</span>
              </div>
            )}
            {summary.patches_generated > 0 && (
              <div className="text-dimmed">
                patches: <span className="text-nvidia">{summary.patches_generated}</span>
              </div>
            )}
          </>
        )}
      </div>

      <div className="ml-auto flex items-center gap-3 text-xs">
        {isScanning && (
          <span className="text-nvidia animate-pulse-glow">
            {currentLayer?.toUpperCase() || 'SCANNING'}
            {statusMessage && (
              <span className="text-dimmed ml-2">{statusMessage}</span>
            )}
          </span>
        )}
        {status === 'complete' && summary && (
          <>
            <span className="text-dimmed">
              {summary.files_scanned} files in{' '}
              <span className="text-nvidia-bright">{summary.duration_seconds}s</span>
            </span>
            <button
              onClick={() => downloadReport(state)}
              className="px-3 py-1 bg-nvidia/10 border border-nvidia/30 rounded text-nvidia
                         text-[10px] font-bold uppercase tracking-wider hover:bg-nvidia/20
                         hover:border-nvidia/50 transition-all"
            >
              Export Report
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default function DashboardView() {
  const [activeTab, setActiveTab] = useState('findings');
  const { state } = useScan();

  const hasGraph = state.graphData.nodes.length > 0;

  return (
    <div className="h-full flex flex-col">
      <TopBar />

      <div className="flex-1 flex min-h-0">
        {/* Left sidebar: File Tree */}
        <div className="w-48 shrink-0 border-r border-border overflow-hidden">
          <FileTree />
        </div>

        {/* Center: Tabbed content (Findings / Attack Graph) */}
        <div className="flex-1 flex flex-col min-w-0 border-r border-border">
          {/* Tabs */}
          <div className="flex items-center gap-1 px-3 py-1.5 border-b border-border shrink-0">
            <button
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1 rounded text-xs uppercase tracking-wider transition-colors ${
                activeTab === 'findings'
                  ? 'bg-nvidia/15 text-nvidia'
                  : 'text-dimmed hover:text-nvidia/60'
              }`}
            >
              Findings ({state.findings.length})
            </button>
            <button
              onClick={() => setActiveTab('graph')}
              className={`px-3 py-1 rounded text-xs uppercase tracking-wider transition-colors ${
                activeTab === 'graph'
                  ? 'bg-nvidia/15 text-nvidia'
                  : 'text-dimmed hover:text-nvidia/60'
              }`}
            >
              Attack Graph
              {hasGraph && (
                <span className="ml-1 text-dimmed">
                  ({state.graphData.nodes.length})
                </span>
              )}
            </button>
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-hidden">
            {activeTab === 'findings' && <VulnCards />}
            {activeTab === 'graph' && <AttackGraph />}
          </div>
        </div>

        {/* Right: Investigation Feed */}
        <div className="w-80 shrink-0 overflow-hidden">
          <InvestigationFeed />
        </div>
      </div>
    </div>
  );
}
