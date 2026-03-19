import { useState, useEffect } from 'react';
import { useScan } from '../store/scanStore';
import { useSSE } from '../hooks/useSSE';
import { API_BASE } from '../utils/constants';

export default function TopBar() {
  const { state, dispatch } = useScan();
  const { startScan } = useSSE(dispatch);
  const [repoUrl, setRepoUrl] = useState('');
  const [suggestions, setSuggestions] = useState([]);

  useEffect(() => {
    fetch(`${API_BASE}/api/repos/suggested`)
      .then((r) => r.json())
      .then((d) => setSuggestions(d.repos || []))
      .catch(() => {});
  }, []);

  const handleScan = () => {
    if (!repoUrl.trim()) return;
    startScan(repoUrl.trim());
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleScan();
  };

  const isScanning = state.status === 'scanning';

  return (
    <div className="border-b border-border px-4 py-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 shrink-0">
          <span className="font-display text-2xl font-bold text-nvidia glow-strong tracking-wide">
            CodeSentinel
          </span>
          <span className="text-dimmed text-xs hidden sm:inline">
            Not a scanner. A researcher.
          </span>
        </div>

        <div className="flex items-center gap-2 flex-1 max-w-2xl">
          <span className="text-dimmed text-sm shrink-0">git:</span>
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://github.com/owner/repo.git"
            disabled={isScanning}
            className="flex-1 bg-surface border border-border rounded px-3 py-1.5 text-sm text-nvidia
                       placeholder:text-dimmed/50 focus:outline-none focus:border-nvidia/50
                       disabled:opacity-50 font-mono"
          />
          <button
            onClick={handleScan}
            disabled={isScanning || !repoUrl.trim()}
            className="px-4 py-1.5 bg-nvidia/10 border border-nvidia/30 rounded text-nvidia text-sm
                       font-bold uppercase tracking-wider hover:bg-nvidia/20 hover:border-nvidia/50
                       disabled:opacity-30 disabled:cursor-not-allowed transition-all
                       hover:shadow-[0_0_12px_rgba(118,185,0,0.3)]"
          >
            {isScanning ? 'SCANNING...' : '\u25B6 SCAN'}
          </button>
        </div>

        <div className="text-xs text-dimmed shrink-0 hidden md:block">
          {state.status === 'idle' && 'READY'}
          {isScanning && (
            <span className="text-nvidia animate-pulse-glow">
              {state.currentLayer ? state.currentLayer.toUpperCase() : 'INITIALIZING'}
            </span>
          )}
          {state.status === 'complete' && (
            <span className="text-nvidia-bright">COMPLETE</span>
          )}
        </div>
      </div>

      {state.status === 'idle' && suggestions.length > 0 && (
        <div className="flex gap-2 mt-2 ml-[180px]">
          <span className="text-dimmed text-xs">try:</span>
          {suggestions.map((s) => (
            <button
              key={s.url}
              onClick={() => setRepoUrl(s.url)}
              className="text-xs text-nvidia/60 hover:text-nvidia underline decoration-dotted
                         underline-offset-2 cursor-pointer"
            >
              {s.name}
            </button>
          ))}
        </div>
      )}

      {isScanning && state.statusMessage && (
        <div className="mt-2 text-xs text-nvidia/70 ml-[180px]">
          &gt; {state.statusMessage}
        </div>
      )}
    </div>
  );
}
