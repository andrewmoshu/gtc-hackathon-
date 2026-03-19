import { useState, useEffect } from 'react';
import { useScan } from '../store/scanStore';
import { useSSE } from '../hooks/useSSE';
import { API_BASE } from '../utils/constants';

export default function LandingPage() {
  const { dispatch } = useScan();
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

  return (
    <div className="h-full flex flex-col items-center justify-center px-4">
      {/* Logo */}
      <div className="mb-2">
        <h1 className="font-display text-6xl font-bold text-nvidia glow-strong tracking-wide">
          CodeSentinel
        </h1>
      </div>
      <p className="text-dimmed text-sm mb-10 tracking-wide">
        Not a scanner. A researcher.
      </p>

      {/* Search box */}
      <div className="w-full max-w-2xl">
        <div className="flex items-center gap-2 bg-surface border border-border rounded-lg px-4 py-3
                        focus-within:border-nvidia/40 transition-colors
                        hover:border-nvidia/20">
          <span className="text-dimmed text-sm shrink-0">git:</span>
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://github.com/owner/repo.git"
            autoFocus
            className="flex-1 bg-transparent text-nvidia text-sm
                       placeholder:text-dimmed/40 focus:outline-none font-mono"
          />
          <button
            onClick={handleScan}
            disabled={!repoUrl.trim()}
            className="px-5 py-1.5 bg-nvidia/10 border border-nvidia/30 rounded text-nvidia text-sm
                       font-bold uppercase tracking-wider hover:bg-nvidia/20 hover:border-nvidia/50
                       disabled:opacity-20 disabled:cursor-not-allowed transition-all
                       hover:shadow-[0_0_16px_rgba(118,185,0,0.3)]"
          >
            SCAN
          </button>
        </div>

        {/* Suggestions */}
        {suggestions.length > 0 && (
          <div className="mt-4 flex items-center justify-center gap-4">
            <span className="text-dimmed text-xs">try:</span>
            {suggestions.map((s) => (
              <button
                key={s.url}
                onClick={() => setRepoUrl(s.url)}
                className="text-xs text-nvidia/50 hover:text-nvidia transition-colors
                           border border-border hover:border-nvidia/30 rounded px-3 py-1.5
                           hover:bg-nvidia/5"
              >
                {s.name}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Features */}
      <div className="mt-16 flex items-center gap-8 text-[11px] text-dimmed/60">
        <div className="flex items-center gap-1.5">
          <span className="text-nvidia/40">01</span> Secret Detection
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-nvidia/40">02</span> CVE Scanning
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-nvidia/40">03</span> AI Code Analysis
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-nvidia/40">04</span> Auto Patching
        </div>
      </div>

      <div className="absolute bottom-4 text-[10px] text-dimmed/30">
        Powered by NVIDIA Nemotron Super
      </div>
    </div>
  );
}
