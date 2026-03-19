import { useMemo } from 'react';
import { useScan } from '../store/scanStore';

const RISK_COLORS = {
  critical: '#FF0033',
  high: '#FF6600',
  medium: '#FFD600',
  low: '#4a7a00',
};

export default function FileTree() {
  const { state } = useScan();
  const { fileTree, recon } = state;

  const riskMap = useMemo(() => {
    const map = {};
    if (recon?.risk_tiers) {
      for (const [tier, files] of Object.entries(recon.risk_tiers)) {
        for (const f of files) {
          map[f] = tier;
        }
      }
    }
    return map;
  }, [recon]);

  const tree = useMemo(() => {
    const dirs = {};
    for (const f of fileTree) {
      const parts = f.path.split('/');
      const dir = parts.length > 1 ? parts.slice(0, -1).join('/') : '.';
      if (!dirs[dir]) dirs[dir] = [];
      dirs[dir].push(f);
    }
    return Object.entries(dirs).sort(([a], [b]) => a.localeCompare(b));
  }, [fileTree]);

  if (fileTree.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-dimmed text-xs">
        <div className="text-center">
          <div className="text-2xl mb-2 opacity-30">{'\u{1F4C1}'}</div>
          <div>No files loaded</div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto p-2 text-xs">
      <div className="text-dimmed mb-2 uppercase tracking-wider text-[10px]">
        Files ({fileTree.length})
      </div>
      {tree.map(([dir, files]) => (
        <div key={dir} className="mb-1">
          <div className="text-dimmed/80 mb-0.5">{'\u{1F4C2}'} {dir}/</div>
          {files.map((f) => {
            const risk = riskMap[f.path];
            const color = risk ? RISK_COLORS[risk] : '#76B900';
            return (
              <div
                key={f.path}
                className="pl-4 py-0.5 hover:bg-surface/50 rounded cursor-default truncate"
                style={{ color }}
                title={`${f.path} (${f.lines} lines)`}
              >
                {f.path.split('/').pop()}
                <span className="text-dimmed ml-1">:{f.lines}</span>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}
