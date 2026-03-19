import { useScan } from '../store/scanStore';
import { useSSE } from '../hooks/useSSE';

const STAGES = [
  { key: 'ingestion', label: 'Cloning repository', icon: '\u{1F4E5}' },
  { key: 'deterministic', label: 'Deterministic scanning', icon: '\u{1F50D}' },
  { key: 'secret_scanner', label: 'Detecting secrets', icon: '\u{1F511}' },
  { key: 'dependency_scanner', label: 'Checking CVE databases', icon: '\u{1F4E6}' },
  { key: 'hunter_agent', label: 'AI security investigation', icon: '\u{1F575}' },
  { key: 'verifier_agent', label: 'Verifying findings', icon: '\u{2705}' },
  { key: 'patcher_agent', label: 'Generating patches', icon: '\u{1F527}' },
];

function getStageStatus(stageKey, currentLayer, statusMessage, errors) {
  const hasError = errors.some((e) => e.layer === stageKey);
  if (hasError) return 'error';

  const stageIdx = STAGES.findIndex((s) => s.key === stageKey);
  const currentIdx = STAGES.findIndex((s) => s.key === currentLayer);

  if (stageKey === currentLayer) {
    if (statusMessage?.includes('complete') || statusMessage?.includes('Complete')) {
      return 'done';
    }
    return 'active';
  }
  if (currentIdx > stageIdx) return 'done';
  return 'pending';
}

export default function ScanProgress() {
  const { state, dispatch } = useScan();
  const { currentLayer, statusMessage, errors, findings } = state;

  const secretCount = findings.filter((f) => f.source === 'secrets').length;
  const cveCount = findings.filter((f) => f.source === 'osv').length;

  return (
    <div className="h-full flex flex-col items-center justify-center px-4">
      <h1 className="font-display text-4xl font-bold text-nvidia glow-strong tracking-wide mb-2">
        CodeSentinel
      </h1>
      <p className="text-dimmed text-xs mb-12">Analyzing repository...</p>

      <div className="w-full max-w-md space-y-3">
        {STAGES.map((stage) => {
          const status = getStageStatus(stage.key, currentLayer, statusMessage, errors);
          return (
            <div
              key={stage.key}
              className={`flex items-center gap-3 px-4 py-2.5 rounded-lg border transition-all duration-500 ${
                status === 'active'
                  ? 'border-nvidia/40 bg-nvidia/5'
                  : status === 'done'
                  ? 'border-border bg-surface/30'
                  : status === 'error'
                  ? 'border-critical/30 bg-critical/5'
                  : 'border-border/50 opacity-30'
              }`}
            >
              {/* Status indicator */}
              <div className="w-5 h-5 flex items-center justify-center shrink-0">
                {status === 'active' && (
                  <div className="w-3 h-3 rounded-full bg-nvidia animate-pulse-glow" />
                )}
                {status === 'done' && (
                  <span className="text-nvidia text-sm">{'\u2713'}</span>
                )}
                {status === 'error' && (
                  <span className="text-critical text-sm">{'\u2717'}</span>
                )}
                {status === 'pending' && (
                  <div className="w-2 h-2 rounded-full bg-dimmed/30" />
                )}
              </div>

              {/* Icon + label */}
              <span className="text-lg">{stage.icon}</span>
              <span
                className={`text-xs flex-1 ${
                  status === 'active'
                    ? 'text-nvidia'
                    : status === 'done'
                    ? 'text-nvidia/50'
                    : status === 'error'
                    ? 'text-critical/70'
                    : 'text-dimmed/50'
                }`}
              >
                {stage.label}
              </span>

              {/* Live count badges */}
              {stage.key === 'secret_scanner' && secretCount > 0 && (
                <span className="text-[10px] text-high border border-high/30 rounded px-1.5 py-0.5">
                  {secretCount} found
                </span>
              )}
              {stage.key === 'dependency_scanner' && cveCount > 0 && (
                <span className="text-[10px] text-medium border border-medium/30 rounded px-1.5 py-0.5">
                  {cveCount} CVEs
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Status message */}
      {statusMessage && (
        <div className="mt-6 text-[11px] text-nvidia/50 animate-pulse-glow max-w-md text-center">
          &gt; {statusMessage}
        </div>
      )}

      {/* Error display */}
      {errors.length > 0 && (
        <div className="mt-4 max-w-md text-center">
          <div className="text-[11px] text-critical/70 mb-3">
            {errors[errors.length - 1].message}
          </div>
          {state.status === 'error' && (
            <button
              onClick={() => dispatch({ type: 'RESET' })}
              className="px-4 py-1.5 text-xs text-nvidia border border-nvidia/30 rounded
                         hover:bg-nvidia/10 transition-colors"
            >
              Try another repo
            </button>
          )}
        </div>
      )}
    </div>
  );
}
