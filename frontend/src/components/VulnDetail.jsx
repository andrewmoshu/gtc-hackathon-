import { useEffect, useRef } from 'react';
import SeverityBadge from './SeverityBadge';
import { TOOL_COLORS } from '../utils/constants';
import hljs from 'highlight.js/lib/core';
import javascript from 'highlight.js/lib/languages/javascript';
import python from 'highlight.js/lib/languages/python';
import java from 'highlight.js/lib/languages/java';
import go from 'highlight.js/lib/languages/go';
import php from 'highlight.js/lib/languages/php';
import ruby from 'highlight.js/lib/languages/ruby';
import sql from 'highlight.js/lib/languages/sql';
import 'highlight.js/styles/github-dark.css';

hljs.registerLanguage('javascript', javascript);
hljs.registerLanguage('python', python);
hljs.registerLanguage('java', java);
hljs.registerLanguage('go', go);
hljs.registerLanguage('php', php);
hljs.registerLanguage('ruby', ruby);
hljs.registerLanguage('sql', sql);

function CodeBlock({ code, language }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current && code) {
      try {
        ref.current.innerHTML = hljs.highlight(code, {
          language: language || 'plaintext',
          ignoreIllegals: true,
        }).value;
      } catch {
        ref.current.textContent = code;
      }
    }
  }, [code, language]);

  if (!code) return null;
  return (
    <pre className="rounded bg-bg p-3 overflow-x-auto text-xs border border-border">
      <code ref={ref} className="font-mono" />
    </pre>
  );
}

export default function VulnDetail({ finding, patch, toolCalls, onClose }) {
  const ext = finding.file?.split('.').pop() || '';
  const langMap = {
    py: 'python', js: 'javascript', ts: 'javascript',
    java: 'java', go: 'go', php: 'php', rb: 'ruby',
  };
  const language = langMap[ext] || 'plaintext';

  // Find related tool calls
  const related = (finding.tool_references || []).map((tr) => tr);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80"
      onClick={onClose}
    >
      <div
        className="bg-surface border border-border rounded-lg max-w-3xl w-full mx-4
                    max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 bg-surface border-b border-border p-4 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <SeverityBadge severity={finding.severity} />
              {finding.cwe_id && (
                <span className="text-xs text-dimmed">{finding.cwe_id}</span>
              )}
              {finding.confidence && (
                <span className="text-[10px] text-dimmed border border-border px-1.5 py-0.5 rounded">
                  {finding.confidence} confidence
                </span>
              )}
            </div>
            <h2 className="text-nvidia-bright text-sm font-bold mt-1">{finding.title}</h2>
            <div className="text-[11px] text-dimmed mt-0.5">
              {finding.file}
              {finding.line_start ? `:${finding.line_start}` : finding.line ? `:${finding.line}` : ''}
              {finding.line_end ? `-${finding.line_end}` : ''}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-dimmed hover:text-nvidia text-lg px-2"
          >
            {'\u2715'}
          </button>
        </div>

        <div className="p-4 space-y-4">
          {/* Description */}
          {finding.description && (
            <div>
              <div className="text-[10px] text-dimmed uppercase tracking-wider mb-1">
                Description
              </div>
              <p className="text-xs text-nvidia/80 leading-relaxed">
                {finding.description}
              </p>
            </div>
          )}

          {/* Evidence / Code */}
          {finding.evidence && (
            <div>
              <div className="text-[10px] text-dimmed uppercase tracking-wider mb-1">
                Vulnerable Code
              </div>
              <CodeBlock code={finding.evidence} language={language} />
            </div>
          )}

          {/* Data flow trace */}
          {finding.data_flow_trace && (
            <div>
              <div className="text-[10px] text-dimmed uppercase tracking-wider mb-1">
                Data Flow
              </div>
              <div className="text-xs text-cyan bg-bg p-2 rounded border border-border font-mono">
                {finding.data_flow_trace}
              </div>
            </div>
          )}

          {/* Exploitation scenario */}
          {finding.exploitation_scenario && (
            <div>
              <div className="text-[10px] text-dimmed uppercase tracking-wider mb-1">
                Exploitation Scenario
              </div>
              <p className="text-xs text-high/80 leading-relaxed">
                {finding.exploitation_scenario}
              </p>
            </div>
          )}

          {/* Patch */}
          {patch && (
            <div>
              <div className="text-[10px] text-dimmed uppercase tracking-wider mb-1">
                {'\u{1F527}'} Suggested Fix
              </div>
              {patch.explanation && (
                <p className="text-xs text-nvidia/70 mb-2">{patch.explanation}</p>
              )}
              {patch.patched_code && (
                <CodeBlock code={patch.patched_code} language={language} />
              )}
              {patch.commands && patch.commands.length > 0 && (
                <div className="mt-2 text-xs">
                  {patch.commands.map((cmd, i) => (
                    <div key={i} className="text-cyan font-mono bg-bg p-1.5 rounded border border-border mb-1">
                      $ {cmd}
                    </div>
                  ))}
                </div>
              )}
              {patch.breaking_risk && patch.breaking_risk !== 'LOW' && (
                <div className="mt-1 text-[10px] text-high">
                  {'\u26A0'} Breaking risk: {patch.breaking_risk}
                  {patch.breaking_notes && ` \u2014 ${patch.breaking_notes}`}
                </div>
              )}
            </div>
          )}

          {/* Investigation Trail */}
          {related.length > 0 && (
            <div>
              <div className="text-[10px] text-dimmed uppercase tracking-wider mb-1">
                Investigation Trail
              </div>
              {related.map((tr, i) => (
                <div
                  key={i}
                  className="text-xs p-2 mb-1 rounded border"
                  style={{
                    borderColor: (TOOL_COLORS[tr.tool] || '#76B900') + '30',
                    color: TOOL_COLORS[tr.tool] || '#76B900',
                  }}
                >
                  <span className="font-bold">{tr.tool}</span>
                  <span className="text-dimmed ml-2">{tr.result_summary || tr.result || ''}</span>
                </div>
              ))}
            </div>
          )}

          {/* Details (for secret/CVE findings) */}
          {finding.details && (
            <div>
              <div className="text-[10px] text-dimmed uppercase tracking-wider mb-1">
                Details
              </div>
              <pre className="text-[11px] text-nvidia/60 bg-bg p-2 rounded border border-border overflow-x-auto">
                {JSON.stringify(finding.details, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
