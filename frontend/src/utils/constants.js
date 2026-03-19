export const SEVERITY_COLORS = {
  CRITICAL: '#FF0033',
  HIGH: '#FF6600',
  MEDIUM: '#FFD600',
  LOW: '#4a7a00',
};

export const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export const TOOL_COLORS = {
  run_command: '#c084fc',
  cwe_lookup: '#76B900',
  osv_query: '#FF6600',
  web_search: '#00D4FF',
  get_existing_findings: '#4a7a00',
  report_finding: '#FF0033',
  retract_finding: '#666666',
};

export const TOOL_ICONS = {
  run_command: '\u{1F4BB}',
  cwe_lookup: '\u{1F6E1}',
  osv_query: '\u{1F4E6}',
  web_search: '\u{1F310}',
  get_existing_findings: '\u{1F4CB}',
  report_finding: '\u{1F6A8}',
  retract_finding: '\u{274C}',
};

export const SOURCE_LABELS = {
  secrets: { label: 'Secrets', icon: '\u{1F511}' },
  osv: { label: 'CVEs', icon: '\u{1F4E6}' },
  code: { label: 'Code', icon: '\u{1F41B}' },
  config: { label: 'Config', icon: '\u{1F433}' },
};

export const API_BASE = 'http://localhost:8004';
