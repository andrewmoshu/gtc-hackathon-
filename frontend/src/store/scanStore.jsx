import { useReducer, createContext, useContext } from 'react';

const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function buildGraphFromFindings(hunterFindings, allFindings) {
  const nodeMap = {};  // file path → node
  const edges = [];
  const edgeSet = new Set();

  // Add nodes from all findings (secrets, CVEs, code vulns)
  for (const f of allFindings) {
    const file = f.file;
    if (!file) continue;

    if (!nodeMap[file]) {
      nodeMap[file] = {
        id: file,
        label: file.split('/').pop(),
        full_path: file,
        type: f.source === 'code' ? 'vulnerability' : f.source || 'file',
        risk: (f.severity || 'LOW').toLowerCase(),
        hasVuln: true,
        vulnSeverity: f.severity,
        vulnCount: 0,
        findings: [],
      };
    }

    const node = nodeMap[file];
    node.vulnCount++;
    node.findings.push({ id: f.id, title: f.title, severity: f.severity });

    // Upgrade severity if this finding is worse
    if ((SEVERITY_RANK[f.severity] ?? 99) < (SEVERITY_RANK[node.vulnSeverity] ?? 99)) {
      node.vulnSeverity = f.severity;
      node.risk = f.severity.toLowerCase();
    }
  }

  // Build edges from data_flow_trace in hunter findings
  for (const f of hunterFindings) {
    const trace = f.data_flow_trace;
    if (!trace || !f.file) continue;

    // Parse traces like "request.body → processInput() → db.execute()"
    // Extract file references from the trace
    const fileRefs = trace.match(/[\w./]+\.\w+/g) || [];
    for (const ref of fileRefs) {
      // Check if this ref matches any known file
      const matchedFile = Object.keys(nodeMap).find(
        (fp) => fp.endsWith(ref) || fp.includes(ref)
      );
      if (matchedFile && matchedFile !== f.file) {
        const edgeKey = `${matchedFile}|${f.file}`;
        if (!edgeSet.has(edgeKey)) {
          edgeSet.add(edgeKey);
          edges.push({
            from: matchedFile,
            to: f.file,
            label: 'data flow',
          });
        }
      }
    }
  }

  // If we have findings in same directory, connect them lightly
  const dirFiles = {};
  for (const file of Object.keys(nodeMap)) {
    const dir = file.includes('/') ? file.split('/').slice(0, -1).join('/') : '.';
    if (!dirFiles[dir]) dirFiles[dir] = [];
    dirFiles[dir].push(file);
  }
  for (const files of Object.values(dirFiles)) {
    if (files.length >= 2 && files.length <= 6) {
      for (let i = 0; i < files.length - 1; i++) {
        const edgeKey = `${files[i]}|${files[i + 1]}`;
        if (!edgeSet.has(edgeKey)) {
          edgeSet.add(edgeKey);
          edges.push({ from: files[i], to: files[i + 1], label: 'same module' });
        }
      }
    }
  }

  return { nodes: Object.values(nodeMap), edges };
}

const initialState = {
  status: 'idle', // idle | scanning | complete | error
  currentLayer: '',
  statusMessage: '',
  fileTree: [],
  recon: null,
  graphData: { nodes: [], edges: [] },
  findings: [],
  hunterFindings: [],
  toolCalls: [],
  reasoning: [],
  patches: [],
  summary: null,
  errors: [],
};

function scanReducer(state, action) {
  switch (action.type) {
    case 'START_SCAN':
      return { ...initialState, status: 'scanning' };

    case 'STATUS':
      return {
        ...state,
        currentLayer: action.payload.layer,
        statusMessage: action.payload.message || action.payload.state,
      };

    case 'FILE_TREE':
      return { ...state, fileTree: action.payload.files };

    case 'FINDING': {
      const updatedFindings = [...state.findings, action.payload];
      return {
        ...state,
        findings: updatedFindings,
        graphData: buildGraphFromFindings(state.hunterFindings, updatedFindings),
      };
    }

    case 'RECON':
      return { ...state, recon: action.payload };

    case 'GRAPH_DATA':
      return state; // graph is built from findings now

    case 'TOOL_CALL':
      return { ...state, toolCalls: [...state.toolCalls, action.payload] };

    case 'REASONING':
      return { ...state, reasoning: [...state.reasoning, action.payload] };

    case 'HUNTER_FINDING': {
      const hf = action.payload;
      const newFindings = [...state.findings, { ...hf, source: 'code' }];
      // Build graph from all findings that have file info
      const graphData = buildGraphFromFindings([...state.hunterFindings, hf], newFindings);
      return {
        ...state,
        hunterFindings: [...state.hunterFindings, hf],
        findings: newFindings,
        graphData,
      };
    }

    case 'PATCH':
      return { ...state, patches: [...state.patches, action.payload] };

    case 'COMPLETE':
      return { ...state, status: 'complete', summary: action.payload };

    case 'ERROR':
      return {
        ...state,
        status: state.findings.length > 0 ? state.status : 'error',
        errors: [...state.errors, action.payload],
      };

    case 'RESET':
      return initialState;

    case 'RETRACT_FINDING': {
      const retractId = action.payload.id;
      const filteredFindings = state.findings.filter((f) => f.id !== retractId);
      const filteredHunter = state.hunterFindings.filter((f) => f.id !== retractId);
      return {
        ...state,
        findings: filteredFindings,
        hunterFindings: filteredHunter,
        graphData: buildGraphFromFindings(filteredHunter, filteredFindings),
      };
    }

    default:
      return state;
  }
}

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(scanReducer, initialState);
  return (
    <ScanContext.Provider value={{ state, dispatch }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error('useScan must be used within ScanProvider');
  return ctx;
}
