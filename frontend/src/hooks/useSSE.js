import { useRef, useCallback } from 'react';
import { API_BASE } from '../utils/constants';

const EVENT_MAP = {
  status: 'STATUS',
  file_tree: 'FILE_TREE',
  finding: 'FINDING',
  recon: 'RECON',
  graph_data: 'GRAPH_DATA',
  tool_call: 'TOOL_CALL',
  reasoning: 'REASONING',
  hunter_finding: 'HUNTER_FINDING',
  patch: 'PATCH',
  complete: 'COMPLETE',
  error: 'ERROR',
  retract_finding: 'RETRACT_FINDING',
};

export function useSSE(dispatch) {
  const sourceRef = useRef(null);

  const startScan = useCallback(
    (repoUrl) => {
      if (sourceRef.current) {
        sourceRef.current.close();
      }

      dispatch({ type: 'START_SCAN' });

      const url = `${API_BASE}/api/scan?repo_url=${encodeURIComponent(repoUrl)}`;
      const source = new EventSource(url);
      sourceRef.current = source;

      Object.entries(EVENT_MAP).forEach(([eventName, actionType]) => {
        source.addEventListener(eventName, (e) => {
          try {
            const payload = JSON.parse(e.data);
            dispatch({ type: actionType, payload });
          } catch {
            // ignore parse errors
          }
        });
      });

      source.onerror = () => {
        source.close();
        sourceRef.current = null;
      };
    },
    [dispatch]
  );

  const stopScan = useCallback(() => {
    if (sourceRef.current) {
      sourceRef.current.close();
      sourceRef.current = null;
    }
  }, []);

  return { startScan, stopScan };
}
