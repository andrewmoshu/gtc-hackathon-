import { ScanProvider, useScan } from './store/scanStore';
import LandingPage from './components/LandingPage';
import ScanProgress from './components/ScanProgress';
import DashboardView from './components/DashboardView';

function AppRouter() {
  const { state } = useScan();

  if (state.status === 'idle') {
    return <LandingPage />;
  }

  if (state.status === 'error') {
    return <ScanProgress />;
  }

  // Stay on progress until deterministic scanners finish (findings appear)
  const hasFindings = state.findings.length > 0;

  if (state.status === 'scanning' && !hasFindings) {
    return <ScanProgress />;
  }

  // Hunter is active, or scan is complete → dashboard
  return <DashboardView />;
}

export default function App() {
  return (
    <ScanProvider>
      <div className="h-screen bg-bg scanlines">
        <AppRouter />
      </div>
    </ScanProvider>
  );
}
