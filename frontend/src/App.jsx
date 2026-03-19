import { useState } from 'react';
import { motion } from 'framer-motion';
import { ScanProvider, useScan } from './store/scanStore';
import LandingPage from './components/LandingPage';
import ScanProgress from './components/ScanProgress';
import DashboardView from './components/DashboardView';
import VideoIntro from './components/VideoIntro';

function AppRouter() {
  const { state } = useScan();

  if (state.status === 'idle') {
    return <LandingPage />;
  }

  if (state.status === 'error') {
    return <ScanProgress />;
  }

  // Stay on progress until deterministic scanners finish OR hunter agent starts
  const hasFindings = state.findings.length > 0;
  const hunterActive =
    state.toolCalls.length > 0 ||
    ['hunter_agent', 'verifier_agent', 'patcher_agent'].includes(state.currentLayer);

  if (state.status === 'scanning' && !hasFindings && !hunterActive) {
    return <ScanProgress />;
  }

  // Hunter is active, or scan is complete → dashboard
  return <DashboardView />;
}

export default function App() {
  const [showIntro, setShowIntro] = useState(
    () => sessionStorage.getItem('intro-seen') !== 'true'
  );

  const handleIntroComplete = () => {
    sessionStorage.setItem('intro-seen', 'true');
    setShowIntro(false);
  };

  const handleReplay = () => {
    setShowIntro(true);
  };

  return (
    <ScanProvider>
      {showIntro && <VideoIntro onComplete={handleIntroComplete} />}
      <div className="h-screen bg-bg scanlines">
        <AppRouter />
      </div>

      {/* Back to video button — always visible when intro is hidden */}
      {!showIntro && (
        <motion.button
          onClick={handleReplay}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, duration: 0.4 }}
          whileHover={{ scale: 1.06, boxShadow: '0 0 20px rgba(118,185,0,0.25)' }}
          whileTap={{ scale: 0.94 }}
          style={{
            position: 'fixed',
            bottom: 20,
            left: 20,
            zIndex: 40,
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            padding: '7px 14px',
            background: 'rgba(10,10,10,0.85)',
            border: '1px solid rgba(118,185,0,0.3)',
            borderRadius: 8,
            cursor: 'pointer',
            backdropFilter: 'blur(8px)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            letterSpacing: '0.15em',
            textTransform: 'uppercase',
            color: 'rgba(118,185,0,0.7)',
          }}
        >
          <span style={{ fontSize: 13 }}>▶</span>
          Intro
        </motion.button>
      )}
    </ScanProvider>
  );
}
