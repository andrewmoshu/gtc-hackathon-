import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useScan } from '../store/scanStore';
import { useSSE } from '../hooks/useSSE';
import { API_BASE } from '../utils/constants';

const FEATURES = [
  {
    num: '01',
    label: 'Secret Detection',
    desc: 'API keys, tokens & leaked credentials',
    icon: '🔑',
  },
  {
    num: '02',
    label: 'CVE Scanning',
    desc: 'Dependencies against known vuln DBs',
    icon: '📦',
  },
  {
    num: '03',
    label: 'AI Code Analysis',
    desc: 'Deep pattern & logic vulnerability recognition',
    icon: '🧠',
  },
  {
    num: '04',
    label: 'Auto Patching',
    desc: 'AI-generated one-click remediation',
    icon: '🔧',
  },
];

const containerVariants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.12 } },
};

const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.55, ease: [0.22, 1, 0.36, 1] } },
};

const cardVariants = {
  hidden: { opacity: 0, y: 24, scale: 0.96 },
  visible: (i) => ({
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { delay: i * 0.08 + 0.5, duration: 0.5, ease: [0.22, 1, 0.36, 1] },
  }),
};

function GridBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {/* Radial center glow */}
      <div
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full"
        style={{
          width: 700,
          height: 500,
          background:
            'radial-gradient(ellipse, rgba(118,185,0,0.07) 0%, transparent 70%)',
        }}
      />
      {/* Dot grid */}
      <svg
        className="absolute inset-0 w-full h-full opacity-[0.035]"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <pattern id="dots" x="0" y="0" width="32" height="32" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="#76B900" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#dots)" />
      </svg>
      {/* Horizontal accent line */}
      <motion.div
        initial={{ scaleX: 0, opacity: 0 }}
        animate={{ scaleX: 1, opacity: 1 }}
        transition={{ delay: 0.2, duration: 1.2, ease: [0.22, 1, 0.36, 1] }}
        className="absolute left-0 right-0"
        style={{
          top: '50%',
          height: 1,
          background:
            'linear-gradient(90deg, transparent 0%, rgba(118,185,0,0.12) 30%, rgba(118,185,0,0.12) 70%, transparent 100%)',
          transformOrigin: 'center',
        }}
      />
    </div>
  );
}

export default function LandingPage() {
  const { dispatch } = useScan();
  const { startScan } = useSSE(dispatch);
  const [repoUrl, setRepoUrl] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [focused, setFocused] = useState(false);

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

  return (
    <div className="h-full flex flex-col items-center justify-center px-4 relative overflow-hidden select-none">
      <GridBackground />

      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="relative z-10 w-full flex flex-col items-center"
      >
        {/* Badge */}
        <motion.div variants={fadeUp} className="mb-5">
          <span
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full border text-[10px]
                       font-mono tracking-[0.25em] uppercase"
            style={{
              borderColor: 'rgba(118,185,0,0.25)',
              color: 'rgba(118,185,0,0.6)',
              background: 'rgba(118,185,0,0.04)',
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full animate-pulse"
              style={{ background: '#76B900' }}
            />
            AI-Powered Security Research
          </span>
        </motion.div>

        {/* Logo */}
        <motion.div variants={fadeUp} className="mb-2 text-center">
          <h1
            className="font-display font-bold tracking-widest"
            style={{
              fontSize: 'clamp(3rem, 8vw, 5.5rem)',
              color: '#76B900',
              textShadow:
                '0 0 40px rgba(118,185,0,0.35), 0 0 80px rgba(118,185,0,0.12)',
              lineHeight: 1.05,
            }}
          >
            CodeSentinel
          </h1>
        </motion.div>

        <motion.p
          variants={fadeUp}
          className="text-sm mb-12 tracking-[0.4em] uppercase"
          style={{ color: 'rgba(102,102,102,0.7)' }}
        >
          Not a scanner. A researcher.
        </motion.p>

        {/* Search box */}
        <motion.div variants={fadeUp} className="w-full max-w-2xl">
          <motion.div
            animate={
              focused
                ? { boxShadow: '0 0 0 1px rgba(118,185,0,0.4), 0 0 32px rgba(118,185,0,0.1)' }
                : { boxShadow: '0 0 0 1px rgba(42,42,42,1)' }
            }
            transition={{ duration: 0.2 }}
            className="flex items-center gap-3 rounded-xl px-5 py-3.5"
            style={{ background: '#1a1a1a' }}
          >
            <span className="text-sm font-mono shrink-0" style={{ color: 'rgba(118,185,0,0.35)' }}>
              git://
            </span>
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              placeholder="github.com/owner/repo"
              autoFocus
              className="flex-1 bg-transparent text-sm focus:outline-none font-mono"
              style={{
                color: '#76B900',
              }}
            />
            <motion.button
              onClick={handleScan}
              disabled={!repoUrl.trim()}
              whileHover={repoUrl.trim() ? { scale: 1.04 } : {}}
              whileTap={repoUrl.trim() ? { scale: 0.96 } : {}}
              className="px-6 py-2 rounded-lg font-bold text-xs uppercase tracking-widest transition-colors"
              style={{
                background: repoUrl.trim() ? 'rgba(118,185,0,0.12)' : 'rgba(118,185,0,0.04)',
                border: `1px solid ${repoUrl.trim() ? 'rgba(118,185,0,0.45)' : 'rgba(118,185,0,0.15)'}`,
                color: repoUrl.trim() ? '#76B900' : 'rgba(118,185,0,0.3)',
                cursor: repoUrl.trim() ? 'pointer' : 'not-allowed',
              }}
            >
              Scan →
            </motion.button>
          </motion.div>

          {/* Suggestions */}
          <AnimatePresence>
            {suggestions.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.7, duration: 0.4 }}
                className="mt-3 flex items-center justify-center gap-3"
              >
                <span className="text-[11px] font-mono" style={{ color: 'rgba(102,102,102,0.45)' }}>
                  try:
                </span>
                {suggestions.map((s) => (
                  <motion.button
                    key={s.url}
                    onClick={() => setRepoUrl(s.url)}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    className="text-[11px] font-mono rounded-lg px-3 py-1.5 border transition-colors"
                    style={{
                      color: 'rgba(118,185,0,0.45)',
                      borderColor: 'rgba(42,42,42,0.8)',
                      background: 'transparent',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.color = 'rgba(118,185,0,0.85)';
                      e.currentTarget.style.borderColor = 'rgba(118,185,0,0.3)';
                      e.currentTarget.style.background = 'rgba(118,185,0,0.05)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.color = 'rgba(118,185,0,0.45)';
                      e.currentTarget.style.borderColor = 'rgba(42,42,42,0.8)';
                      e.currentTarget.style.background = 'transparent';
                    }}
                  >
                    {s.name}
                  </motion.button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Feature cards */}
        <div className="mt-14 grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-3xl w-full">
          {FEATURES.map((f, i) => (
            <motion.div
              key={f.num}
              custom={i}
              variants={cardVariants}
              initial="hidden"
              animate="visible"
              whileHover={{ y: -5, transition: { duration: 0.18 } }}
              className="rounded-xl p-4 border cursor-default group"
              style={{
                background: 'rgba(26,26,26,0.6)',
                borderColor: 'rgba(42,42,42,0.8)',
                backdropFilter: 'blur(4px)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'rgba(118,185,0,0.2)';
                e.currentTarget.style.background = 'rgba(118,185,0,0.04)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'rgba(42,42,42,0.8)';
                e.currentTarget.style.background = 'rgba(26,26,26,0.6)';
              }}
            >
              <div className="text-2xl mb-2 opacity-70">{f.icon}</div>
              <div
                className="text-[10px] font-mono mb-1.5"
                style={{ color: 'rgba(118,185,0,0.3)' }}
              >
                {f.num}
              </div>
              <div className="text-xs font-semibold mb-1" style={{ color: 'rgba(118,185,0,0.85)' }}>
                {f.label}
              </div>
              <div className="text-[11px]" style={{ color: 'rgba(102,102,102,0.55)' }}>
                {f.desc}
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2, duration: 0.6 }}
        className="absolute bottom-5 text-[10px] font-mono tracking-[0.3em] uppercase"
        style={{ color: 'rgba(102,102,102,0.25)' }}
      >
        Powered by NVIDIA Nemotron Super
      </motion.div>
    </div>
  );
}
