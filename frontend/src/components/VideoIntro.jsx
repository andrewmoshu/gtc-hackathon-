import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const TAGLINES = [
  'Detecting secrets...',
  'Mapping attack surfaces...',
  'Correlating CVEs...',
  'Reasoning about code...',
  'Generating patches...',
];

function ParticleGrid() {
  const cols = 20;
  const rows = 12;
  const cells = Array.from({ length: cols * rows }, (_, i) => i);
  return (
    <div
      className="absolute inset-0 overflow-hidden pointer-events-none"
      style={{ opacity: 0.18 }}
    >
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${cols}, 1fr)`,
          gridTemplateRows: `repeat(${rows}, 1fr)`,
          width: '100%',
          height: '100%',
        }}
      >
        {cells.map((i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, (i % 7) * 0.12 + 0.05, 0] }}
            transition={{
              duration: (i % 3) + 2,
              repeat: Infinity,
              delay: (i % 13) * 0.3,
              ease: 'easeInOut',
            }}
            style={{
              border: '1px solid rgba(118,185,0,0.15)',
              background: i % 17 === 0 ? 'rgba(118,185,0,0.06)' : 'transparent',
            }}
          />
        ))}
      </div>
    </div>
  );
}

function TypewriterLine({ text }) {
  const [displayed, setDisplayed] = useState('');
  useEffect(() => {
    setDisplayed('');
    let i = 0;
    const interval = setInterval(() => {
      setDisplayed(text.slice(0, i + 1));
      i++;
      if (i >= text.length) clearInterval(interval);
    }, 38);
    return () => clearInterval(interval);
  }, [text]);

  return (
    <span>
      {displayed}
      <motion.span
        animate={{ opacity: [1, 0, 1] }}
        transition={{ duration: 0.7, repeat: Infinity }}
        style={{ color: '#76B900' }}
      >
        _
      </motion.span>
    </span>
  );
}

function ScanLine() {
  return (
    <motion.div
      initial={{ top: '-2%' }}
      animate={{ top: '102%' }}
      transition={{ duration: 3.5, repeat: Infinity, ease: 'linear', repeatDelay: 1.5 }}
      style={{
        position: 'absolute',
        left: 0,
        right: 0,
        height: 2,
        background:
          'linear-gradient(90deg, transparent 0%, rgba(118,185,0,0.6) 30%, rgba(118,185,0,0.8) 50%, rgba(118,185,0,0.6) 70%, transparent 100%)',
        boxShadow: '0 0 16px rgba(118,185,0,0.5)',
        pointerEvents: 'none',
        zIndex: 5,
      }}
    />
  );
}

export default function VideoIntro({ onComplete }) {
  const [visible, setVisible] = useState(true);
  const [phase, setPhase] = useState(0);
  const [taglineIdx, setTaglineIdx] = useState(0);
  const [canEnter, setCanEnter] = useState(false);
  const [muted, setMuted] = useState(true);

  useEffect(() => {
    const t1 = setTimeout(() => setPhase(1), 600);
    const t2 = setTimeout(() => setPhase(2), 1800);
    const t3 = setTimeout(() => setCanEnter(true), 1800 + TAGLINES.length * 1200 + 800);
    return () => [t1, t2, t3].forEach(clearTimeout);
  }, []);

  useEffect(() => {
    if (phase < 2) return;
    const interval = setInterval(() => {
      setTaglineIdx((i) => {
        if (i >= TAGLINES.length - 1) {
          clearInterval(interval);
          return i;
        }
        return i + 1;
      });
    }, 1200);
    return () => clearInterval(interval);
  }, [phase]);

  const dismiss = () => {
    setVisible(false);
    setTimeout(onComplete, 700);
  };

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          key="intro"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.7 }}
          onClick={canEnter ? dismiss : undefined}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 50,
            background: '#050505',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: canEnter ? 'pointer' : 'default',
            overflow: 'hidden',
          }}
        >
          <ParticleGrid />
          <ScanLine />

          {/* Center radial glow */}
          <div
            style={{
              position: 'absolute',
              left: '50%',
              top: '50%',
              transform: 'translate(-50%, -50%)',
              width: 800,
              height: 600,
              background: 'radial-gradient(ellipse, rgba(118,185,0,0.08) 0%, transparent 65%)',
              pointerEvents: 'none',
            }}
          />

          {/* Main content */}
          <div
            style={{
              position: 'relative',
              zIndex: 10,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            {/* YouTube commercial video */}
            <AnimatePresence>
              {phase >= 1 && (
                <motion.div
                  initial={{ opacity: 0, y: -16 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
                  style={{
                    marginBottom: 28,
                    borderRadius: 10,
                    overflow: 'hidden',
                    border: '1px solid rgba(118,185,0,0.2)',
                    boxShadow: '0 0 40px rgba(118,185,0,0.12), 0 0 80px rgba(118,185,0,0.06)',
                    lineHeight: 0,
                  }}
                >
                  <div style={{ position: 'relative', lineHeight: 0 }}>
                    <iframe
                      key={muted ? 'muted' : 'unmuted'}
                      width="840"
                      height="473"
                      src={`https://www.youtube.com/embed/L_jOWiGj1nc?autoplay=1&mute=${muted ? 1 : 0}&loop=1&playlist=L_jOWiGj1nc&controls=0&modestbranding=1&rel=0`}
                      title="CodeSentinel Commercial"
                      allow="autoplay; fullscreen; accelerometer; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                      allowFullScreen
                      style={{ display: 'block', border: 'none' }}
                    />
                    {/* Mute/unmute toggle */}
                    <motion.button
                      onClick={(e) => { e.stopPropagation(); setMuted((m) => !m); }}
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                      style={{
                        position: 'absolute',
                        bottom: 12,
                        right: 12,
                        zIndex: 20,
                        background: 'rgba(0,0,0,0.75)',
                        border: '1px solid rgba(118,185,0,0.4)',
                        borderRadius: 8,
                        padding: '6px 12px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 11,
                        letterSpacing: '0.15em',
                        color: '#76B900',
                        backdropFilter: 'blur(4px)',
                      }}
                    >
                      <span style={{ fontSize: 15 }}>{muted ? '🔇' : '🔊'}</span>
                      {muted ? 'Unmute' : 'Mute'}
                    </motion.button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Sub-label */}
            <AnimatePresence>
              {phase >= 1 && (
                <motion.div
                  initial={{ opacity: 0, letterSpacing: '0.8em' }}
                  animate={{ opacity: 1, letterSpacing: '0.35em' }}
                  transition={{ duration: 1.2, ease: 'easeOut' }}
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 11,
                    color: 'rgba(118,185,0,0.4)',
                    textTransform: 'uppercase',
                    marginBottom: 24,
                  }}
                >
                  AI Security Research Platform
                </motion.div>
              )}
            </AnimatePresence>

            {/* Logo */}
            <AnimatePresence>
              {phase >= 1 && (
                <motion.h1
                  initial={{ opacity: 0, y: 30, scale: 0.9 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
                  style={{
                    fontFamily: "'Barlow Semi Condensed', sans-serif",
                    fontWeight: 700,
                    fontSize: 'clamp(4rem, 12vw, 8rem)',
                    color: '#76B900',
                    textShadow: '0 0 60px rgba(118,185,0,0.5), 0 0 120px rgba(118,185,0,0.2)',
                    margin: 0,
                    lineHeight: 1,
                    letterSpacing: '0.04em',
                  }}
                >
                  CodeSentinel
                </motion.h1>
              )}
            </AnimatePresence>

            {/* Divider */}
            <AnimatePresence>
              {phase >= 1 && (
                <motion.div
                  initial={{ scaleX: 0, opacity: 0 }}
                  animate={{ scaleX: 1, opacity: 1 }}
                  transition={{ delay: 0.4, duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
                  style={{
                    width: 480,
                    height: 1,
                    background:
                      'linear-gradient(90deg, transparent, rgba(118,185,0,0.5) 30%, rgba(118,185,0,0.5) 70%, transparent)',
                    margin: '20px 0',
                    transformOrigin: 'center',
                  }}
                />
              )}
            </AnimatePresence>

            {/* Typewriter taglines */}
            <div
              style={{
                height: 28,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <AnimatePresence mode="wait">
                {phase >= 2 && (
                  <motion.div
                    key={taglineIdx}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.25 }}
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 14,
                      color: 'rgba(118,185,0,0.55)',
                      letterSpacing: '0.1em',
                    }}
                  >
                    <TypewriterLine text={`> ${TAGLINES[taglineIdx]}`} />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Tagline */}
            <AnimatePresence>
              {phase >= 1 && (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.8, duration: 0.8 }}
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 12,
                    color: 'rgba(102,102,102,0.5)',
                    letterSpacing: '0.35em',
                    textTransform: 'uppercase',
                    margin: '20px 0 0',
                  }}
                >
                  Not a scanner. A researcher.
                </motion.p>
              )}
            </AnimatePresence>
          </div>

          {/* Enter button */}
          <AnimatePresence>
            {canEnter && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.5 }}
                style={{
                  position: 'absolute',
                  bottom: 48,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 8,
                  zIndex: 20,
                }}
              >
                <motion.button
                  onClick={dismiss}
                  whileHover={{ scale: 1.06 }}
                  whileTap={{ scale: 0.94 }}
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 12,
                    letterSpacing: '0.3em',
                    textTransform: 'uppercase',
                    color: '#76B900',
                    background: 'rgba(118,185,0,0.07)',
                    border: '1px solid rgba(118,185,0,0.4)',
                    borderRadius: 8,
                    padding: '10px 32px',
                    cursor: 'pointer',
                    boxShadow: '0 0 24px rgba(118,185,0,0.15)',
                  }}
                >
                  Enter →
                </motion.button>
                <motion.span
                  animate={{ opacity: [0.3, 0.7, 0.3] }}
                  transition={{ duration: 2, repeat: Infinity }}
                  style={{
                    fontSize: 10,
                    fontFamily: "'JetBrains Mono', monospace",
                    color: 'rgba(102,102,102,0.35)',
                    letterSpacing: '0.2em',
                  }}
                >
                  or click anywhere
                </motion.span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Scanlines overlay */}
          <div
            style={{
              position: 'absolute',
              inset: 0,
              pointerEvents: 'none',
              background:
                'repeating-linear-gradient(0deg, rgba(0,0,0,0.04) 0px, rgba(0,0,0,0.04) 1px, transparent 1px, transparent 2px)',
              zIndex: 15,
            }}
          />
        </motion.div>
      )}
    </AnimatePresence>
  );
}
