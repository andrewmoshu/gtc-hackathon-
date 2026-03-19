import { SEVERITY_COLORS } from '../utils/constants';

export default function SeverityBadge({ severity }) {
  const color = SEVERITY_COLORS[severity] || '#666';

  return (
    <span
      className="inline-block px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider"
      style={{
        color,
        border: `1px solid ${color}`,
        textShadow: `0 0 6px ${color}40`,
      }}
    >
      {severity}
    </span>
  );
}
