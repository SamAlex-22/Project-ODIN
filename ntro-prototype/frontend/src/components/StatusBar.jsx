import React from 'react';

export default function StatusBar({ stats, connected }) {
  const cards = [
    { label: 'Total Alerts',    value: stats.total, color: '#3b82f6' },
    { label: 'DDoS Detected',   value: stats.ddos,  color: '#ef4444' },
    { label: 'Recon Detected',  value: stats.recon, color: '#f97316' },
    { label: 'C2 Beaconing',    value: stats.c2,    color: '#a855f7' },
  ];

  return (
    <div style={styles.bar}>
      {cards.map(card => (
        <div key={card.label} style={styles.card}>
          <div style={{ ...styles.value, color: card.color }}>{card.value}</div>
          <div style={styles.label}>{card.label}</div>
        </div>
      ))}
      <div style={styles.card}>
        <div style={styles.value}>
          <span style={{ color: connected ? '#22c55e' : '#ef4444' }}>
            {connected ? '✓' : '✗'}
          </span>
        </div>
        <div style={styles.label}>
          {connected ? 'Zeek Active' : 'Zeek Offline'}
        </div>
      </div>
    </div>
  );
}

const styles = {
  bar: {
    display: 'flex',
    gap: '1px',
    background: '#1e293b',
    borderBottom: '1px solid #1e293b',
  },
  card: {
    flex: 1,
    padding: '12px 20px',
    background: '#0f172a',
    textAlign: 'center',
  },
  value: {
    fontSize: '28px',
    fontWeight: 'bold',
    fontFamily: 'monospace',
  },
  label: { fontSize: '11px', color: '#64748b', marginTop: '2px' },
};
