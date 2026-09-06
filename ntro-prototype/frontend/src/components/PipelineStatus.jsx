import React, { useState, useEffect } from 'react';

const ROWS = [
  { key: 'diode',           label: 'Diode / Passive Input' },
  { key: 'zeek',             label: 'Zeek NSM' },
  { key: 'kafka',            label: 'Kafka Event Stream' },
  { key: 'stream_detector',  label: 'Streaming Detector' },
  { key: 'alert_engine',     label: 'Alert Engine' },
  { key: 'dashboard',        label: 'Dashboard' },
];

export default function PipelineStatus() {
  const [status, setStatus] = useState({});

  useEffect(() => {
    const poll = () => {
      fetch('/api/pipeline-status')
        .then(r => r.json())
        .then(setStatus)
        .catch(() => setStatus({}));
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => clearInterval(id);
  }, []);

  const renderIndicator = (key) => {
    if (key === 'dashboard') {
      return <span style={{ ...styles.dot, background: '#22c55e' }} />;
    }
    if (key === 'diode') {
      // Never claim the software enforces physical isolation -- this row
      // is always "simulated", not a green/red online check.
      return <span style={styles.simulated}>SIMULATED</span>;
    }
    const alive = !!status[key];
    return <span style={{ ...styles.dot, background: alive ? '#22c55e' : '#ef4444' }} />;
  };

  const renderText = (key) => {
    if (key === 'diode') return 'READ-ONLY INGEST';
    if (key === 'dashboard') return 'ONLINE';
    return status[key] ? 'ONLINE' : 'OFFLINE';
  };

  return (
    <div style={styles.panel}>
      <div style={styles.title}>Hybrid 1 Monitoring Pipeline</div>
      <div style={styles.rows}>
        {ROWS.map(({ key, label }) => (
          <div key={key} style={styles.row}>
            <div style={styles.rowLeft}>
              {renderIndicator(key)}
              <span style={styles.label}>{label}</span>
            </div>
            <span style={{
              ...styles.status,
              color: key === 'diode' ? '#3b82f6' : (status[key] || key === 'dashboard') ? '#22c55e' : '#ef4444',
            }}>
              {renderText(key)}
            </span>
          </div>
        ))}
      </div>
      <div style={styles.divider} />
      <div style={styles.footerRow}>
        <span>READ-ONLY INGEST</span>
        <span style={styles.enabled}>ENABLED</span>
      </div>
      <div style={styles.footerRow}>
        <span>RETURN PATH</span>
        <span style={styles.none}>NONE</span>
      </div>
      <div style={styles.note}>
        Physical one-way isolation is provided by the deployment boundary
        (diode/passive tap). This prototype simulates the diode-fed,
        read-only ingest interface -- the software pipeline has no return
        path or active response mechanism.
      </div>
    </div>
  );
}

const styles = {
  panel: {
    background: '#0f172a',
    border: '1px solid #1e293b',
    borderRadius: '8px',
    padding: '16px',
  },
  title: {
    fontSize: '13px',
    fontWeight: 'bold',
    color: '#94a3b8',
    marginBottom: '12px',
    textTransform: 'uppercase',
    letterSpacing: '1px',
  },
  rows: { display: 'flex', flexDirection: 'column', gap: '8px' },
  row: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '12px',
  },
  rowLeft: { display: 'flex', alignItems: 'center', gap: '8px' },
  dot: { width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0 },
  simulated: {
    fontSize: '9px',
    fontWeight: 'bold',
    color: '#3b82f6',
    border: '1px solid #3b82f6',
    borderRadius: '3px',
    padding: '1px 4px',
  },
  label: { color: '#cbd5e1' },
  status: { fontFamily: 'monospace', fontSize: '11px', fontWeight: 'bold' },
  divider: { borderTop: '1px solid #1e293b', margin: '12px 0' },
  footerRow: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '11px',
    color: '#64748b',
    fontFamily: 'monospace',
    marginBottom: '4px',
  },
  enabled: { color: '#22c55e', fontWeight: 'bold' },
  none: { color: '#94a3b8', fontWeight: 'bold' },
  note: {
    marginTop: '10px',
    fontSize: '11px',
    color: '#64748b',
    lineHeight: '1.5',
  },
};
