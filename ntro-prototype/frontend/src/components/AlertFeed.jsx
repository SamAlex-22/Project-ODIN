import React, { useState } from 'react';

const SEVERITY_COLOR = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#64748b',
};

export default function AlertFeed({ alerts, colors, labels }) {
  const [selected, setSelected] = useState(null);

  return (
    <div style={styles.panel}>
      <div style={styles.panelTitle}>
        Live Alert Feed
        <span style={styles.count}>{alerts.length} alerts</span>
      </div>

      <div style={styles.feed}>
        {alerts.length === 0 && (
          <div style={styles.empty}>
            Monitoring active — no threats detected
          </div>
        )}

        {alerts.map((alert, idx) => (
          <div
            key={idx}
            style={{
              ...styles.alertRow,
              borderLeft: `3px solid ${colors[alert.threat_class] || '#64748b'}`,
              background: selected === idx ? '#1e293b' : 'transparent',
            }}
            onClick={() => setSelected(selected === idx ? null : idx)}
          >
            {/* Row summary */}
            <div style={styles.rowTop}>
              <span style={{
                ...styles.badge,
                background: colors[alert.threat_class] || '#64748b',
              }}>
                {(alert.threat_label || alert.threat_class || '').toString().toUpperCase()}
              </span>
              <span style={styles.srcIp}>
                {alert.src_ip}{alert.src_port ? `:${alert.src_port}` : ''}
                <span style={styles.arrow}> → </span>
                {alert.dst_ip}{alert.dst_port ? `:${alert.dst_port}` : ''}
              </span>
              {alert.severity && (
                <span style={{ ...styles.severity, color: SEVERITY_COLOR[alert.severity] || '#94a3b8' }}>
                  {alert.severity}
                </span>
              )}
              <span style={styles.confidence}>
                {Math.round((alert.confidence || 0) * 100)}%
              </span>
              <span style={styles.time}>
                {new Date(alert.timestamp).toLocaleTimeString()}
              </span>
            </div>

            {/* Expanded evidence */}
            {selected === idx && (
              <div style={styles.evidence}>
                <div style={styles.evidenceTitle}>Why was this detected?</div>
                <div style={styles.evidenceList}>
                  {(Array.isArray(alert.evidence) ? alert.evidence : []).map((line, i) => (
                    <div key={i} style={styles.evidenceLine}>
                      <span style={styles.check}>✓</span> {line}
                    </div>
                  ))}
                </div>
                <div style={styles.metaRow}>
                  <span>Detector: {alert.detector || 'n/a'}</span>
                  <span>Window: {alert.window_seconds ? `${alert.window_seconds}s` : 'n/a'}</span>
                  <span>Flow ID: {alert.flow_id || 'n/a'}</span>
                </div>
              </div>
            )}
          </div>
        ))}
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
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
  },
  panelTitle: {
    fontSize: '13px',
    fontWeight: 'bold',
    color: '#94a3b8',
    marginBottom: '12px',
    textTransform: 'uppercase',
    letterSpacing: '1px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  count: {
    fontSize: '11px',
    background: '#1e293b',
    padding: '2px 8px',
    borderRadius: '10px',
    color: '#64748b',
    fontWeight: 'normal',
  },
  feed: {
    flex: 1,
    overflowY: 'auto',
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  empty: {
    color: '#475569',
    textAlign: 'center',
    padding: '40px 0',
    fontSize: '13px',
  },
  alertRow: {
    padding: '10px 12px',
    borderRadius: '4px',
    cursor: 'pointer',
    transition: 'background 0.1s',
  },
  rowTop: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  badge: {
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '10px',
    fontWeight: 'bold',
    color: '#fff',
    flexShrink: 0,
    minWidth: '56px',
    textAlign: 'center',
  },
  srcIp: {
    fontSize: '13px',
    color: '#e2e8f0',
    fontFamily: 'monospace',
    flex: 1,
  },
  arrow: { color: '#475569' },
  severity: {
    fontSize: '11px',
    fontFamily: 'monospace',
    fontWeight: 'bold',
    minWidth: '52px',
    textAlign: 'right',
  },
  confidence: {
    fontSize: '12px',
    color: '#22c55e',
    fontFamily: 'monospace',
    minWidth: '36px',
    textAlign: 'right',
  },
  time: {
    fontSize: '11px',
    color: '#475569',
    fontFamily: 'monospace',
    flexShrink: 0,
  },
  evidence: {
    marginTop: '10px',
    padding: '10px',
    background: '#0a0e1a',
    borderRadius: '4px',
    fontSize: '12px',
  },
  evidenceTitle: {
    color: '#64748b',
    textTransform: 'uppercase',
    fontSize: '10px',
    letterSpacing: '1px',
    marginBottom: '8px',
  },
  evidenceList: { display: 'flex', flexDirection: 'column', gap: '5px', marginBottom: '10px' },
  evidenceLine: { color: '#e2e8f0', lineHeight: '1.4' },
  check: { color: '#22c55e', fontWeight: 'bold' },
  metaRow: {
    display: 'flex',
    gap: '16px',
    paddingTop: '8px',
    borderTop: '1px solid #1e293b',
    color: '#475569',
    fontFamily: 'monospace',
    fontSize: '11px',
    flexWrap: 'wrap',
  },
};
