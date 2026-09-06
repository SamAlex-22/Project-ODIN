import React from 'react';

export default function SOCOverview({ stats, alerts }) {
  const recent = alerts.slice(0, 3);
  
  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>SOC Overview</h2>
      
      <div style={{display: 'flex', gap: '20px', marginBottom: '30px'}}>
        <div style={styles.card}>
          <div style={styles.label}>System Status</div>
          <div style={styles.valueOk}>MONITORING</div>
        </div>
        <div style={styles.card}>
          <div style={styles.label}>One-Way Ingest</div>
          <div style={styles.valueOk}>ACTIVE</div>
        </div>
        <div style={styles.card}>
          <div style={styles.label}>Total Alerts</div>
          <div style={styles.valueAlert}>{stats.total}</div>
        </div>
      </div>

      <h3>Threat Status</h3>
      <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '20px', marginTop: '15px'}}>
        {['ddos', 'c2', 'recon', 'dga', 'malware', 'exfiltration'].map(threat => (
          <div key={threat} style={{...styles.card, borderTop: `3px solid ${stats[threat] > 0 ? '#ef4444' : '#22c55e'}`}}>
            <div style={styles.threatTitle}>{threat.toUpperCase()}</div>
            <div style={{fontSize: '12px', color: '#94a3b8'}}>Detections: {stats[threat] || 0}</div>
            <div style={{fontSize: '12px', color: stats[threat] > 0 ? '#ef4444' : '#22c55e', marginTop: '10px'}}>
              {stats[threat] > 0 ? 'CRITICAL / ACTIVE' : 'CLEAR'}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
const styles = {
  card: { background: '#0f172a', padding: '20px', borderRadius: '8px', border: '1px solid #1e293b' },
  label: { fontSize: '12px', color: '#94a3b8', marginBottom: '8px' },
  valueOk: { fontSize: '24px', fontWeight: 'bold', color: '#22c55e' },
  valueAlert: { fontSize: '24px', fontWeight: 'bold', color: '#ef4444' },
  threatTitle: { fontSize: '14px', fontWeight: 'bold', color: '#f1f5f9', marginBottom: '5px' }
};
