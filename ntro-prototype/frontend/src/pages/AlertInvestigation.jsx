import React from 'react';
import { useLocation } from 'react-router-dom';

export default function AlertInvestigation() {
  const location = useLocation();
  const alert = location.state?.alert;

  if (!alert) return <div>Please select an alert from Live Detections.</div>;

  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>Alert Investigation</h2>
      
      <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px'}}>
        <div style={styles.card}>
          <h3>Alert Summary</h3>
          <div style={styles.row}><span>Threat:</span> <span>{alert.threat_class.toUpperCase()}</span></div>
          <div style={styles.row}><span>Severity:</span> <span>{alert.severity}</span></div>
          <div style={styles.row}><span>Confidence:</span> <span>{Math.round(alert.confidence * 100)}%</span></div>
          <div style={styles.row}><span>Source IP:</span> <span>{alert.src_ip}</span></div>
          <div style={styles.row}><span>Timestamp:</span> <span>{alert.timestamp}</span></div>
        </div>

        <div style={styles.card}>
          <h3>Detection Evidence</h3>
          <p style={{color: '#94a3b8', fontSize: '13px', marginBottom: '15px'}}>{alert.evidence.explanation}</p>
          {Object.entries(alert.evidence).filter(([k]) => k !== 'explanation').map(([k, v]) => (
            <div key={k} style={styles.row}>
              <span>{k}:</span>
              <span>{Array.isArray(v) ? v.join(', ') : String(v)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
const styles = { 
  card: { background: '#0f172a', padding: '20px', borderRadius: '8px', border: '1px solid #1e293b' },
  row: { display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', padding: '8px 0', fontSize: '13px', color: '#cbd5e1' }
};
