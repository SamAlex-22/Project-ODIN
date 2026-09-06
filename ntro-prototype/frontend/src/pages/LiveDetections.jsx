import React from 'react';
import { useNavigate } from 'react-router-dom';

export default function LiveDetections({ alerts }) {
  const navigate = useNavigate();

  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>Live Detections (Structured EVE-JSON Alerts)</h2>
      <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse'}}>
        <thead>
          <tr style={{borderBottom: '1px solid #1e293b'}}>
            <th style={styles.th}>Timestamp</th>
            <th style={styles.th}>Threat Class</th>
            <th style={styles.th}>Source IP</th>
            <th style={styles.th}>Confidence</th>
            <th style={styles.th}>Severity</th>
            <th style={styles.th}>Action</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i} style={{borderBottom: '1px solid #1e293b', background: '#0f172a'}}>
              <td style={styles.td}>{new Date(a.timestamp).toLocaleTimeString()}</td>
              <td style={styles.td}>{a.threat_class.toUpperCase()}</td>
              <td style={styles.td}>{a.src_ip}</td>
              <td style={styles.td}>{Math.round(a.confidence * 100)}%</td>
              <td style={styles.td}>{a.severity > 2 ? 'HIGH' : 'MEDIUM'}</td>
              <td style={styles.td}>
                <button onClick={() => navigate('/investigate', {state: {alert: a}})} style={styles.btn}>Investigate</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
const styles = {
  th: { padding: '12px', color: '#94a3b8', fontSize: '12px' },
  td: { padding: '12px', fontSize: '13px' },
  btn: { background: '#1e293b', color: '#f1f5f9', border: 'none', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer' }
};
