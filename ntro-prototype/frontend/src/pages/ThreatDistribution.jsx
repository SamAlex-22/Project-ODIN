import React from 'react';

export default function ThreatDistribution({ stats }) {
  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>Threat Distribution</h2>
      <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse'}}>
        <thead>
          <tr style={{borderBottom: '1px solid #1e293b'}}>
            <th style={styles.th}>Threat Class</th>
            <th style={styles.th}>Detections</th>
          </tr>
        </thead>
        <tbody>
          {['ddos', 'c2', 'recon', 'dga', 'malware', 'exfiltration'].map(t => (
            <tr key={t} style={{borderBottom: '1px solid #1e293b', background: '#0f172a'}}>
              <td style={styles.td}>{t.toUpperCase()}</td>
              <td style={styles.td}>{stats[t] || 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
const styles = { th: { padding: '12px', color: '#94a3b8' }, td: { padding: '12px' } };
