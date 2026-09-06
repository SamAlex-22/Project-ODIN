import React from 'react';

export default function ThreatAnalysis() {
  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>Threat Analysis & AI Features</h2>
      <div style={{display: 'flex', flexDirection: 'column', gap: '20px'}}>
        <div style={styles.card}>
          <h3 style={{color:'#ef4444'}}>DDoS (Volumetric SYN)</h3>
          <p style={{fontSize:'13px', color:'#94a3b8'}}>Analyzes 10-second rolling windows. Calculates Shannon entropy of source IPs. Low entropy + High packet rate = Spoofed Flood.</p>
        </div>
        <div style={styles.card}>
          <h3 style={{color:'#ef4444'}}>Botnet C2 Beaconing</h3>
          <p style={{fontSize:'13px', color:'#94a3b8'}}>Groups connections by tuple. Calculates mean inter-arrival time and Coefficient of Variation. CV &lt; 0.35 indicates programmatic beaconing.</p>
        </div>
        <div style={styles.card}>
          <h3 style={{color:'#ef4444'}}>Reconnaissance / Port Scanning</h3>
          <p style={{fontSize:'13px', color:'#94a3b8'}}>Stateful tracking over 60s windows. Triggers when unique destination ports or hosts exceed specific fan-out thresholds per source IP.</p>
        </div>
      </div>
    </div>
  );
}
const styles = { card: { background: '#0f172a', padding: '20px', borderRadius: '8px', border: '1px solid #1e293b' } };
