import React, { useState } from 'react';

export default function ReplayDemo() {
  const [status, setStatus] = useState('');

  const trigger = (scenario) => {
    setStatus(`Starting ${scenario}...`);
    fetch(`/api/replay/${scenario}`, { method: 'POST' })
      .then(r => r.json())
      .then(d => setStatus(`Scenario ${scenario} active. Check Live Detections.`));
  };

  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>Replay / Demo Mode</h2>
      <p style={{color: '#94a3b8', marginBottom: '20px'}}>
        Use these controls to inject simulated traffic scenarios into the monitoring enclave to trigger the AI detection models.
      </p>

      <div style={{display: 'flex', gap: '15px'}}>
        <button style={styles.btn} onClick={() => trigger('ddos')}>▶ START DDoS (SYN FLOOD)</button>
        <button style={styles.btn} onClick={() => trigger('recon')}>▶ START RECON (PORT SCAN)</button>
        <button style={styles.btn} onClick={() => trigger('c2')}>▶ START C2 BEACONING</button>
      </div>

      {status && <div style={{marginTop: '20px', padding: '10px', background: '#1e293b', borderRadius: '4px'}}>{status}</div>}
    </div>
  );
}
const styles = { btn: { padding: '12px 24px', background: '#3b82f6', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' } };
